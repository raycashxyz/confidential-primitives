import { describe, expect, it } from "vitest";
import { parseEventLogs, zeroHash } from "viem";

import { fheTxOpts } from "../setup/tx";
import { DAY, MONTH, WEEK, YEAR, useAllowanceSuite } from "./setup/suite";

describe("RecurringAllowance: periods and security regressions", () => {
  const S = useAllowanceSuite();

  it("resets spent when a period elapses, anchored at startTime", async () => {
    const { H, allowance } = S.ctx();
    const { alice, bob, carol } = H.wallets;

    await S.fundUser(alice, 10_000n);
    await S.setPermission({
      user: alice,
      spender: bob.account.address,
      limit: 1000n,
      duration: DAY
    });
    const { startTime } = await S.getPermission(alice.account.address, bob.account.address, 0n);

    const doSpend = (amount: bigint) => S.spend({
      spender: bob,
      from: alice.account.address,
      to: carol.account.address,
      amount
    });

    await doSpend(600n);
    await doSpend(600n); // denied within the same period
    expect(await S.decryptSpent(alice, bob.account.address, 0n)).toBe(600n);
    expect(await S.balanceOf(carol)).toBe(600n);

    await H.warpTime(DAY + 3600n);

    const receipt = await doSpend(900n); // new period: fits again
    const [reset] = parseEventLogs({
      abi: allowance.abi,
      logs: receipt.logs,
      eventName: "PermissionReset"
    });
    expect(reset.args.user).toBe(alice.account.address);

    expect(await S.decryptSpent(alice, bob.account.address, 0n)).toBe(900n);
    expect(await S.balanceOf(carol)).toBe(1500n);

    // startTime is the immutable grid anchor — resets never move it
    const after = await S.getPermission(alice.account.address, bob.account.address, 0n);
    expect(after.startTime).toBe(startTime);
  });

  it("resets each tier independently when several periods elapse", async () => {
    const { H } = S.ctx();
    const { alice, bob, carol } = H.wallets;

    await S.fundUser(alice, 100_000n);
    await S.setPermission({
      user: alice,
      spender: bob.account.address,
      limit: 100n,
      duration: DAY
    });
    await S.setPermission({
      user: alice,
      spender: bob.account.address,
      limit: 500n,
      duration: WEEK
    });
    await S.setPermission({
      user: alice,
      spender: bob.account.address,
      limit: 10_000n,
      duration: YEAR
    });

    const doSpend = (amount: bigint) => S.spend({
      spender: bob,
      from: alice.account.address,
      to: carol.account.address,
      amount
    });
    const spentAt = (index: bigint) => S.decryptSpent(alice, bob.account.address, index);

    await doSpend(100n);
    expect(await spentAt(0n)).toBe(100n);
    expect(await spentAt(1n)).toBe(100n);
    expect(await spentAt(2n)).toBe(100n);

    // a month later: daily and weekly reset, yearly keeps counting
    await H.warpTime(MONTH);
    await doSpend(30n);
    expect(await spentAt(0n)).toBe(30n);
    expect(await spentAt(1n)).toBe(30n);
    expect(await spentAt(2n)).toBe(130n);
  });

  it("spends inside the window and stops after the inclusive endTime", async () => {
    const { H } = S.ctx();
    const { alice, bob, carol } = H.wallets;

    await S.fundUser(alice, 10_000n);
    const nowTs = await S.now();
    await S.setPermission({
      user: alice,
      spender: bob.account.address,
      limit: 1000n,
      duration: DAY,
      endTime: nowTs + 5000n
    });

    await S.spend({
      spender: bob,
      from: alice.account.address,
      to: carol.account.address,
      amount: 300n
    });
    expect(await S.balanceOf(carol)).toBe(300n);

    await H.warpTime(10_000n);

    // Past endTime the spend reverts NoPermissions (the revert also rolls back the prune,
    // so the expired entry stays until a successful write prunes it).
    await expect(S.spend({
      spender: bob,
      from: alice.account.address,
      to: carol.account.address,
      amount: 1n
    })).rejects.toThrow();
    expect(await S.getPermissionCount(alice.account.address, bob.account.address)).toBe(1n);
  });

  // REGRESSION (critical finding): FHE arithmetic wraps, so the original
  // `amount <= limit - spent` check turned "spent > limit" (reachable by lowering the
  // limit mid-period) into a near-unlimited budget: remaining wrapped to ~2^64.
  it("denies spending when the limit is lowered below the amount already spent", async () => {
    const { H, token, allowance } = S.ctx();
    const { alice, bob, carol } = H.wallets;

    await S.fundUser(alice, 10_000n);
    const { permissionId } = await S.setPermission({
      user: alice,
      spender: bob.account.address,
      limit: 100n,
      duration: DAY
    });

    const doSpend = (amount: bigint) => S.spend({
      spender: bob,
      from: alice.account.address,
      to: carol.account.address,
      amount
    });

    await doSpend(100n); // exhaust the original limit
    expect(await S.balanceOf(carol)).toBe(100n);

    // Alice LOWERS the limit to 50 (spent 100 now exceeds it).
    const { handle, inputProof } = await S.encAmount(allowance.address, alice.account.address, 50n);
    await S.sendOk(allowance.write.updatePermission([
      token.address,
      bob.account.address,
      0n,
      permissionId,
      handle,
      inputProof,
      0n,
      0n,
      0n
    ], fheTxOpts(alice.account)));

    // Pre-fix these would drain: remaining wrapped to 2^64 - 50.
    await doSpend(60n); // over the new limit
    await doSpend(40n); // under the new limit but spent (100) already exceeds it
    await doSpend(9000n); // the drain attempt
    expect(await S.balanceOf(carol)).toBe(100n); // nothing moved
    expect(await S.decryptSpent(alice, bob.account.address, 0n)).toBe(100n);

    // Next period the counter resets and the NEW limit applies.
    await H.warpTime(DAY + 3600n);
    await doSpend(50n);
    expect(await S.balanceOf(carol)).toBe(150n);
  });

  // REGRESSION (high finding): moving startTime forward used to leave
  // lastUpdated < startTime, so the reset math (`lastUpdated - startTime`) panicked
  // once the permission reactivated — permanently bricking the key.
  it("survives a startTime moved into the future (no underflow panic)", async () => {
    const { H, token, allowance } = S.ctx();
    const { alice, bob, carol } = H.wallets;

    await S.fundUser(alice, 10_000n);
    const { permissionId } = await S.setPermission({
      user: alice,
      spender: bob.account.address,
      limit: 100n,
      duration: DAY
    });

    // Spend so lastUpdated is set to "now"...
    await S.spend({
      spender: bob,
      from: alice.account.address,
      to: carol.account.address,
      amount: 30n
    });

    // ...then pause the permission until later (re-anchors the grid).
    const nowTs = await S.now();
    await S.sendOk(allowance.write.updatePermission([
      token.address,
      bob.account.address,
      0n,
      permissionId,
      zeroHash,
      "0x",
      0n,
      nowTs + 5000n,
      0n
    ], fheTxOpts(alice.account)));

    // While paused: no active permission.
    await expect(S.spend({
      spender: bob,
      from: alice.account.address,
      to: carol.account.address,
      amount: 10n
    })).rejects.toThrow();

    // Once it reactivates, spends must work (pre-fix: Panic 0x11 forever).
    await H.warpTime(10_000n);
    await S.spend({
      spender: bob,
      from: alice.account.address,
      to: carol.account.address,
      amount: 20n
    });
    expect(await S.balanceOf(carol)).toBe(50n);
    expect(await S.decryptSpent(alice, bob.account.address, 0n)).toBe(20n); // fresh grid
  });

  it("keeps not-yet-started permissions untouched by spends", async () => {
    const { H } = S.ctx();
    const { alice, bob, carol } = H.wallets;

    await S.fundUser(alice, 10_000n);
    const nowTs = await S.now();
    await S.setPermission({
      user: alice,
      spender: bob.account.address,
      limit: 100n,
      duration: DAY
    });
    await S.setPermission({
      user: alice,
      spender: bob.account.address,
      limit: 100n,
      duration: DAY,
      startTime: nowTs + WEEK
    });

    await S.spend({
      spender: bob,
      from: alice.account.address,
      to: carol.account.address,
      amount: 100n
    });

    expect(await S.decryptSpent(alice, bob.account.address, 0n)).toBe(100n);
    // The future permission was neither checked nor mutated.
    const future = await S.getPermission(alice.account.address, bob.account.address, 1n);
    expect(await S.decryptAllowanceHandle(future.spent, alice)).toBe(0n);
    expect(future.lastUpdated).toBe(future.startTime);
  });
});
