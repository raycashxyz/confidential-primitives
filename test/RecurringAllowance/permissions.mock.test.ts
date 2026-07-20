import { describe, expect, it } from "vitest";
import { getAddress, parseEventLogs, zeroAddress, zeroHash } from "viem";

import { assertRevertsWith } from "../setup/asserts";
import { fheTxOpts, txOpts } from "../setup/tx";
import { DAY, MAX_UINT64, WEEK, useAllowanceSuite } from "./setup/suite";

describe("RecurringAllowance: permission lifecycle", () => {
  const S = useAllowanceSuite();

  it("creates a permission with defaults (no expiry, sentinel handling)", async () => {
    const { H, token, allowance } = S.ctx();
    const { alice, bob } = H.wallets;

    const before = await S.now();
    const { permissionId, event } = await S.setPermission({
      user: alice,
      spender: bob.account.address,
      limit: 1000n,
      duration: 0n, // 0 -> never resets
      startTime: 0n, // 0 -> block.timestamp
      endTime: 0n // 0 -> no expiry
    });

    expect(permissionId).toBe(1n);
    expect(event.user).toBe(getAddress(alice.account.address));
    expect(event.token).toBe(getAddress(token.address));
    expect(event.spender).toBe(getAddress(bob.account.address));

    expect(await S.getPermissionCount(alice.account.address, bob.account.address)).toBe(1n);
    const permission = await S.getPermission(alice.account.address, bob.account.address, 0n);
    expect(permission.id).toBe(1n);
    expect(permission.duration).toBe(MAX_UINT64);
    expect(permission.endTime).toBe(MAX_UINT64);
    expect(permission.startTime).toBeGreaterThanOrEqual(before);
    expect(permission.lastUpdated).toBe(permission.startTime);

    // getPermissionById resolves the same permission
    const byId = await allowance.read.getPermissionById([
      alice.account.address,
      token.address,
      bob.account.address,
      permissionId
    ]);
    expect(byId.limit).toBe(permission.limit);
  });

  it("both the user and the spender can decrypt limit and spent", async () => {
    const { H } = S.ctx();
    const { alice, bob } = H.wallets;

    await S.setPermission({
      user: alice,
      spender: bob.account.address,
      limit: 1000n
    });

    const permission = await S.getPermission(alice.account.address, bob.account.address, 0n);
    expect(await S.decryptAllowanceHandle(permission.limit, alice)).toBe(1000n);
    expect(await S.decryptAllowanceHandle(permission.limit, bob)).toBe(1000n);
    expect(await S.decryptAllowanceHandle(permission.spent, alice)).toBe(0n);
    expect(await S.decryptAllowanceHandle(permission.spent, bob)).toBe(0n);

    // A SECOND permission under the same key: the contract skips re-granting the shared
    // encrypted-zero to save gas, so this checks the spender can still decrypt its
    // freshly-created (still-zero) spent — i.e. the optimization didn't under-grant.
    await S.setPermission({
      user: alice,
      spender: bob.account.address,
      limit: 500n
    });
    const second = await S.getPermission(alice.account.address, bob.account.address, 1n);
    expect(await S.decryptAllowanceHandle(second.limit, bob)).toBe(500n);
    expect(await S.decryptAllowanceHandle(second.spent, alice)).toBe(0n);
    expect(await S.decryptAllowanceHandle(second.spent, bob)).toBe(0n);
  });

  it("validates addresses and the time window on creation", async () => {
    const { H, token, allowance } = S.ctx();
    const { alice, bob } = H.wallets;
    const nowTs = await S.now();

    const { handle, inputProof } = await S.encAmount(allowance.address, alice.account.address, 100n);
    const args = (overrides: Partial<Record<"token" | "spender", `0x${string}`>> & { startTime?: bigint; endTime?: bigint }) => [
      overrides.token ?? token.address,
      overrides.spender ?? bob.account.address,
      handle,
      inputProof,
      DAY,
      overrides.startTime ?? 0n,
      overrides.endTime ?? 0n
    ] as const;

    await assertRevertsWith(
      allowance.write.setPermission([...args({ token: zeroAddress })], txOpts(alice.account)),
      "InvalidTokenAddress",
    );
    await assertRevertsWith(
      allowance.write.setPermission([...args({ spender: zeroAddress })], txOpts(alice.account)),
      "InvalidSpenderAddress",
    );
    // endTime in the past
    await assertRevertsWith(
      allowance.write.setPermission([...args({ endTime: nowTs - 1000n })], txOpts(alice.account)),
      "InvalidEndTime",
    );
    // endTime not after startTime
    await assertRevertsWith(
      allowance.write.setPermission([
        ...args({
          startTime: nowTs + 5000n,
          endTime: nowTs + 5000n
        })
      ], txOpts(alice.account)),
      "InvalidEndTime",
    );
    // startTime in the past is fine
    const receipt = await S.sendOk(allowance.write.setPermission([...args({ startTime: nowTs - 10_000n })], fheTxOpts(alice.account)));
    expect(receipt.status).toBe("success");
  });

  it("caps live permissions per key at MAX_PERMISSIONS", async () => {
    const { H, token, allowance } = S.ctx();
    const { alice, bob } = H.wallets;

    const max = await allowance.read.MAX_PERMISSIONS();
    for (let i = 0n; i < max; i++) {
      await S.setPermission({
        user: alice,
        spender: bob.account.address,
        limit: 100n + i
      });
    }
    expect(await S.getPermissionCount(alice.account.address, bob.account.address)).toBe(max);

    const { handle, inputProof } = await S.encAmount(allowance.address, alice.account.address, 100n);
    await assertRevertsWith(
      allowance.write.setPermission([
        token.address,
        bob.account.address,
        handle,
        inputProof,
        DAY,
        0n,
        0n
      ], txOpts(alice.account)),
      "TooManyPermissions",
    );
  });

  it("updates only the limit, keeping the window and the current period's spent", async () => {
    const { H, token, allowance } = S.ctx();
    const { alice, bob, carol } = H.wallets;

    await S.fundUser(alice, 10_000n);
    const { permissionId } = await S.setPermission({
      user: alice,
      spender: bob.account.address,
      limit: 500n,
      duration: WEEK
    });
    await S.spend({
      spender: bob,
      from: alice.account.address,
      to: carol.account.address,
      amount: 200n
    });

    const beforeUpdate = await S.getPermission(alice.account.address, bob.account.address, 0n);
    const { handle, inputProof } = await S.encAmount(allowance.address, alice.account.address, 800n);
    await S.sendOk(allowance.write.updatePermission([
      token.address,
      bob.account.address,
      0n,
      permissionId,
      handle,
      inputProof,
      0n, // duration unchanged
      0n, // startTime unchanged
      0n // endTime unchanged
    ], fheTxOpts(alice.account)));

    const updated = await S.getPermission(alice.account.address, bob.account.address, 0n);
    expect(await S.decryptAllowanceHandle(updated.limit, alice)).toBe(800n);
    expect(await S.decryptAllowanceHandle(updated.spent, alice)).toBe(200n); // kept
    expect(updated.startTime).toBe(beforeUpdate.startTime);
    expect(updated.endTime).toBe(beforeUpdate.endTime);
    expect(updated.duration).toBe(beforeUpdate.duration);
  });

  it("re-anchors the grid (and resets spent) when duration or startTime changes", async () => {
    const { H, token, allowance } = S.ctx();
    const { alice, bob, carol } = H.wallets;

    await S.fundUser(alice, 10_000n);
    const { permissionId } = await S.setPermission({
      user: alice,
      spender: bob.account.address,
      limit: 500n,
      duration: DAY
    });
    await S.spend({
      spender: bob,
      from: alice.account.address,
      to: carol.account.address,
      amount: 200n
    });
    expect(await S.decryptSpent(alice, bob.account.address, 0n)).toBe(200n);
    const before = await S.getPermission(alice.account.address, bob.account.address, 0n);

    await S.sendOk(allowance.write.updatePermission([
      token.address,
      bob.account.address,
      0n,
      permissionId,
      zeroHash,
      "0x", // limit unchanged
      WEEK, // duration changed -> grid re-anchor
      0n,
      0n
    ], fheTxOpts(alice.account)));

    const blockTimestamp = await S.now();
    const updated = await S.getPermission(alice.account.address, bob.account.address, 0n);
    expect(updated.duration).toBe(WEEK);
    expect(await S.decryptAllowanceHandle(updated.spent, alice)).toBe(0n); // reset
    // startTime is unchanged; lastUpdated re-anchors to now (>= startTime) so `spent` is
    // fresh for the current grid period and does not immediately re-reset on next spend.
    expect(updated.startTime).toBe(before.startTime);
    expect(updated.lastUpdated).toBe(blockTimestamp);
    expect(updated.lastUpdated).toBeGreaterThanOrEqual(updated.startTime);
  });

  it("does NOT reset spent when duration/startTime are re-submitted unchanged", async () => {
    const { H, token, allowance } = S.ctx();
    const { alice, bob, carol } = H.wallets;

    await S.fundUser(alice, 10_000n);
    const { permissionId } = await S.setPermission({
      user: alice,
      spender: bob.account.address,
      limit: 500n,
      duration: DAY
    });
    await S.spend({
      spender: bob,
      from: alice.account.address,
      to: carol.account.address,
      amount: 200n
    });

    const before = await S.getPermission(alice.account.address, bob.account.address, 0n);

    // A wallet echoes back the FULL current record (same duration and startTime, both
    // nonzero). This must be a no-op for the grid — not a silent budget refresh.
    await S.sendOk(allowance.write.updatePermission([
      token.address,
      bob.account.address,
      0n,
      permissionId,
      zeroHash,
      "0x",
      before.duration, // unchanged
      before.startTime, // unchanged
      before.endTime // unchanged
    ], fheTxOpts(alice.account)));

    const after = await S.getPermission(alice.account.address, bob.account.address, 0n);
    expect(await S.decryptAllowanceHandle(after.spent, alice)).toBe(200n); // NOT reset
    expect(after.lastUpdated).toBe(before.lastUpdated); // grid untouched
  });

  it("guards updates with (index, id) and validates the resulting window", async () => {
    const { H, token, allowance } = S.ctx();
    const { alice, bob } = H.wallets;
    const nowTs = await S.now();

    const { permissionId } = await S.setPermission({
      user: alice,
      spender: bob.account.address,
      limit: 500n
    });

    // wrong id
    await assertRevertsWith(
      allowance.write.updatePermission([
        token.address,
        bob.account.address,
        0n,
        permissionId + 1n,
        zeroHash,
        "0x",
        0n,
        0n,
        0n
      ], txOpts(alice.account)),
      "PermissionMismatch",
    );
    // out-of-range index
    await assertRevertsWith(
      allowance.write.updatePermission([
        token.address,
        bob.account.address,
        5n,
        permissionId,
        zeroHash,
        "0x",
        0n,
        0n,
        0n
      ], txOpts(alice.account)),
      "PermissionNotFound",
    );
    // resulting window invalid: startTime pushed past the (unchanged) endTime
    await assertRevertsWith(
      allowance.write.updatePermission([
        token.address,
        bob.account.address,
        0n,
        permissionId,
        zeroHash,
        "0x",
        0n,
        nowTs + 10_000n,
        nowTs + 5000n
      ], txOpts(alice.account)),
      "InvalidEndTime",
    );
    // endTime in the past is invalidatePermission's job, not update's
    await assertRevertsWith(
      allowance.write.updatePermission([
        token.address,
        bob.account.address,
        0n,
        permissionId,
        zeroHash,
        "0x",
        0n,
        0n,
        nowTs - 1n
      ], txOpts(alice.account)),
      "InvalidEndTime",
    );
  });

  it("invalidates a single permission and leaves the rest", async () => {
    const { H, token, allowance } = S.ctx();
    const { alice, bob } = H.wallets;

    const { permissionId: idA } = await S.setPermission({
      user: alice,
      spender: bob.account.address,
      limit: 100n
    });
    const { permissionId: idB } = await S.setPermission({
      user: alice,
      spender: bob.account.address,
      limit: 200n
    });

    // fheTxOpts: swap-and-pop earns storage refunds, which tevm's gas estimate
    // does not cover (the limit must cover the pre-refund peak).
    const receipt = await S.sendOk(allowance.write.invalidatePermission([
      token.address,
      bob.account.address,
      0n,
      idA
    ], fheTxOpts(alice.account)));
    const [event] = parseEventLogs({
      abi: allowance.abi,
      logs: receipt.logs,
      eventName: "PermissionInvalidated"
    });
    expect(event.args.permissionId).toBe(idA);

    expect(await S.getPermissionCount(alice.account.address, bob.account.address)).toBe(1n);
    const remaining = await S.getPermission(alice.account.address, bob.account.address, 0n);
    expect(remaining.id).toBe(idB); // B swapped into slot 0

    // a stale index+id pair now misses
    await assertRevertsWith(
      allowance.write.invalidatePermission([
        token.address,
        bob.account.address,
        0n,
        idA
      ], txOpts(alice.account)),
      "PermissionMismatch",
    );
  });

  it("lockdown wipes every permission for the pair", async () => {
    const { H, token, allowance } = S.ctx();
    const { alice, bob, carol } = H.wallets;

    await S.fundUser(alice, 10_000n);
    await S.setPermission({
      user: alice,
      spender: bob.account.address,
      limit: 100n
    });
    await S.setPermission({
      user: alice,
      spender: bob.account.address,
      limit: 200n,
      duration: WEEK
    });

    await S.sendOk(allowance.write.lockdown([
      [
        {
          token: token.address,
          spender: bob.account.address
        }
      ]
    ], fheTxOpts(alice.account))); // explicit gas: delete refunds under-estimate, see above

    expect(await S.getPermissionCount(alice.account.address, bob.account.address)).toBe(0n);
    await assertRevertsWith(
      S.spendExpectingRevert({
        spender: bob,
        from: alice.account.address,
        to: carol.account.address,
        amount: 1n
      }),
      "NoPermissions",
    );
  });
});
