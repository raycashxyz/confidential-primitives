import { describe, expect, it } from "vitest";
import { getAddress, parseEventLogs } from "viem";

import { assertRevertsWith } from "../setup/asserts";
import { fheTxOpts, txOpts } from "../setup/tx";
import { DAY, WEEK, useAllowanceSuite } from "./setup/suite";

describe("RecurringAllowance: spending", () => {
  const S = useAllowanceSuite();

  it("moves funds when permitted and records spent for both parties", async () => {
    const { H, token, allowance } = S.ctx();
    const { alice, bob, carol } = H.wallets;

    await S.fundUser(alice, 10_000n);
    await S.setPermission({
      user: alice,
      spender: bob.account.address,
      limit: 500n
    });

    const receipt = await S.spend({
      spender: bob,
      from: alice.account.address,
      to: carol.account.address,
      amount: 300n
    });

    expect(await S.balanceOf(alice)).toBe(9700n);
    expect(await S.balanceOf(carol)).toBe(300n);
    // spent is decryptable by the user and by the spender
    expect(await S.decryptSpent(alice, bob.account.address, 0n)).toBe(300n);
    expect(await S.decryptSpent(alice, bob.account.address, 0n, bob)).toBe(300n);

    const [event] = parseEventLogs({
      abi: allowance.abi,
      logs: receipt.logs,
      eventName: "AllowanceTransfer"
    });
    expect(event.args.from).toBe(getAddress(alice.account.address));
    expect(event.args.to).toBe(getAddress(carol.account.address));
    expect(event.args.token).toBe(getAddress(token.address));
    expect(event.args.spender).toBe(getAddress(bob.account.address));
  });

  it("transfers an encrypted zero when the amount exceeds the limit", async () => {
    const { H } = S.ctx();
    const { alice, bob, carol } = H.wallets;

    await S.fundUser(alice, 10_000n);
    await S.setPermission({
      user: alice,
      spender: bob.account.address,
      limit: 100n
    });

    await S.spend({
      spender: bob,
      from: alice.account.address,
      to: carol.account.address,
      amount: 200n
    });

    expect(await S.balanceOf(alice)).toBe(10_000n);
    expect(await S.balanceOf(carol)).toBe(0n);
    expect(await S.decryptSpent(alice, bob.account.address, 0n)).toBe(0n);
  });

  it("caps cumulative spend within a period at the limit", async () => {
    const { H } = S.ctx();
    const { alice, bob, carol } = H.wallets;

    await S.fundUser(alice, 10_000n);
    await S.setPermission({
      user: alice,
      spender: bob.account.address,
      limit: 500n
    });

    const doSpend = (amount: bigint) => S.spend({
      spender: bob,
      from: alice.account.address,
      to: carol.account.address,
      amount
    });

    await doSpend(400n); // ok: 400 <= 500
    await doSpend(200n); // denied: 400 + 200 > 500
    await doSpend(100n); // ok: exactly reaches the limit

    expect(await S.balanceOf(carol)).toBe(500n);
    expect(await S.decryptSpent(alice, bob.account.address, 0n)).toBe(500n);
  });

  it("does not consume allowance when the user's balance is short", async () => {
    const { H } = S.ctx();
    const { alice, bob, carol } = H.wallets;

    await S.fundUser(alice, 50n); // balance below the limit
    await S.setPermission({
      user: alice,
      spender: bob.account.address,
      limit: 200n
    });

    // Permitted by the allowance (120 <= 200) but the balance is 50: the token moves 0.
    await S.spend({
      spender: bob,
      from: alice.account.address,
      to: carol.account.address,
      amount: 120n
    });
    expect(await S.balanceOf(carol)).toBe(0n);
    expect(await S.decryptSpent(alice, bob.account.address, 0n)).toBe(0n); // nothing consumed

    // After topping up, the same pull succeeds — the failed attempt did not burn budget.
    await S.mintTo(alice, 200n);
    await S.spend({
      spender: bob,
      from: alice.account.address,
      to: carol.account.address,
      amount: 120n
    });
    expect(await S.balanceOf(carol)).toBe(120n);
    expect(await S.decryptSpent(alice, bob.account.address, 0n)).toBe(120n);
  });

  it("reverts NoPermissions when none exist, none started, or all expired", async () => {
    const { H } = S.ctx();
    const { alice, bob, carol } = H.wallets;
    await S.fundUser(alice, 10_000n);

    const attempt = () => S.spendExpectingRevert({
      spender: bob,
      from: alice.account.address,
      to: carol.account.address,
      amount: 10n
    });

    // none exist
    await assertRevertsWith(attempt(), "NoPermissions");

    // not started yet
    const nowTs = await S.now();
    await S.setPermission({
      user: alice,
      spender: bob.account.address,
      limit: 100n,
      startTime: nowTs + 100_000n
    });
    await assertRevertsWith(attempt(), "NoPermissions");

    // expired (warp past endTime; the future one from above still hasn't started)
    await S.setPermission({
      user: alice,
      spender: bob.account.address,
      limit: 100n,
      endTime: nowTs + 1000n
    });
    await S.ctx().H.warpTime(2000n);
    await assertRevertsWith(attempt(), "NoPermissions");
  });

  it("enforces every active permission conjunctively (daily AND weekly)", async () => {
    const { H } = S.ctx();
    const { alice, bob, carol } = H.wallets;

    await S.fundUser(alice, 10_000n);
    await S.setPermission({
      user: alice,
      spender: bob.account.address,
      limit: 500n,
      duration: WEEK
    }); // index 0: weekly
    await S.setPermission({
      user: alice,
      spender: bob.account.address,
      limit: 100n,
      duration: DAY
    }); // index 1: daily

    const doSpend = (amount: bigint) => S.spend({
      spender: bob,
      from: alice.account.address,
      to: carol.account.address,
      amount
    });

    // within both -> moves, both counters advance
    await doSpend(100n);
    expect(await S.decryptSpent(alice, bob.account.address, 0n)).toBe(100n);
    expect(await S.decryptSpent(alice, bob.account.address, 1n)).toBe(100n);
    expect(await S.balanceOf(carol)).toBe(100n);

    // within weekly, over daily -> denied, nothing advances
    await doSpend(100n);
    expect(await S.decryptSpent(alice, bob.account.address, 0n)).toBe(100n);
    expect(await S.decryptSpent(alice, bob.account.address, 1n)).toBe(100n);
    expect(await S.balanceOf(carol)).toBe(100n);

    // next day: daily resets, weekly keeps counting
    await H.warpTime(DAY + 3600n);
    await doSpend(50n);
    expect(await S.decryptSpent(alice, bob.account.address, 0n)).toBe(150n);
    expect(await S.decryptSpent(alice, bob.account.address, 1n)).toBe(50n);
    expect(await S.balanceOf(carol)).toBe(150n);

    // next day again: within daily but the weekly cap now binds
    await H.warpTime(DAY + 3600n);
    await doSpend(400n); // weekly: 150 + 400 > 500 -> denied
    expect(await S.decryptSpent(alice, bob.account.address, 0n)).toBe(150n);
    expect(await S.decryptSpent(alice, bob.account.address, 1n)).toBe(0n); // reset, nothing added
    expect(await S.balanceOf(carol)).toBe(150n);
  });

  it("supports batch transfers with per-item oblivious outcomes", async () => {
    const { H, allowance, token } = S.ctx();
    const { alice, bob, carol } = H.wallets;

    await S.fundUser(alice, 10_000n);
    await S.setPermission({
      user: alice,
      spender: bob.account.address,
      limit: 500n
    });

    const item = async (amount: bigint, to: `0x${string}`) => {
      const { handle, inputProof } = await S.encAmount(allowance.address, bob.account.address, amount);
      return {
        from: alice.account.address,
        to,
        amount: handle,
        inputProof,
        token: token.address
      };
    };

    await S.sendOk(allowance.write.transferFrom([
      [
        await item(200n, carol.account.address), // fits
        await item(400n, carol.account.address) // 200 + 400 > 500 -> denied
      ]
    ], fheTxOpts(bob.account)));

    expect(await S.balanceOf(carol)).toBe(200n);
    expect(await S.decryptSpent(alice, bob.account.address, 0n)).toBe(200n);
  });

  it("reverts the whole batch when one item has no permissions", async () => {
    const { H, allowance, token } = S.ctx();
    const { alice, bob, carol } = H.wallets;

    await S.fundUser(alice, 10_000n);
    await S.setPermission({
      user: alice,
      spender: bob.account.address,
      limit: 500n
    });

    const okItem = await (async () => {
      const { handle, inputProof } = await S.encAmount(allowance.address, bob.account.address, 100n);
      return {
        from: alice.account.address,
        to: carol.account.address,
        amount: handle,
        inputProof,
        token: token.address
      };
    })();
    const badItem = await (async () => {
      const { handle, inputProof } = await S.encAmount(allowance.address, bob.account.address, 100n);
      return {
        from: carol.account.address, // carol granted bob nothing
        to: alice.account.address,
        amount: handle,
        inputProof,
        token: token.address
      };
    })();

    await assertRevertsWith(
      allowance.write.transferFrom([[okItem, badItem]], txOpts(bob.account)),
      "NoPermissions",
    );
    expect(await S.balanceOf(carol)).toBe(0n);
  });
});
