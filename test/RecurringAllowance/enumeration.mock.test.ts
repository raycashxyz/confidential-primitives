import { describe, expect, it } from "vitest";
import { getAddress, parseEventLogs } from "viem";

import { assertRevertsWith } from "../setup/asserts";
import { fheTxOpts } from "../setup/tx";
import { useAllowanceSuite } from "./setup/suite";

/** SkipReason enum mirror (contract: NONE=0, NO_PERMISSIONS=1, TOKEN_CALL_FAILED=2). */
const SKIP_NO_PERMISSIONS = 1;
const SKIP_TOKEN_CALL_FAILED = 2;

describe("RecurringAllowance: grant enumeration and lenient batch", () => {
  const S = useAllowanceSuite();

  it("tracks each (token, spender) pair once and untracks when the last permission goes", async () => {
    const { H, token, allowance } = S.ctx();
    const { alice, bob, carol } = H.wallets;
    const user = alice.account.address;

    expect(await allowance.read.getGrantedPairCount([user])).toBe(0n);

    // Two permissions for bob (one pair), one for carol (second pair).
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
    await S.setPermission({
      user: alice,
      spender: carol.account.address,
      limit: 300n
    });

    expect(await allowance.read.getGrantedPairCount([user])).toBe(2n);
    const pairs = await allowance.read.getGrantedPairs([user]);
    expect(pairs.map((p) => [getAddress(p.token), getAddress(p.spender)])).toEqual([
      [getAddress(token.address), getAddress(bob.account.address)],
      [getAddress(token.address), getAddress(carol.account.address)]
    ]);

    // Removing ONE of bob's two permissions keeps the pair listed.
    await S.sendOk(allowance.write.invalidatePermission([
      token.address,
      bob.account.address,
      0n,
      idA
    ], fheTxOpts(alice.account)));
    expect(await allowance.read.getGrantedPairCount([user])).toBe(2n);

    // Removing the last one unlists the pair.
    await S.sendOk(allowance.write.invalidatePermission([
      token.address,
      bob.account.address,
      0n,
      idB
    ], fheTxOpts(alice.account)));
    expect(await allowance.read.getGrantedPairCount([user])).toBe(1n);
    const remaining = await allowance.read.getGrantedPairAt([user, 0n]);
    expect(getAddress(remaining.spender)).toBe(getAddress(carol.account.address));

    // Lockdown unlists too; re-granting lists again.
    await S.sendOk(allowance.write.lockdown([
      [
        {
          token: token.address,
          spender: carol.account.address
        }
      ]
    ], fheTxOpts(alice.account)));
    expect(await allowance.read.getGrantedPairCount([user])).toBe(0n);

    await S.setPermission({
      user: alice,
      spender: carol.account.address,
      limit: 50n
    });
    expect(await allowance.read.getGrantedPairCount([user])).toBe(1n);

    // getGrantedPairAt reverts cleanly (not a bare panic) past the end.
    await assertRevertsWith(
      allowance.read.getGrantedPairAt([user, 1n]),
      "PermissionNotFound",
    );
  });

  it("unlists a pair whose only permission expired and got pruned by a lenient spend", async () => {
    const { H, token, allowance } = S.ctx();
    const { alice, bob, carol } = H.wallets;
    const user = alice.account.address;

    await S.fundUser(alice, 1000n);
    const nowTs = await S.now();
    await S.setPermission({
      user: alice,
      spender: bob.account.address,
      limit: 100n,
      endTime: nowTs + 1000n
    });
    expect(await allowance.read.getGrantedPairCount([user])).toBe(1n);

    await H.warpTime(5000n);

    // tryTransferFrom skips (instead of reverting), so its prune PERSISTS and the
    // now-empty pair must drop off the enumeration.
    const { handle, inputProof } = await S.encAmount(allowance.address, bob.account.address, 10n);
    const receipt = await S.sendOk(allowance.write.tryTransferFrom([
      [
        {
          from: alice.account.address,
          to: carol.account.address,
          amount: handle,
          inputProof,
          token: token.address
        }
      ]
    ], fheTxOpts(bob.account)));

    const [skip] = parseEventLogs({
      abi: allowance.abi,
      logs: receipt.logs,
      eventName: "TransferSkipped"
    });
    expect(skip.args.reason).toBe(SKIP_NO_PERMISSIONS);
    expect(await allowance.read.getGrantedPairCount([user])).toBe(0n);
    expect(await S.getPermissionCount(user, bob.account.address)).toBe(0n);
  });

  it("tryTransferFrom executes what it can and skips cleartext failures", async () => {
    const { H, token, allowance } = S.ctx();
    const { alice, bob, carol } = H.wallets;

    // alice: funded, operator set, permission granted -> should execute.
    await S.fundUser(alice, 10_000n);
    await S.setPermission({
      user: alice,
      spender: bob.account.address,
      limit: 500n
    });
    // carol: granted bob nothing -> NO_PERMISSIONS skip.

    const item = async (from: `0x${string}`, amount: bigint) => {
      const { handle, inputProof } = await S.encAmount(allowance.address, bob.account.address, amount);
      return {
        from,
        to: carol.account.address,
        amount: handle,
        inputProof,
        token: token.address
      };
    };

    const receipt = await S.sendOk(allowance.write.tryTransferFrom([
      [
        await item(alice.account.address, 200n),
        await item(carol.account.address, 50n)
      ]
    ], fheTxOpts(bob.account)));

    const executedEvents = parseEventLogs({
      abi: allowance.abi,
      logs: receipt.logs,
      eventName: "AllowanceTransfer"
    });
    const skippedEvents = parseEventLogs({
      abi: allowance.abi,
      logs: receipt.logs,
      eventName: "TransferSkipped"
    });
    expect(executedEvents).toHaveLength(1);
    expect(getAddress(executedEvents[0].args.from)).toBe(getAddress(alice.account.address));
    expect(skippedEvents).toHaveLength(1);
    expect(skippedEvents[0].args.reason).toBe(SKIP_NO_PERMISSIONS);
    expect(getAddress(skippedEvents[0].args.from)).toBe(getAddress(carol.account.address));

    expect(await S.balanceOf(carol)).toBe(200n);
    expect(await S.decryptSpent(alice, bob.account.address, 0n)).toBe(200n);
  });

  it("tryTransferFrom skips a token-level failure (no operator) without losing the batch", async () => {
    const { H, token, allowance } = S.ctx();
    const {
      alice, bob, carol, signer: dave
    } = H.wallets;

    // alice fully set up; dave granted a permission but NEVER set the operator.
    await S.fundUser(alice, 10_000n);
    await S.setPermission({
      user: alice,
      spender: bob.account.address,
      limit: 500n
    });
    await S.mintTo(dave, 1000n); // funded but no setOperator
    await S.setPermission({
      user: dave,
      spender: bob.account.address,
      limit: 500n
    });

    const item = async (from: `0x${string}`, amount: bigint) => {
      const { handle, inputProof } = await S.encAmount(allowance.address, bob.account.address, amount);
      return {
        from,
        to: carol.account.address,
        amount: handle,
        inputProof,
        token: token.address
      };
    };

    const receipt = await S.sendOk(allowance.write.tryTransferFrom([
      [
        await item(dave.account.address, 100n), // token reverts: not an operator for dave
        await item(alice.account.address, 100n) // still executes
      ]
    ], fheTxOpts(bob.account)));

    const skipped = parseEventLogs({
      abi: allowance.abi,
      logs: receipt.logs,
      eventName: "TransferSkipped"
    });
    expect(skipped).toHaveLength(1);
    expect(skipped[0].args.reason).toBe(SKIP_TOKEN_CALL_FAILED);
    expect(getAddress(skipped[0].args.from)).toBe(getAddress(dave.account.address));

    expect(await S.balanceOf(carol)).toBe(100n);
    // dave's allowance untouched by the failed item.
    expect(await S.decryptSpent(dave, bob.account.address, 0n)).toBe(0n);
  });

  it("keeps oblivious denials as executions, not skips", async () => {
    const { H, token, allowance } = S.ctx();
    const { alice, bob, carol } = H.wallets;

    await S.fundUser(alice, 10_000n);
    await S.setPermission({
      user: alice,
      spender: bob.account.address,
      limit: 100n
    });

    const { handle, inputProof } = await S.encAmount(allowance.address, bob.account.address, 500n); // over limit
    const receipt = await S.sendOk(allowance.write.tryTransferFrom([
      [
        {
          from: alice.account.address,
          to: carol.account.address,
          amount: handle,
          inputProof,
          token: token.address
        }
      ]
    ], fheTxOpts(bob.account)));

    // Denied by the ENCRYPTED check -> executed=true path, zero moved, no skip event.
    expect(parseEventLogs({
      abi: allowance.abi,
      logs: receipt.logs,
      eventName: "TransferSkipped"
    })).toHaveLength(0);
    expect(parseEventLogs({
      abi: allowance.abi,
      logs: receipt.logs,
      eventName: "AllowanceTransfer"
    })).toHaveLength(1);
    expect(await S.balanceOf(carol)).toBe(0n);
  });
});
