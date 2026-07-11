/**
 * BatchedAsyncWrapper — finalizeWrap correctness (gating, replay nullifier, per-recipient
 * scan). Multi-batch + scale cases live in the sibling *.finalize-scale file.
 */
import {
  describe, it, expect
} from "vitest";

import { useBatchedSuite, AMOUNT } from "./setup/suite";
import { txOpts, fheTxOpts } from "../setup/tx";
import { assertRevertsWith } from "../setup/asserts";

const boot = useBatchedSuite();

describe("BatchedAsyncWrapper finalizeWrap", () => {
  it("reverts while the batch is still open", async () => {
    const {
      wallets, deployWrapper, fundAndApprove, initWrap
    } = await boot();
    const { alice } = wallets;
    const { contract: wrapper } = await deployWrapper(4n);
    await fundAndApprove(wrapper, alice, 1n);
    await initWrap(wrapper, alice, alice.account.address); // 1/4 — open

    await assertRevertsWith(
      wrapper.write.finalizeWrap([[0n], alice.account.address], txOpts(alice.account)),
      "BatchNotClosed",
    );
  });

  it("transfers the sum of a recipient's deposits once the batch is full", async () => {
    const {
      wallets, deployWrapper, fundAndApprove, initWrap, decryptBalance, send
    } = await boot();
    const { alice } = wallets;
    const { contract: wrapper } = await deployWrapper(3n);
    await fundAndApprove(wrapper, alice, 3n);
    for (let i = 0; i < 3; i++) await initWrap(wrapper, alice, alice.account.address);

    expect(await decryptBalance(alice)).toBe(0n); // before
    await send(wrapper.write.finalizeWrap([[0n], alice.account.address], fheTxOpts(alice.account)));
    expect(await decryptBalance(alice)).toBe(AMOUNT * 3n); // after
  });

  it("is replay-safe: a second finalize for the same (batch, recipient) reverts", async () => {
    const {
      wallets, deployWrapper, fundAndApprove, initWrap, decryptBalance, send
    } = await boot();
    const { alice } = wallets;
    const { contract: wrapper } = await deployWrapper(2n);
    await fundAndApprove(wrapper, alice, 2n);
    for (let i = 0; i < 2; i++) await initWrap(wrapper, alice, alice.account.address);

    await send(wrapper.write.finalizeWrap([[0n], alice.account.address], fheTxOpts(alice.account)));
    const afterFirst = await decryptBalance(alice);
    expect(afterFirst).toBe(AMOUNT * 2n);

    await assertRevertsWith(
      wrapper.write.finalizeWrap([[0n], alice.account.address], txOpts(alice.account)),
      "AlreadyFinalized",
    );
    expect(await decryptBalance(alice)).toBe(afterFirst); // unchanged
  });

  it("pays each recipient only their own deposits from a shared batch", async () => {
    const {
      wallets, deployWrapper, fundAndApprove, initWrap, decryptBalance, send
    } = await boot();
    const { alice, bob } = wallets;
    const { contract: wrapper } = await deployWrapper(4n);
    await fundAndApprove(wrapper, alice, 3n);
    await fundAndApprove(wrapper, bob, 1n);

    // batch 0: alice, alice, bob, alice
    await initWrap(wrapper, alice, alice.account.address);
    await initWrap(wrapper, alice, alice.account.address);
    await initWrap(wrapper, bob, bob.account.address);
    await initWrap(wrapper, alice, alice.account.address); // fills batch 0

    await send(wrapper.write.finalizeWrap([[0n], alice.account.address], fheTxOpts(alice.account)));
    await send(wrapper.write.finalizeWrap([[0n], bob.account.address], fheTxOpts(bob.account)));

    expect(await decryptBalance(alice)).toBe(AMOUNT * 3n);
    expect(await decryptBalance(bob)).toBe(AMOUNT * 1n);
  });
});
