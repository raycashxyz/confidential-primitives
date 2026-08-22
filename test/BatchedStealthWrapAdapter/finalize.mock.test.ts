/**
 * BatchedStealthWrapAdapter: finalizeWrap correctness (gating, no-double-spend via the encrypted
 * claimed accumulator, per-recipient scan). Retry-safety against a soft-failing wrapper lives in the
 * sibling *.retry-safety file; multi-batch + scale cases in *.finalize-scale.
 */
import {
  describe, it, expect
} from "vitest";

import { useBatchedSuite, AMOUNT } from "./setup/suite";
import { txOpts, fheTxOpts } from "../setup/tx";
import { assertRevertsWith } from "../setup/asserts";

const boot = useBatchedSuite();

describe("BatchedStealthWrapAdapter finalizeWrap", () => {
  // An empty id set scanned nothing but still made a real confidentialTransfer of the encrypted
  // zero, emitting WrapFinalized(recipient, handle, []) against any address that need never have
  // touched the protocol, and repeatable at gas cost.
  it("rejects an empty id set instead of emitting a forged claim", async () => {
    const { wallets, deployWrapper } = await boot();
    const { alice, bob } = wallets;
    const { contract: wrapper } = await deployWrapper(4n);

    await assertRevertsWith(
      wrapper.write.finalizeWrap([[], bob.account.address], txOpts(alice.account)),
      "InvalidId",
    );
  });

  it("reverts while the batch is still open", async () => {
    const {
      wallets, deployWrapper, fundAndApprove, initWrap
    } = await boot();
    const { alice } = wallets;
    const { contract: wrapper } = await deployWrapper(4n);
    await fundAndApprove(wrapper, alice, 1n);
    await initWrap(wrapper, alice, alice.account.address); // 1/4, open

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

  it("does not double-pay a fully claimed batch on replay", async () => {
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

    // No cleartext nullifier: a replay does not revert, but `owed` is now zero so it delivers
    // nothing. The accumulator, not a boolean, is what stops the double-pay.
    await send(wrapper.write.finalizeWrap([[0n], alice.account.address], fheTxOpts(alice.account)));
    expect(await decryptBalance(alice)).toBe(afterFirst); // unchanged
  });

  // `ids` and `recipient` are both visible in the mempool. The old all-or-nothing nullifier let a
  // front-run of one batch revert the whole multi-batch call; the accumulator makes an
  // already-claimed batch contribute an encrypted zero instead, so the original call still lands.
  it("a front-run of one batch does not break the multi-batch finalize", async () => {
    const {
      wallets, deployWrapper, fundAndApprove, initWrap, decryptBalance, send
    } = await boot();
    const { alice, bob } = wallets;
    const { contract: wrapper } = await deployWrapper(2n);
    await fundAndApprove(wrapper, alice, 4n);
    for (let i = 0; i < 4; i++) await initWrap(wrapper, alice, alice.account.address); // batches 0, 1

    // The front-run: a third party claims batch 0 for alice. She still receives the money.
    await send(wrapper.write.finalizeWrap([[0n], alice.account.address], fheTxOpts(bob.account)));
    expect(await decryptBalance(alice)).toBe(AMOUNT * 2n);

    // Alice's original [0, 1] call succeeds, paying only what batch 1 still owes.
    await send(wrapper.write.finalizeWrap([[0n, 1n], alice.account.address], fheTxOpts(alice.account)));
    expect(await decryptBalance(alice)).toBe(AMOUNT * 4n);

    // A fully-claimed replay is a no-op, not a revert.
    await send(wrapper.write.finalizeWrap([[0n, 1n], alice.account.address], fheTxOpts(alice.account)));
    expect(await decryptBalance(alice)).toBe(AMOUNT * 4n);
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
