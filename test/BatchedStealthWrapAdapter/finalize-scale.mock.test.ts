/**
 * BatchedStealthWrapAdapter — multi-batch finalize + the scale headline: the tree reduction
 * clears a full batch of 32. Isolated in its own file
 * (the 32-deposit case is the slowest test in the suite) so it runs on its own worker.
 */
import {
  describe, it, expect
} from "vitest";

import { useBatchedSuite, AMOUNT } from "./setup/suite";
import { txOpts, fheTxOpts } from "../setup/tx";
import { assertRevertsWith } from "../setup/asserts";

const boot = useBatchedSuite();

describe("BatchedStealthWrapAdapter finalizeWrap — multi-batch & scale", () => {
  it("finalizes multiple closed batches in one call", async () => {
    const {
      wallets, deployWrapper, fundAndApprove, initWrap, decryptBalance, send
    } = await boot();
    const { alice } = wallets;
    const { contract: wrapper } = await deployWrapper(2n);
    await fundAndApprove(wrapper, alice, 4n);
    for (let i = 0; i < 4; i++) await initWrap(wrapper, alice, alice.account.address); // batches 0 and 1 full

    expect(await wrapper.read.batchClosed([0n])).toBe(true);
    expect(await wrapper.read.batchClosed([1n])).toBe(true);

    await send(wrapper.write.finalizeWrap([[0n, 1n], alice.account.address], fheTxOpts(alice.account)));
    expect(await decryptBalance(alice)).toBe(AMOUNT * 4n);
  });

  it("rejects duplicate or non-increasing batch ids", async () => {
    const {
      wallets, deployWrapper, fundAndApprove, initWrap
    } = await boot();
    const { alice } = wallets;
    const { contract: wrapper } = await deployWrapper(2n);
    await fundAndApprove(wrapper, alice, 4n);
    for (let i = 0; i < 4; i++) await initWrap(wrapper, alice, alice.account.address);

    await assertRevertsWith(
      wrapper.write.finalizeWrap([[0n, 0n], alice.account.address], txOpts(alice.account)),
      "DuplicateId",
    );
    await assertRevertsWith(
      wrapper.write.finalizeWrap([[1n, 0n], alice.account.address], txOpts(alice.account)),
      "DuplicateId",
    );
  });

  // The headline: tree reduction keeps the add dependency depth logarithmic, so a
  // full 32-slot batch clears in one call.
  it("finalizes a batch of 32 with tree reduction", async () => {
    const {
      wallets, deployWrapper, fundAndApprove, initWrap, decryptBalance, send
    } = await boot();
    const { alice } = wallets;
    const { contract: wrapper } = await deployWrapper(32n);
    await fundAndApprove(wrapper, alice, 32n);
    for (let i = 0; i < 32; i++) await initWrap(wrapper, alice, alice.account.address);
    expect(await wrapper.read.batchClosed([0n])).toBe(true);

    await send(wrapper.write.finalizeWrap([[0n], alice.account.address], fheTxOpts(alice.account)));
    expect(await decryptBalance(alice)).toBe(AMOUNT * 32n);
  }, 300_000);
});
