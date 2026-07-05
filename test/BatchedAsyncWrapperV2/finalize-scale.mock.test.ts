/**
 * BatchedAsyncWrapperV2 — multi-batch finalize + the scale headline: the tree reduction
 * clears a full batch of 32 that the serial-sum designs cannot. Isolated in its own file
 * (the 32-deposit case is the slowest test in the suite) so it runs on its own worker.
 */
import {
  describe, it, expect
} from "vitest";

import { useBatchedV2Suite, AMOUNT } from "./setup/suite";
import { txOpts, fheTxOpts } from "../setup/tx";
import { assertRevertsWith } from "../setup/asserts";

const boot = useBatchedV2Suite();

describe("BatchedAsyncWrapperV2 finalizeWrap — multi-batch & scale", () => {
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
    expect(await decryptBalance(wrapper, alice)).toBe(AMOUNT * 4n);
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

  // The headline: the serial-sum designs revert on the FHEVM 5M HCU DEPTH cap at ~29
  // deposits (see the gas benchmark's extended rows); the tree reduction
  // (depth ~log2 N) clears a full batch of 32 in one call.
  it("finalizes a batch of 32 that the serial-sum designs cannot (tree reduction)", async () => {
    const {
      wallets, deployWrapper, fundAndApprove, initWrap, decryptBalance, send
    } = await boot();
    const { alice } = wallets;
    const { contract: wrapper } = await deployWrapper(32n);
    await fundAndApprove(wrapper, alice, 32n);
    for (let i = 0; i < 32; i++) await initWrap(wrapper, alice, alice.account.address);
    expect(await wrapper.read.batchClosed([0n])).toBe(true);

    await send(wrapper.write.finalizeWrap([[0n], alice.account.address], fheTxOpts(alice.account)));
    expect(await decryptBalance(wrapper, alice)).toBe(AMOUNT * 32n);
  }, 300_000);
});
