/**
 * BatchedStealthWrapAdapter — sealBatch liveness: a tail batch that never fills can be sealed
 * after the delay so it can still finalize.
 */
import {
  describe, it, expect
} from "vitest";
import { parseEventLogs, zeroAddress } from "viem";

import { useBatchedSuite, AMOUNT, SEAL_DELAY } from "./setup/suite";
import { txOpts, fheTxOpts } from "../setup/tx";
import { assertRevertsWith } from "../setup/asserts";

const boot = useBatchedSuite();

describe("BatchedStealthWrapAdapter sealBatch", () => {
  it("reverts before the seal delay elapses", async () => {
    const {
      wallets, deployWrapper, fundAndApprove, initWrap
    } = await boot();
    const { alice } = wallets;
    const { contract: wrapper } = await deployWrapper(4n);
    await fundAndApprove(wrapper, alice, 1n);
    await initWrap(wrapper, alice, alice.account.address);

    await assertRevertsWith(
      wrapper.write.sealBatch([0n], txOpts(alice.account)),
      "SealDelayNotElapsed",
    );
  });

  // With the timer anchored to the LAST deposit, anyone could push the deadline out one dust
  // deposit at a time for every free slot — up to ~(maxBatchDeposits - fillCount) * sealDelay, and
  // since finalizeWrap names its recipient in cleartext calldata, aimed at a specific pending
  // finalization. Anchoring to the first deposit gives the batch a lifetime nobody can extend.
  it("does not let later deposits push out the seal deadline", async () => {
    const {
      wallets, deployWrapper, fundAndApprove, initWrap, send, warpTime
    } = await boot();
    const { alice, bob } = wallets;
    const { contract: wrapper } = await deployWrapper(4n);
    await fundAndApprove(wrapper, alice, 1n);
    await fundAndApprove(wrapper, bob, 2n);

    await initWrap(wrapper, alice, alice.account.address);
    const anchor = await wrapper.read.batchFirstDepositAt([0n]);
    expect(anchor).toBeGreaterThan(0n);

    // A griefer tops the batch up twice, well inside the window.
    await warpTime(SEAL_DELAY / 2n);
    await initWrap(wrapper, bob, bob.account.address);
    await warpTime(SEAL_DELAY / 2n - 10n);
    await initWrap(wrapper, bob, bob.account.address);

    // The anchor never moved, even though lastDepositAt did.
    expect(await wrapper.read.batchFirstDepositAt([0n])).toBe(anchor);
    expect(await wrapper.read.batchLastDepositAt([0n])).toBeGreaterThan(anchor);

    // ...so the batch seals on schedule rather than a delay per remaining slot.
    await warpTime(20n);
    await send(wrapper.write.sealBatch([0n], fheTxOpts(alice.account)));
    expect(await wrapper.read.batchClosed([0n])).toBe(true);
  });

  // Slots are indexed batchId * maxBatchDeposits + batchIndex, so sealing a partial batch leaves
  // its unused slots empty forever. Enumerating [0, totalDeposits) would walk right past the
  // deposits that live after the gap.
  it("reports a slot bound that spans the gap left by a sealed partial batch", async () => {
    const {
      wallets, deployWrapper, fundAndApprove, initWrap, send, warpTime
    } = await boot();
    const { alice } = wallets;
    const { contract: wrapper } = await deployWrapper(4n);
    await fundAndApprove(wrapper, alice, 2n);

    await initWrap(wrapper, alice, alice.account.address); // slot 0, batch 0
    await warpTime(SEAL_DELAY + 1n);
    await send(wrapper.write.sealBatch([0n], fheTxOpts(alice.account)));
    await initWrap(wrapper, alice, alice.account.address); // slot 4, batch 1

    expect(await wrapper.read.totalDeposits()).toBe(2n);
    expect(await wrapper.read.getDepositsLength()).toBe(5n); // slots 1..3 are permanently empty
    expect((await wrapper.read.deposits([4n]))[0]).toBe(alice.account.address);
    expect((await wrapper.read.deposits([1n]))[0]).toBe(zeroAddress);
  });

  it("reverts on an empty batch", async () => {
    const { wallets, deployWrapper } = await boot();
    const { contract: wrapper } = await deployWrapper(4n);
    await assertRevertsWith(
      wrapper.write.sealBatch([0n], txOpts(wallets.alice.account)),
      "NothingToSeal",
    );
  });

  it("seals a stuck partial batch after the delay and lets it finalize (liveness)", async () => {
    const {
      wallets, deployWrapper, fundAndApprove, initWrap, decryptBalance, send, warpTime
    } = await boot();
    const { alice } = wallets;
    const { contract: wrapper } = await deployWrapper(4n);
    await fundAndApprove(wrapper, alice, 2n);

    // Only 2 of 4 slots ever fill — without sealing, the batch could never finalize.
    await initWrap(wrapper, alice, alice.account.address);
    await initWrap(wrapper, alice, alice.account.address);
    expect(await wrapper.read.batchClosed([0n])).toBe(false);

    await warpTime(SEAL_DELAY + 1n);
    // sealBatch is a state-changing write whose gas tevm under-estimates (the reentrancy-guard
    // SSTOREs tip it into a silent OOG), so send with an explicit gas limit like the FHE calls.
    const sealReceipt = await send(wrapper.write.sealBatch([0n], fheTxOpts(alice.account)));
    const [sealed] = parseEventLogs({
      abi: wrapper.abi,
      logs: sealReceipt.logs,
      eventName: "BatchSealed"
    });
    if (!sealed) throw new Error("expected a BatchSealed event");
    expect(sealed.args.batchId).toBe(0n);
    expect(sealed.args.filled).toBe(2n);
    expect(await wrapper.read.batchClosed([0n])).toBe(true);
    expect(await wrapper.read.currentBatchId()).toBe(1n);

    await send(wrapper.write.finalizeWrap([[0n], alice.account.address], fheTxOpts(alice.account)));
    expect(await decryptBalance(alice)).toBe(AMOUNT * 2n);
  });

  it("auto-seals a stuck partial batch on the first finalize after the delay", async () => {
    const {
      wallets, deployWrapper, fundAndApprove, initWrap, decryptBalance, send, warpTime
    } = await boot();
    const { alice } = wallets;
    const { contract: wrapper } = await deployWrapper(4n);
    await fundAndApprove(wrapper, alice, 2n);

    await initWrap(wrapper, alice, alice.account.address);
    await initWrap(wrapper, alice, alice.account.address);
    expect(await wrapper.read.batchClosed([0n])).toBe(false);

    await warpTime(SEAL_DELAY + 1n);
    await send(wrapper.write.finalizeWrap([[0n], alice.account.address], fheTxOpts(alice.account)));

    expect(await wrapper.read.batchClosed([0n])).toBe(true);
    expect(await wrapper.read.currentBatchId()).toBe(1n);
    expect(await decryptBalance(alice)).toBe(AMOUNT * 2n);
  });
});
