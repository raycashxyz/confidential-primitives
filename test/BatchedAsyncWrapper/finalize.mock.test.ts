/**
 * BatchedAsyncWrapper — finalizeWrapBatched: full-batch mint, replay safety, the full-batch
 * guard, and equivalence with the per-slot finalize. Shares the harness in setup/suite.
 */
import {
  describe, it, expect
} from "vitest";
import { parseEventLogs, zeroHash } from "viem";

import { useBatchedSuite, AMOUNT } from "./setup/suite";
import { txOpts, fheTxOpts } from "../setup/tx";
import { assertRevertsWith } from "../setup/asserts";

const boot = useBatchedSuite();

describe("BatchedAsyncWrapper finalizeWrapBatched", () => {
  it("mints the sum of a recipient's deposits in a full batch", async () => {
    const {
      wallets, deployWrapper, fundAndApprove, initWrap, decryptBalance, send
    } = await boot();
    const { alice } = wallets;
    const { contract: wrapper } = await deployWrapper(4n);
    await fundAndApprove(wrapper, alice, 4n);
    for (let i = 0; i < 4; i++) await initWrap(wrapper, alice, alice.account.address);

    expect(await decryptBalance(wrapper, alice)).toBe(0n); // before
    await send(wrapper.write.finalizeWrap([[0n], alice.account.address], fheTxOpts(alice.account)));
    expect(await decryptBalance(wrapper, alice)).toBe(AMOUNT * 4n); // after
  });

  it("is replay-safe: a second batched finalize pays nothing", async () => {
    const {
      wallets, deployWrapper, fundAndApprove, initWrap, decryptBalance, send
    } = await boot();
    const { alice } = wallets;
    const { contract: wrapper } = await deployWrapper(2n);
    await fundAndApprove(wrapper, alice, 2n);
    for (let i = 0; i < 2; i++) await initWrap(wrapper, alice, alice.account.address);

    await send(wrapper.write.finalizeWrap([[0n], alice.account.address], fheTxOpts(alice.account)));
    const afterFirst = await decryptBalance(wrapper, alice);
    expect(afterFirst).toBe(AMOUNT * 2n);

    await send(wrapper.write.finalizeWrap([[0n], alice.account.address], fheTxOpts(alice.account)));
    expect(await decryptBalance(wrapper, alice)).toBe(afterFirst); // no double mint
  });

  it("reverts on an incomplete batch", async () => {
    const {
      wallets, deployWrapper, fundAndApprove, initWrap
    } = await boot();
    const { alice } = wallets;
    const { contract: wrapper } = await deployWrapper(4n);
    await fundAndApprove(wrapper, alice, 2n);
    for (let i = 0; i < 2; i++) await initWrap(wrapper, alice, alice.account.address); // 2/4 — not full

    // No explicit gas → viem simulates and surfaces the custom error.
    await assertRevertsWith(
      wrapper.write.finalizeWrap([[0n], alice.account.address], txOpts(alice.account)),
      "BatchNotComplete",
    );
  });

  it("matches the per-slot finalizeWrap on a full batch", async () => {
    const {
      wallets, deployWrapper, fundAndApprove, initWrap, decryptBalance, send
    } = await boot();
    const { alice } = wallets;

    // Two independent wrappers, same deposits; finalize each with a different strategy.
    const { contract: perSlot } = await deployWrapper(4n);
    const { contract: batched } = await deployWrapper(4n, true); // force: distinct instance

    for (const w of [perSlot, batched]) {
      await fundAndApprove(w, alice, 4n);
      for (let i = 0; i < 4; i++) await initWrap(w, alice, alice.account.address);
    }

    await send(perSlot.write.finalizeWrapPerSlot([0n, alice.account.address], fheTxOpts(alice.account)));
    await send(batched.write.finalizeWrap([[0n], alice.account.address], fheTxOpts(alice.account)));

    const viaPerSlot = await decryptBalance(perSlot, alice);
    const viaBatched = await decryptBalance(batched, alice);
    expect(viaBatched).toBe(viaPerSlot);
    expect(viaBatched).toBe(AMOUNT * 4n);
  });

  it("reverts the per-slot path on an incomplete batch", async () => {
    const {
      wallets, deployWrapper, fundAndApprove, initWrap
    } = await boot();
    const { alice } = wallets;
    const { contract: wrapper } = await deployWrapper(4n);
    await fundAndApprove(wrapper, alice, 2n);
    for (let i = 0; i < 2; i++) await initWrap(wrapper, alice, alice.account.address); // 2/4 — not full

    // No explicit gas → viem simulates and surfaces the custom error.
    await assertRevertsWith(
      wrapper.write.finalizeWrapPerSlot([0n, alice.account.address], txOpts(alice.account)),
      "BatchNotComplete",
    );
  });

  it("does not double-mint when both finalize paths run on the same batch", async () => {
    const {
      wallets, deployWrapper, fundAndApprove, initWrap, decryptBalance, send
    } = await boot();
    const { alice } = wallets;
    const { contract: wrapper } = await deployWrapper(4n);
    await fundAndApprove(wrapper, alice, 4n);
    for (let i = 0; i < 4; i++) await initWrap(wrapper, alice, alice.account.address);

    expect(await decryptBalance(wrapper, alice)).toBe(0n); // before
    await send(wrapper.write.finalizeWrapPerSlot([0n, alice.account.address], fheTxOpts(alice.account)));
    const afterPerSlot = await decryptBalance(wrapper, alice);
    expect(afterPerSlot).toBe(AMOUNT * 4n); // per-slot paid the whole batch

    // Bulk finalize over the SAME batch must pay nothing: every matched slot is already committed.
    await send(wrapper.write.finalizeWrap([[0n], alice.account.address], fheTxOpts(alice.account)));
    expect(await decryptBalance(wrapper, alice)).toBe(afterPerSlot); // no cross-path double-mint
  });

  it("emits WrapInitiated on deposit and WrapFinalized on finalize", async () => {
    const {
      wallets, deployWrapper, fundAndApprove, initWrap, send
    } = await boot();
    const { alice } = wallets;
    const { contract: wrapper } = await deployWrapper(2n);
    await fundAndApprove(wrapper, alice, 2n);

    const initReceipt = await initWrap(wrapper, alice, alice.account.address); // slot 0
    const [initEvent] = parseEventLogs({
      abi: wrapper.abi,
      logs: initReceipt.logs,
      eventName: "WrapInitiated"
    });
    if (!initEvent) throw new Error("expected a WrapInitiated event");
    expect(initEvent.args.batchId).toBe(0n);
    expect(initEvent.args.slot).toBe(0n);
    expect(initEvent.args.depositor).toBe(alice.account.address);
    expect(initEvent.args.amount).toBe(AMOUNT);
    expect(initEvent.args.eRecipient).not.toBe(zeroHash);

    await initWrap(wrapper, alice, alice.account.address); // slot 1 — batch now complete (2/2)
    const finalizeReceipt = await send(
      wrapper.write.finalizeWrap([[0n], alice.account.address], fheTxOpts(alice.account)),
    );
    const [finalizeEvent] = parseEventLogs({
      abi: wrapper.abi,
      logs: finalizeReceipt.logs,
      eventName: "WrapFinalized"
    });
    if (!finalizeEvent) throw new Error("expected a WrapFinalized event");
    expect(finalizeEvent.args.recipient).toBe(alice.account.address);
    expect(finalizeEvent.args.ids).toEqual([0n]);
    expect(finalizeEvent.args.amount).not.toBe(zeroHash);
  });
});
