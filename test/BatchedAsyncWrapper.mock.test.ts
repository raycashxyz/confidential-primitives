/**
 * Functional correctness for BatchedAsyncWrapper — the batched-bitmap variant.
 * Invariants: the euint64 batch-size cap, batch/slot accounting, and the batched-bitwise
 * finalize (full-batch mint, replay safety, full-batch guard, equivalence with the per-slot
 * finalize). State-changing cases assert the recipient's confidential balance before/after.
 */
import {
  describe, it, expect
} from "vitest";
import { zeroHash } from "viem";

import { createTestEnvironment } from "./setup/environment";
import type { WalletWithAccount } from "./setup/environment";
import { encryptRecipient, decryptEuint } from "./setup/fhe";
import { txOpts, fheTxOpts } from "./setup/tx";
import { assertRevertsWith } from "./setup/asserts";
import { getOrDeployMockUSDC } from "../src/deployers/MockUSDC";
import { getOrDeployBatchedAsyncWrapper } from "../src/deployers/BatchedAsyncWrapper";

const AMOUNT = 100n;

type WrapperContract = Awaited<ReturnType<typeof getOrDeployBatchedAsyncWrapper>>["contract"];

async function boot () {
  const env = await createTestEnvironment();
  const {
    publicClient, wallets, store, fhevm
  } = env;
  const { deployer } = wallets;

  const send = async (p: Promise<`0x${string}`>) => publicClient.waitForTransactionReceipt({ hash: await p });

  const { contract: underlying } = await getOrDeployMockUSDC({
    walletClient: deployer,
    publicClient,
    store,
    args: [6]
  });

  const deployWrapper = (maxBatch: bigint, force = false) =>
    getOrDeployBatchedAsyncWrapper({
      walletClient: deployer,
      publicClient,
      store,
      args: [
        maxBatch,
        underlying.address,
        "Batched Confidential",
        "bWRAP"
      ],
      force,
    });

  const fundAndApprove = async (wrapper: WrapperContract, who: WalletWithAccount, count: bigint) => {
    await send(underlying.write.transfer([who.account.address, AMOUNT * count], txOpts(deployer.account)));
    await send(underlying.write.approve([wrapper.address, AMOUNT * count], txOpts(who.account)));
  };

  const initWrap = async (wrapper: WrapperContract, depositor: WalletWithAccount, recipient: `0x${string}`) => {
    const { handle, inputProof } = await encryptRecipient(fhevm.instance, wrapper.address, depositor.account.address, recipient);
    await send(wrapper.write.initWrap([
      depositor.account.address,
      AMOUNT,
      handle,
      inputProof
    ], fheTxOpts(depositor.account)));
  };

  const decryptBalance = async (wrapper: WrapperContract, owner: WalletWithAccount): Promise<bigint> => {
    const handle = await wrapper.read.confidentialBalanceOf([owner.account.address]);
    if (handle === zeroHash) return 0n;
    return decryptEuint(fhevm.instance, handle, wrapper.address, owner);
  };

  return {
    wallets, underlying, send, deployWrapper, fundAndApprove, initWrap, decryptBalance
  };
}

describe("BatchedAsyncWrapper", () => {

  describe("constructor", () => {
    it("reverts on zero batch size", async () => {
      const { deployWrapper } = await boot();
      await assertRevertsWith(deployWrapper(0n), "InvalidBatchSize");
    });

    it("reverts on batch size above the 64-bit bitmap limit", async () => {
      const { deployWrapper } = await boot();
      await assertRevertsWith(deployWrapper(65n), "InvalidBatchSize");
    });

    it("accepts batch size at the limit (64)", async () => {
      const { deployWrapper } = await boot();
      const { contract: wrapper } = await deployWrapper(64n);
      expect(await wrapper.read.maxBatchDeposits()).toBe(64n);
    });
  });

  describe("initWrap", () => {
    it("pulls underlying and records the deposit", async () => {
      const {
        wallets, underlying, deployWrapper, fundAndApprove, initWrap
      } = await boot();
      const { contract: wrapper } = await deployWrapper(4n);

      await fundAndApprove(wrapper, wallets.alice, 1n);
      await initWrap(wrapper, wallets.alice, wallets.alice.account.address);

      expect(await underlying.read.balanceOf([wrapper.address])).toBe(AMOUNT);
      expect(await wrapper.read.totalDeposits()).toBe(1n);
      const deposit = await wrapper.read.deposits([0n]);
      expect(deposit[0]).toBe(wallets.alice.account.address); // depositor
      expect(deposit[1]).toBe(AMOUNT); // cleartext amount
    });
  });

  describe("finalizeWrapBatched", () => {
    it("mints the sum of a recipient's deposits in a full batch", async () => {
      const {
        wallets, deployWrapper, fundAndApprove, initWrap, decryptBalance, send
      } = await boot();
      const { alice } = wallets;
      const { contract: wrapper } = await deployWrapper(4n);
      await fundAndApprove(wrapper, alice, 4n);
      for (let i = 0; i < 4; i++) await initWrap(wrapper, alice, alice.account.address);

      expect(await decryptBalance(wrapper, alice)).toBe(0n); // before
      await send(wrapper.write.finalizeWrapBatched([0n, alice.account.address], fheTxOpts(alice.account)));
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

      await send(wrapper.write.finalizeWrapBatched([0n, alice.account.address], fheTxOpts(alice.account)));
      const afterFirst = await decryptBalance(wrapper, alice);
      expect(afterFirst).toBe(AMOUNT * 2n);

      await send(wrapper.write.finalizeWrapBatched([0n, alice.account.address], fheTxOpts(alice.account)));
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
        wrapper.write.finalizeWrapBatched([0n, alice.account.address], txOpts(alice.account)),
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

      await send(perSlot.write.finalizeWrap([0n, alice.account.address], fheTxOpts(alice.account)));
      await send(batched.write.finalizeWrapBatched([0n, alice.account.address], fheTxOpts(alice.account)));

      const viaPerSlot = await decryptBalance(perSlot, alice);
      const viaBatched = await decryptBalance(batched, alice);
      expect(viaBatched).toBe(viaPerSlot);
      expect(viaBatched).toBe(AMOUNT * 4n);
    });
  });

});
