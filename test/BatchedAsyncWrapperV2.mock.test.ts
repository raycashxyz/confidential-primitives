/**
 * Functional correctness for BatchedAsyncWrapperV2 — the single-finalize, cleartext-nullifier,
 * tree-reduced redesign of BatchedAsyncWrapper. Invariants under test:
 *   - one finalize path, gated on CLOSED batches (full or timeout-sealed)
 *   - cleartext (batch, recipient) replay nullifier (second finalize reverts)
 *   - whole-batch scan pays each recipient only their own matches
 *   - multi-batch finalize over strictly-increasing closed batch ids
 *   - tree reduction finalizes a batch of 32 that the serial-sum designs cannot
 *   - sealBatch liveness for a tail batch that never fills (delay-gated)
 * State-changing cases assert the recipient's confidential balance before/after.
 */
import {
  describe, it, expect
} from "vitest";
import { parseEventLogs, zeroHash } from "viem";

import { createTestEnvironment } from "./setup/environment";
import type { WalletWithAccount } from "./setup/environment";
import { encryptRecipient, decryptEuint } from "./setup/fhe";
import { txOpts, fheTxOpts } from "./setup/tx";
import { assertRevertsWith } from "./setup/asserts";
import { getOrDeployMockUSDC } from "../src/deployers/MockUSDC";
import { getOrDeployBatchedAsyncWrapperV2 } from "../src/deployers/BatchedAsyncWrapperV2";

// (both deployers are also used inline by the rate()-multiple test, which needs an
// 18-decimal underlying instead of boot()'s 6-decimal one)

const AMOUNT = 100n;
const SEAL_DELAY = 3600n; // 1h

type WrapperContract = Awaited<ReturnType<typeof getOrDeployBatchedAsyncWrapperV2>>["contract"];

async function boot () {
  const env = await createTestEnvironment();
  const {
    publicClient, wallets, store, fhevm, warpTime
  } = env;
  const { deployer } = wallets;

  // FHE calls (fheTxOpts) carry an explicit gas limit, so viem skips simulation and an
  // on-chain revert lands as a receipt instead of a throw — check status so a failed
  // deposit/finalize surfaces immediately rather than corrupting later assertions.
  const send = async (p: Promise<`0x${string}`>) => {
    const receipt = await publicClient.waitForTransactionReceipt({ hash: await p });
    if (receipt.status !== "success") throw new Error(`tx reverted: ${receipt.transactionHash}`);
    return receipt;
  };

  const { contract: underlying } = await getOrDeployMockUSDC({
    walletClient: deployer,
    publicClient,
    store,
    args: [6]
  });

  const deployWrapper = (maxBatch: bigint, sealDelay: bigint = SEAL_DELAY, force = false) =>
    getOrDeployBatchedAsyncWrapperV2({
      walletClient: deployer,
      publicClient,
      store,
      args: [
        maxBatch,
        sealDelay,
        underlying.address,
        "Batched Confidential V2",
        "bWRAP2"
      ],
      force,
    });

  const fundAndApprove = async (wrapper: WrapperContract, who: WalletWithAccount, count: bigint) => {
    await send(underlying.write.transfer([who.account.address, AMOUNT * count], txOpts(deployer.account)));
    await send(underlying.write.approve([wrapper.address, AMOUNT * count], txOpts(who.account)));
  };

  const initWrap = async (wrapper: WrapperContract, depositor: WalletWithAccount, recipient: `0x${string}`) => {
    const { handle, inputProof } = await encryptRecipient(fhevm.instance, wrapper.address, depositor.account.address, recipient);
    return send(wrapper.write.initWrap([
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
    publicClient, wallets, store, fhevm, underlying, send, warpTime, deployWrapper, fundAndApprove, initWrap, decryptBalance
  };
}

describe("BatchedAsyncWrapperV2", () => {

  describe("constructor", () => {
    it("reverts on zero batch size", async () => {
      const { deployWrapper } = await boot();
      await assertRevertsWith(deployWrapper(0n), "InvalidBatchSize");
    });

    it("reverts on batch size above the 48 HCU-budget limit", async () => {
      const { deployWrapper } = await boot();
      await assertRevertsWith(deployWrapper(49n), "InvalidBatchSize");
    });

    it("accepts batch size at the limit (48)", async () => {
      const { deployWrapper } = await boot();
      const { contract: wrapper } = await deployWrapper(48n);
      expect(await wrapper.read.maxBatchDeposits()).toBe(48n);
    });

    it("reverts on a zero seal delay (would collapse the anonymity set)", async () => {
      const { deployWrapper } = await boot();
      await assertRevertsWith(deployWrapper(4n, 0n), "SealDelayTooShort");
    });
  });

  describe("initWrap", () => {
    it("reverts when the caller is not the depositor (allowance-theft guard)", async () => {
      const {
        wallets, fhevm, deployWrapper, fundAndApprove
      } = await boot();
      const { alice, bob } = wallets;
      const { contract: wrapper } = await deployWrapper(4n);
      await fundAndApprove(wrapper, alice, 1n); // alice has a standing allowance

      // bob tries to spend alice's allowance with a recipient HE chose (encrypted, so
      // the redirect would be invisible). The depositor check must stop him.
      const { handle, inputProof } = await encryptRecipient(
        fhevm.instance, wrapper.address, bob.account.address, bob.account.address,
      );
      await assertRevertsWith(
        wrapper.write.initWrap([
          alice.account.address,
          AMOUNT,
          handle,
          inputProof
        ], txOpts(bob.account)),
        "UnauthorizedDepositor",
      );
    });

    it("reverts on amounts that are not exact multiples of rate()", async () => {
      const {
        publicClient, wallets, store, fhevm, send
      } = await boot();
      const { deployer, alice } = wallets;

      // An 18-decimal underlying against the wrapper's 6 confidential decimals gives
      // rate() = 1e12; a non-multiple would pull more in than the units minted.
      const { contract: underlying18 } = await getOrDeployMockUSDC({
        walletClient: deployer,
        publicClient,
        store,
        args: [18],
        force: true,
      });
      const { contract: wrapper } = await getOrDeployBatchedAsyncWrapperV2({
        walletClient: deployer,
        publicClient,
        store,
        args: [
          4n,
          SEAL_DELAY,
          underlying18.address,
          "Batched Confidential V2 (18d)",
          "bWRAP2e18"
        ],
        force: true,
      });
      const rate = 10n ** 12n;
      await send(underlying18.write.transfer([alice.account.address, rate * 2n], txOpts(deployer.account)));
      await send(underlying18.write.approve([wrapper.address, rate * 2n], txOpts(alice.account)));

      const { handle, inputProof } = await encryptRecipient(
        fhevm.instance, wrapper.address, alice.account.address, alice.account.address,
      );
      await assertRevertsWith(
        wrapper.write.initWrap([
          alice.account.address,
          rate + 1n,
          handle,
          inputProof
        ], txOpts(alice.account)),
        "AmountNotMultipleOfRate",
      );

      // The exact multiple goes through and records the full cleartext amount.
      const { handle: h2, inputProof: p2 } = await encryptRecipient(
        fhevm.instance, wrapper.address, alice.account.address, alice.account.address,
      );
      await send(wrapper.write.initWrap([
        alice.account.address,
        rate,
        h2,
        p2
      ], fheTxOpts(alice.account)));
      const deposit = await wrapper.read.deposits([0n]);
      expect(deposit[1]).toBe(rate);
    });

    it("pulls underlying, records the deposit, and auto-closes a full batch", async () => {
      const {
        wallets, underlying, deployWrapper, fundAndApprove, initWrap
      } = await boot();
      const { alice } = wallets;
      const { contract: wrapper } = await deployWrapper(2n);

      expect(await wrapper.read.currentBatchId()).toBe(0n);
      expect(await wrapper.read.batchClosed([0n])).toBe(false);

      await fundAndApprove(wrapper, alice, 2n);
      await initWrap(wrapper, alice, alice.account.address);
      expect(await wrapper.read.batchClosed([0n])).toBe(false); // 1/2

      await initWrap(wrapper, alice, alice.account.address);
      expect(await underlying.read.balanceOf([wrapper.address])).toBe(AMOUNT * 2n);
      expect(await wrapper.read.batchFillCount([0n])).toBe(2n);
      expect(await wrapper.read.batchClosed([0n])).toBe(true); // full -> auto-closed
      expect(await wrapper.read.currentBatchId()).toBe(1n); // rolled over
      expect(await wrapper.read.getDepositsLength()).toBe(2n);
    });
  });

  describe("finalizeWrap", () => {
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

    it("mints the sum of a recipient's deposits once the batch is full", async () => {
      const {
        wallets, deployWrapper, fundAndApprove, initWrap, decryptBalance, send
      } = await boot();
      const { alice } = wallets;
      const { contract: wrapper } = await deployWrapper(3n);
      await fundAndApprove(wrapper, alice, 3n);
      for (let i = 0; i < 3; i++) await initWrap(wrapper, alice, alice.account.address);

      expect(await decryptBalance(wrapper, alice)).toBe(0n); // before
      await send(wrapper.write.finalizeWrap([[0n], alice.account.address], fheTxOpts(alice.account)));
      expect(await decryptBalance(wrapper, alice)).toBe(AMOUNT * 3n); // after
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
      const afterFirst = await decryptBalance(wrapper, alice);
      expect(afterFirst).toBe(AMOUNT * 2n);

      await assertRevertsWith(
        wrapper.write.finalizeWrap([[0n], alice.account.address], txOpts(alice.account)),
        "AlreadyFinalized",
      );
      expect(await decryptBalance(wrapper, alice)).toBe(afterFirst); // unchanged
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

      expect(await decryptBalance(wrapper, alice)).toBe(AMOUNT * 3n);
      expect(await decryptBalance(wrapper, bob)).toBe(AMOUNT * 1n);
    });

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

  describe("sealBatch", () => {
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
      const sealReceipt = await send(wrapper.write.sealBatch([0n], txOpts(alice.account)));
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
      expect(await decryptBalance(wrapper, alice)).toBe(AMOUNT * 2n);
    });
  });
});
