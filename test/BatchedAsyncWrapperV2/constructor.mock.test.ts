/**
 * BatchedAsyncWrapperV2 — constructor + initWrap.
 * (finalizeWrap and sealBatch live in the sibling *.finalize / *.finalize-scale / *.seal files
 * so vitest can run them on separate workers; all share the harness in setup/suite.)
 */
import {
  describe, it, expect
} from "vitest";

import { useBatchedV2Suite, AMOUNT, SEAL_DELAY } from "./setup/suite";
import { encryptRecipient } from "../setup/fhe";
import { txOpts, fheTxOpts } from "../setup/tx";
import { assertRevertsWith } from "../setup/asserts";
import { getOrDeployMockUSDC } from "../../src/deployers/MockUSDC";
import { getOrDeployBatchedAsyncWrapperV2 } from "../../src/deployers/BatchedAsyncWrapperV2";

const boot = useBatchedV2Suite();

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

});
