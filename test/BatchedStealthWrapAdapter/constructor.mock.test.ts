/**
 * BatchedStealthWrapAdapter — constructor + initWrap.
 * (finalizeWrap and sealBatch live in the sibling *.finalize / *.finalize-scale / *.seal files
 * so vitest can run them on separate workers; all share the harness in setup/suite.)
 */
import {
  describe, it, expect
} from "vitest";
import { decodeEventLog, parseAbiItem } from "viem";

import { useBatchedSuite, AMOUNT, SEAL_DELAY } from "./setup/suite";
import { encryptRecipient } from "../setup/fhe";
import { txOpts, fheTxOpts } from "../setup/tx";
import { assertRevertsWith } from "../setup/asserts";
import { getOrDeployMockUSDC } from "../../src/deployers/MockUSDC";
import { getOrDeployMockERC7984ERC20Wrapper } from "../../src/deployers/MockERC7984ERC20Wrapper";
import { getOrDeployBatchedStealthWrapAdapter } from "../../src/deployers/BatchedStealthWrapAdapter";
import { getOrDeployMockBatchedStealthWrapAdapterExtension } from "../../src/deployers/MockBatchedStealthWrapAdapterExtension";

const boot = useBatchedSuite();

describe("BatchedStealthWrapAdapter", () => {

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
    it("lets a subclass override initWrap and record through the batched deposit hook", async () => {
      const {
        publicClient, wallets, store, confidentialWrapper, underlying, fhevm, send
      } = await boot();
      const { deployer, alice } = wallets;
      const { contract: wrapper } = await getOrDeployMockBatchedStealthWrapAdapterExtension({
        walletClient: deployer,
        publicClient,
        store,
        args: [2n, SEAL_DELAY, confidentialWrapper.address],
        force: true,
      });

      await send(underlying.write.transfer([alice.account.address, AMOUNT], txOpts(deployer.account)));
      await send(underlying.write.approve([wrapper.address, AMOUNT], txOpts(alice.account)));
      const { handle, inputProof } = await encryptRecipient(
        fhevm.instance, wrapper.address, alice.account.address, alice.account.address,
      );
      await send(wrapper.write.initWrap([AMOUNT, handle, inputProof], fheTxOpts(alice.account)));

      const deposit = await wrapper.read.deposits([0n]);
      expect(deposit[0]).toBe(alice.account.address);
      expect(deposit[1]).toBe(AMOUNT);
      expect(await wrapper.read.batchFillCount([0n])).toBe(1n);
      expect(await wrapper.read.getDepositsLength()).toBe(1n);
      expect(await underlying.read.balanceOf([confidentialWrapper.address])).toBe(AMOUNT);
    });

    it("lets a subclass acquire from and record a depositor distinct from the caller", async () => {
      const {
        publicClient, wallets, store, confidentialWrapper, underlying, fhevm, send
      } = await boot();
      const { deployer, alice, bob } = wallets;
      const { contract: wrapper } = await getOrDeployMockBatchedStealthWrapAdapterExtension({
        walletClient: deployer,
        publicClient,
        store,
        args: [2n, SEAL_DELAY, confidentialWrapper.address],
        force: true,
      });

      await send(underlying.write.transfer([bob.account.address, AMOUNT], txOpts(deployer.account)));
      await send(underlying.write.approve([wrapper.address, AMOUNT], txOpts(bob.account)));
      const { handle, inputProof } = await encryptRecipient(
        fhevm.instance, wrapper.address, alice.account.address, alice.account.address,
      );
      const receipt = await send(wrapper.write.initWrapFor([
        bob.account.address,
        AMOUNT,
        handle,
        inputProof,
      ], fheTxOpts(alice.account)));

      const deposit = await wrapper.read.deposits([0n]);
      expect(deposit[0]).toBe(bob.account.address);
      expect(deposit[1]).toBe(AMOUNT);
      expect(await underlying.read.balanceOf([confidentialWrapper.address])).toBe(AMOUNT);

      const wrapInitiated = receipt.logs
        .map((log) => {
          try {
            return decodeEventLog({
              abi: [parseAbiItem("event WrapInitiated(uint256 indexed batchId, uint256 indexed slot, address indexed depositor, uint256 amount, bytes32 eRecipient)")],
              data: log.data,
              topics: log.topics,
            });
          } catch {
            return undefined;
          }
        })
        .find((event) => event?.eventName === "WrapInitiated");
      expect(wrapInitiated?.args.depositor).toBe(bob.account.address);
    });

    it("lets a subclass replace finalizeWrap", async () => {
      const { publicClient, wallets, store, confidentialWrapper } = await boot();
      const { deployer, alice } = wallets;
      const { contract: wrapper } = await getOrDeployMockBatchedStealthWrapAdapterExtension({
        walletClient: deployer,
        publicClient,
        store,
        args: [2n, SEAL_DELAY, confidentialWrapper.address],
        force: true,
      });

      await assertRevertsWith(
        wrapper.write.finalizeWrap([[], alice.account.address], txOpts(alice.account)),
        "FinalizeOverrideCalled",
      );
    });

    it("rounds non-multiple amounts down through the configured wrapper rate", async () => {
      const {
        publicClient, wallets, store, fhevm, send
      } = await boot();
      const { deployer, alice } = wallets;

      // An 18-decimal underlying against the wrapper's 6 confidential decimals gives
      // rate() = 1e12, so `rate + 1` wraps to exactly one confidential unit.
      const { contract: underlying18 } = await getOrDeployMockUSDC({
        walletClient: deployer,
        publicClient,
        store,
        args: [18],
        force: true,
      });
      const { contract: confidentialWrapper18 } = await getOrDeployMockERC7984ERC20Wrapper({
        walletClient: deployer,
        publicClient,
        store,
        args: [
          underlying18.address,
          "Confidential USDC (18d)",
          "cUSDCe18"
        ],
        force: true,
      });
      const { contract: wrapper } = await getOrDeployBatchedStealthWrapAdapter({
        walletClient: deployer,
        publicClient,
        store,
        args: [
          4n,
          SEAL_DELAY,
          confidentialWrapper18.address
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
          rate - 1n,
          handle,
          inputProof
        ], txOpts(alice.account)),
        "ZeroAmount",
      );

      // Non-multiples are rounded down by the configured wrapper; the adapter
      // records the amount actually wrapped, not the requested amount.
      const { handle: h2, inputProof: p2 } = await encryptRecipient(
        fhevm.instance, wrapper.address, alice.account.address, alice.account.address,
      );
      await send(wrapper.write.initWrap([
        rate + 1n,
        h2,
        p2
      ], fheTxOpts(alice.account)));
      const deposit = await wrapper.read.deposits([0n]);
      expect(deposit[1]).toBe(rate);
      expect(await underlying18.read.balanceOf([confidentialWrapper18.address])).toBe(rate);
    });

    it("pulls underlying, records the deposit, and auto-closes a full batch", async () => {
      const {
        wallets, underlying, confidentialWrapper, deployWrapper, fundAndApprove, initWrap
      } = await boot();
      const { alice } = wallets;
      const { contract: wrapper } = await deployWrapper(2n);

      expect(await wrapper.read.currentBatchId()).toBe(0n);
      expect(await wrapper.read.batchClosed([0n])).toBe(false);

      await fundAndApprove(wrapper, alice, 2n);
      await initWrap(wrapper, alice, alice.account.address);
      expect(await wrapper.read.batchClosed([0n])).toBe(false); // 1/2

      await initWrap(wrapper, alice, alice.account.address);
      expect(await underlying.read.balanceOf([confidentialWrapper.address])).toBe(AMOUNT * 2n);
      expect(await wrapper.read.batchFillCount([0n])).toBe(2n);
      expect(await wrapper.read.batchClosed([0n])).toBe(true); // full -> auto-closed
      expect(await wrapper.read.currentBatchId()).toBe(1n); // rolled over
      expect(await wrapper.read.getDepositsLength()).toBe(2n);
    });
  });

});
