/**
 * BatchedStealthWrapAdapter: constructor + initWrap.
 * finalizeWrap and sealBatch live in the sibling *.finalize / *.finalize-scale / *.seal files
 * so vitest can run them on separate workers. All share the harness in setup/suite.
 */
import {
  describe, it, expect
} from "vitest";
import { decodeEventLog, parseAbiItem, zeroHash } from "viem";

import { useBatchedSuite, AMOUNT, SEAL_DELAY } from "./setup/suite";
import { encryptRecipient } from "../setup/fhe";
import { txOpts, fheTxOpts } from "../setup/tx";
import { assertRevertsWith } from "../setup/asserts";
import { getOrDeployMockUSDC } from "../../src/deployers/MockUSDC";
import { getOrDeployMockERC7984ERC20Wrapper } from "../../src/deployers/MockERC7984ERC20Wrapper";
import { getOrDeployBatchedStealthWrapAdapter } from "../../src/deployers/BatchedStealthWrapAdapter";
import { getOrDeployMockBatchedStealthWrapAdapterExtension } from "../../src/deployers/MockBatchedStealthWrapAdapterExtension";
import { getOrDeployMockTransientAmountAdapter } from "../../src/deployers/MockTransientAmountAdapter";
import { getOrDeployMockReusableHandleAdapter } from "../../src/deployers/MockReusableHandleAdapter";

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
    // Every legitimate deposit carries a proof. `FHEUtils.fromExternal` rejects an empty one before
    // the coprocessor is called.
    it("rejects an empty inputProof (the handle would skip the coprocessor's type check)", async () => {
      const {
        wallets, fhevm, deployWrapper, fundAndApprove
      } = await boot();
      const { alice } = wallets;
      const { contract: wrapper } = await deployWrapper(2n);
      await fundAndApprove(wrapper, alice, 1n);

      const { handle } = await encryptRecipient(
        fhevm.instance, wrapper.address, alice.account.address, alice.account.address,
      );
      await assertRevertsWith(
        wrapper.write.initWrap([AMOUNT, handle, "0x"], txOpts(alice.account)),
        "MissingInputProof",
      );
    });

    // The handle is public in WrapInitiated so the recipient can spot their payment, which makes
    // reuse a stable tag linking otherwise separate deposits as "same unknown recipient".
    it("rejects a replayed recipient handle but allows a fresh one for the same address", async () => {
      const {
        wallets, fhevm, deployWrapper, fundAndApprove, send
      } = await boot();
      const { alice } = wallets;
      const { contract: wrapper } = await deployWrapper(4n);
      await fundAndApprove(wrapper, alice, 2n);

      const { handle, inputProof } = await encryptRecipient(
        fhevm.instance, wrapper.address, alice.account.address, alice.account.address,
      );
      await send(wrapper.write.initWrap([AMOUNT, handle, inputProof], fheTxOpts(alice.account)));
      expect(await wrapper.read.recipientHandleUsed([handle])).toBe(true);

      await assertRevertsWith(
        wrapper.write.initWrap([AMOUNT, handle, inputProof], txOpts(alice.account)),
        "RecipientHandleAlreadyUsed",
      );

      // A new encryption of the SAME recipient is a different handle, so paying them again is fine.
      const fresh = await encryptRecipient(
        fhevm.instance, wrapper.address, alice.account.address, alice.account.address,
      );
      expect(fresh.handle).not.toBe(handle);
      await send(wrapper.write.initWrap([AMOUNT, fresh.handle, fresh.inputProof], fheTxOpts(alice.account)));
      expect(await wrapper.read.batchFillCount([0n])).toBe(2n);
    });

    // Single-use is the default and a subclass may permit reuse. A deposit-address flow keyed on the
    // handle (salt == handle) cannot rotate it, and its deposits are already clustered by the payer's
    // clear transfer to that public address. Reuse must stay claimable, so both deposits pay out to R.
    it("lets a subclass permit handle reuse without breaking the payout", async () => {
      const {
        publicClient, wallets, store, confidentialWrapper, underlying, fhevm, send, decryptBalance
      } = await boot();
      const { deployer, alice } = wallets;
      const { contract: wrapper } = await getOrDeployMockReusableHandleAdapter({
        walletClient: deployer,
        publicClient,
        store,
        args: [2n, SEAL_DELAY, confidentialWrapper.address], // 2 slots -> closes on the second deposit
        force: true,
      });

      await send(underlying.write.transfer([alice.account.address, AMOUNT * 2n], txOpts(deployer.account)));
      await send(underlying.write.approve([wrapper.address, AMOUNT * 2n], txOpts(alice.account)));
      const { handle, inputProof } = await encryptRecipient(
        fhevm.instance, wrapper.address, alice.account.address, alice.account.address,
      );

      await send(wrapper.write.initWrap([AMOUNT, handle, inputProof], fheTxOpts(alice.account)));
      // The handle is recorded as seen, since the view reports history, not policy...
      expect(await wrapper.read.recipientHandleUsed([handle])).toBe(true);
      // ...so the same handle is accepted again where the base adapter reverts.
      await send(wrapper.write.initWrap([AMOUNT, handle, inputProof], fheTxOpts(alice.account)));
      expect(await wrapper.read.batchFillCount([0n])).toBe(2n);
      expect(await wrapper.read.batchClosed([0n])).toBe(true);

      await send(wrapper.write.finalizeWrap([[0n], alice.account.address], fheTxOpts(alice.account)));
      expect(await decryptBalance(alice)).toBe(AMOUNT * 2n);
    });

    // The empty-proof check and the typed import sit in `_verifyRecipient`, outside the overridable
    // freshness hook, so a subclass that relaxes reuse cannot relax the type check that closes the
    // Bool/euint64 attacks.
    it("keeps the empty-proof check on a subclass that permits handle reuse", async () => {
      const {
        publicClient, wallets, store, confidentialWrapper, fhevm
      } = await boot();
      const { deployer, alice } = wallets;
      const { contract: wrapper } = await getOrDeployMockReusableHandleAdapter({
        walletClient: deployer,
        publicClient,
        store,
        args: [2n, SEAL_DELAY, confidentialWrapper.address],
        force: true,
      });

      const { handle } = await encryptRecipient(
        fhevm.instance, wrapper.address, alice.account.address, alice.account.address,
      );
      await assertRevertsWith(
        wrapper.write.initWrap([AMOUNT, handle, "0x"], txOpts(alice.account)),
        "MissingInputProof",
      );
    });

    it("rejects an empty inputProof through a subclass's own deposit path", async () => {
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
      const { handle } = await encryptRecipient(
        fhevm.instance, wrapper.address, alice.account.address, alice.account.address,
      );

      await assertRevertsWith(
        wrapper.write.initWrap([AMOUNT, handle, "0x"], txOpts(alice.account)),
        "MissingInputProof",
      );
      await assertRevertsWith(
        wrapper.write.initWrapFor([alice.account.address, AMOUNT, handle, "0x"], txOpts(alice.account)),
        "MissingInputProof",
      );
    });

    // `_recordBatchedDeposit` is advertised as the reusable hook for adapters that acquire funds
    // some other way. Those can hold only transient authorization on the amount, which expires at
    // the end of the transaction, so finalize could never touch the stored ciphertext again.
    it("persists ACL access to eAmount for a subclass that supplies it transiently", async () => {
      const {
        publicClient, wallets, store, confidentialWrapper, fhevm, send
      } = await boot();
      const { deployer, alice } = wallets;
      const { contract: wrapper } = await getOrDeployMockTransientAmountAdapter({
        walletClient: deployer,
        publicClient,
        store,
        args: [1n, SEAL_DELAY, confidentialWrapper.address], // 1 slot -> closes on the first deposit
        force: true,
      });

      const { handle, inputProof } = await encryptRecipient(
        fhevm.instance, wrapper.address, alice.account.address, alice.account.address,
      );
      await send(wrapper.write.recordTransientAmountDeposit([
        AMOUNT,
        handle,
        inputProof
      ], fheTxOpts(alice.account)));
      expect(await wrapper.read.batchClosed([0n])).toBe(true);

      // A LATER transaction. The deposit-time transient grant is long gone, so this only works if
      // the hook persisted access.
      await send(wrapper.write.finalizeWrap([[0n], alice.account.address], fheTxOpts(alice.account)));
      // The finalize recorded a claim for alice (its encrypted amount handle is now set), which it
      // could only compute if the hook had persisted ACL access to eAmount.
      expect(await wrapper.read.claimedAmount([0n, alice.account.address])).not.toBe(zeroHash);
    });

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
      expect(await wrapper.read.totalDeposits()).toBe(1n);
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

      // Non-multiples are rounded down by the configured wrapper. The adapter
      // records the amount wrapped, not the requested amount.
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

    // An event-only indexer replays logs in order, so a BatchSealed ahead of the deposit that
    // caused it reads as "batch closed with one fewer deposit than it holds".
    it("emits WrapInitiated before BatchSealed on the deposit that fills the batch", async () => {
      const {
        wallets, deployWrapper, fundAndApprove, initWrap
      } = await boot();
      const { alice } = wallets;
      const { contract: wrapper } = await deployWrapper(2n);

      await fundAndApprove(wrapper, alice, 2n);
      await initWrap(wrapper, alice, alice.account.address);
      const receipt = await initWrap(wrapper, alice, alice.account.address); // fills the batch

      const ordered = receipt.logs
        .filter((log) => log.address.toLowerCase() === wrapper.address.toLowerCase())
        .map((log) => {
          try {
            return decodeEventLog({
              abi: wrapper.abi,
              data: log.data,
              topics: log.topics
            }).eventName;
          } catch {
            return undefined;
          }
        })
        .filter((name) => name === "WrapInitiated" || name === "BatchSealed");

      expect(ordered).toEqual(["WrapInitiated", "BatchSealed"]);
    });

    // Which batch a deposit joins is decided at execution, so anyone can fill the remaining slots
    // ahead of a pending initWrap and push it into a fresh batch they then fill around it.
    it("initWrapInto lands in the inspected batch or reverts without moving funds", async () => {
      const {
        wallets, underlying, deployWrapper, fundAndApprove, initWrap, fhevm, send
      } = await boot();
      const { alice, bob } = wallets;
      const { contract: wrapper } = await deployWrapper(2n);
      await fundAndApprove(wrapper, alice, 1n);
      await fundAndApprove(wrapper, bob, 2n);

      // Alice inspects batch 0, but bob fills it first and it rolls over.
      await initWrap(wrapper, bob, bob.account.address);
      await initWrap(wrapper, bob, bob.account.address);
      expect(await wrapper.read.currentBatchId()).toBe(1n);

      const balanceBefore = await underlying.read.balanceOf([alice.account.address]);
      const { handle, inputProof } = await encryptRecipient(
        fhevm.instance, wrapper.address, alice.account.address, alice.account.address,
      );
      await assertRevertsWith(
        wrapper.write.initWrapInto([0n, AMOUNT, handle, inputProof], txOpts(alice.account)),
        "NotCurrentBatch",
      );
      expect(await underlying.read.balanceOf([alice.account.address])).toBe(balanceBefore);

      // Pinning the batch she can join works normally.
      await send(wrapper.write.initWrapInto([1n, AMOUNT, handle, inputProof], fheTxOpts(alice.account)));
      expect(await wrapper.read.batchFillCount([1n])).toBe(1n);
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
