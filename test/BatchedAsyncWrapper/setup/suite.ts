/**
 * Shared harness + `boot()` factory for the BatchedAsyncWrapper suites (split across sibling
 * *.mock.test.ts files so vitest runs them on separate workers). Each test file in this folder
 * calls `useBatchedSuite()` at the top level; it registers the per-file `beforeAll`/`beforeEach`
 * (one FHEVM env + MockUSDC, snapshotted then restored each test) and returns the bound `boot()`.
 */
import { beforeAll, beforeEach } from "vitest";
import { zeroHash } from "viem";

import { createHarness } from "../../setup/harness";
import type { Harness } from "../../setup/harness";
import type { WalletWithAccount } from "../../setup/environment";
import { encryptRecipient, decryptEuint } from "../../setup/fhe";
import { txOpts, fheTxOpts } from "../../setup/tx";
import { getOrDeployMockUSDC } from "../../../src/deployers/MockUSDC";
import { getOrDeployBatchedAsyncWrapper } from "../../../src/deployers/BatchedAsyncWrapper";

export const AMOUNT = 100n;

export type WrapperContract = Awaited<ReturnType<typeof getOrDeployBatchedAsyncWrapper>>["contract"];
type MockUSDCContract = Awaited<ReturnType<typeof getOrDeployMockUSDC>>["contract"];

/** Register the per-file harness (once per file) and return the `boot()` helper factory. */
export function useBatchedSuite () {
  let H: Harness;
  let underlying: MockUSDCContract;

  beforeAll(async () => {
    H = await createHarness(async (env) => {
      const { contract } = await getOrDeployMockUSDC({
        walletClient: env.wallets.deployer,
        publicClient: env.publicClient,
        store: env.store,
        args: [6]
      });
      underlying = contract;
    });
  });

  beforeEach(() => H.reset());

  // Bind the per-test helpers over the shared, freshly-reset harness. Wrappers deploy with
  // `force: true` because the chain rolls back each test but deployoor's store does not.
  return async function boot () {
    const {
      publicClient, wallets, store, fhevm
    } = H;
    const { deployer } = wallets;

    const send = async (p: Promise<`0x${string}`>) => {
      const receipt = await publicClient.waitForTransactionReceipt({ hash: await p });
      if (receipt.status !== "success") throw new Error(`tx reverted: ${receipt.transactionHash}`);
      return receipt;
    };

    const deployWrapper = (maxBatch: bigint, force = true) =>
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
      wallets, underlying, send, deployWrapper, fundAndApprove, initWrap, decryptBalance
    };
  };
}
