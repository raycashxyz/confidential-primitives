/**
 * Shared harness + `boot()` factory for the BatchedAsyncWrapper suites.
 *
 * The batched wrapper tests are split across several *.mock.test.ts files so vitest can run them on
 * separate workers (see vitest.config.ts). Each file calls `useBatchedSuite()` at the top
 * level: it registers the per-file `beforeAll`/`beforeEach` (one FHEVM env + MockUSDC,
 * snapshotted then restored each test) and returns the bound `boot()` those tests already use.
 */
import { beforeAll, beforeEach } from "vitest";
import { zeroHash } from "viem";

import { createHarness } from "../../setup/harness";
import type { Harness } from "../../setup/harness";
import type { WalletWithAccount } from "../../setup/environment";
import { encryptRecipient, decryptEuint } from "../../setup/fhe";
import { txOpts, fheTxOpts } from "../../setup/tx";
import { getOrDeployMockUSDC } from "../../../src/deployers/MockUSDC";
import { getOrDeployMockERC7984ERC20Wrapper } from "../../../src/deployers/MockERC7984ERC20Wrapper";
import { getOrDeployBatchedAsyncWrapper } from "../../../src/deployers/BatchedAsyncWrapper";

export const AMOUNT = 100n;
export const SEAL_DELAY = 3600n; // 1h

export type WrapperContract = Awaited<ReturnType<typeof getOrDeployBatchedAsyncWrapper>>["contract"];
type MockUSDCContract = Awaited<ReturnType<typeof getOrDeployMockUSDC>>["contract"];
type ConfidentialWrapperContract = Awaited<ReturnType<typeof getOrDeployMockERC7984ERC20Wrapper>>["contract"];

/** Register the per-file harness (once per file) and return the `boot()` helper factory. */
export function useBatchedSuite () {
  // One environment per file: the FHEVM runtime + a shared MockUSDC are installed once and
  // snapshotted; `beforeEach` restores that snapshot in ~ms.
  let H: Harness;
  let underlying: MockUSDCContract;
  let confidentialWrapper: ConfidentialWrapperContract;

  beforeAll(async () => {
    H = await createHarness(async (env) => {
      const { contract } = await getOrDeployMockUSDC({
        walletClient: env.wallets.deployer,
        publicClient: env.publicClient,
        store: env.store,
        args: [6]
      });
      underlying = contract;
      const { contract: wrapperToken } = await getOrDeployMockERC7984ERC20Wrapper({
        walletClient: env.wallets.deployer,
        publicClient: env.publicClient,
        store: env.store,
        args: [
          underlying.address,
          "Confidential USDC",
          "cUSDC"
        ]
      });
      confidentialWrapper = wrapperToken;
    });
  });

  beforeEach(() => H.reset());

  // Bind the per-test helpers over the shared, freshly-reset harness. Wrappers deploy with
  // `force: true` because the chain rolls back each test but deployoor's store does not.
  return async function boot () {
    const {
      publicClient, wallets, store, fhevm, warpTime
    } = H;
    const { deployer } = wallets;

    // FHE calls (fheTxOpts) carry an explicit gas limit, so viem skips simulation and an
    // on-chain revert lands as a receipt instead of a throw — check status so a failed
    // deposit/finalize surfaces immediately rather than corrupting later assertions.
    const send = async (p: Promise<`0x${string}`>) => {
      const receipt = await publicClient.waitForTransactionReceipt({ hash: await p });
      if (receipt.status !== "success") throw new Error(`tx reverted: ${receipt.transactionHash}`);
      return receipt;
    };

    const deployWrapper = (maxBatch: bigint, sealDelay: bigint = SEAL_DELAY, force = true) =>
      getOrDeployBatchedAsyncWrapper({
        walletClient: deployer,
        publicClient,
        store,
        args: [
          maxBatch,
          sealDelay,
          confidentialWrapper.address
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
        AMOUNT,
        handle,
        inputProof
      ], fheTxOpts(depositor.account)));
    };

    const decryptBalance = async (owner: WalletWithAccount): Promise<bigint> => {
      const handle = await confidentialWrapper.read.confidentialBalanceOf([owner.account.address]);
      if (handle === zeroHash) return 0n;
      return decryptEuint(fhevm.instance, handle, confidentialWrapper.address, owner);
    };

    return {
      publicClient,
      wallets,
      store,
      fhevm,
      underlying,
      confidentialWrapper,
      send,
      warpTime,
      deployWrapper,
      fundAndApprove,
      initWrap,
      decryptBalance
    };
  };
}
