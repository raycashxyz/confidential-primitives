/**
 * Shared harness + `boot()` factory for the ConfidentialSealedBidAuction suites (split across
 * sibling *.mock.test.ts files so vitest runs them on separate workers). Each test file calls
 * `useAuctionSuite()` at the top level.
 *
 * The default auction is deployed lazily on first use via `getAuction()`, so constructor /
 * cap tests (which only call `deployAuction`) skip the deploy entirely. It is NOT baked into
 * the snapshot baseline: unlike the plain-ERC20 MockUSDC, an FHE contract's constructor
 * ciphertexts + ACL don't survive a loadState restore for later FHE ops, so FHE contracts
 * must be (re)deployed per test. `deployAuction` (force:true) covers custom-param cases —
 * the chain rolls back each test but deployoor's store does not.
 */
import { beforeAll, beforeEach } from "vitest";
import { parseEventLogs } from "viem";

import { createHarness } from "../../setup/harness";
import type { Harness } from "../../setup/harness";
import type { WalletWithAccount } from "../../setup/environment";
import { encryptValues, publicDecryptEuint } from "../../setup/fhe";
import { fheTxOpts } from "../../setup/tx";
import { getOrDeployConfidentialSealedBidAuction } from "../../../src/deployers/ConfidentialSealedBidAuction";

export const ZERO_ADDRESS = "0x0000000000000000000000000000000000000000";
export const BIDDING_DURATION = 1000n;
export const MAX_BIDDERS = 8n;

type AuctionContract = Awaited<ReturnType<typeof getOrDeployConfidentialSealedBidAuction>>["contract"];

/** Register the per-file harness (once per file) and return the `boot()` helper factory. */
export function useAuctionSuite () {
  let H: Harness;

  beforeAll(async () => {
    H = await createHarness();
  });

  beforeEach(() => H.reset());

  return async function boot () {
    const {
      publicClient, wallets, store, fhevm, warpTime
    } = H;
    const { deployer } = wallets;

    // FHE calls (fheTxOpts) carry an explicit gas limit, so viem skips simulation and an
    // on-chain revert lands as a receipt instead of a throw — check status so a failed
    // bid/reveal/settle surfaces immediately rather than corrupting later assertions.
    const send = async (p: Promise<`0x${string}`>) => {
      const receipt = await publicClient.waitForTransactionReceipt({ hash: await p });
      if (receipt.status !== "success") throw new Error(`tx reverted: ${receipt.transactionHash}`);
      return receipt;
    };

    // Deploy an auction with custom parameters (constructor-validation / cap tests). force:true
    // because the chain rolls back each test but deployoor's store does not.
    const deployAuction = (
      beneficiary: `0x${string}`,
      duration: bigint,
      maxBidders: bigint,
      force = true,
    ) =>
      getOrDeployConfidentialSealedBidAuction({
        walletClient: deployer,
        publicClient,
        store,
        args: [
          beneficiary,
          duration,
          maxBidders
        ],
        force,
      });

    // The default auction, deployed lazily + memoized on first use within a test. Constructor /
    // cap tests never touch it (they use `deployAuction` directly), so they skip the deploy.
    let _auction: AuctionContract | undefined;
    const getAuction = async (): Promise<AuctionContract> => {
      if (!_auction) {
        ({ contract: _auction } = await deployAuction(deployer.account.address, BIDDING_DURATION, MAX_BIDDERS));
      }
      return _auction;
    };

    const encryptBidFor = async (target: AuctionContract, bidder: WalletWithAccount, value: bigint) => {
      const [handle, inputProof] = await encryptValues(
        fhevm.instance,
        [{
          type: "add64",
          value
        }],
        target.address,
        bidder.account.address,
      );
      return {
        handle,
        inputProof
      };
    };

    const encryptBid = async (bidder: WalletWithAccount, value: bigint) => encryptBidFor(await getAuction(), bidder, value);

    const bidOn = async (target: AuctionContract, bidder: WalletWithAccount, value: bigint) => {
      const { handle, inputProof } = await encryptBidFor(target, bidder, value);
      return send(target.write.bid([handle, inputProof], fheTxOpts(bidder.account)));
    };

    const placeBid = async (bidder: WalletWithAccount, value: bigint) => bidOn(await getAuction(), bidder, value);

    // reveal() then settle() — returns the KMS-decrypted clearing price.
    const revealAndSettle = async (caller: WalletWithAccount): Promise<bigint> => {
      const auction = await getAuction();
      const revealReceipt = await send(auction.write.reveal(fheTxOpts(caller.account)));
      const [revealEvent] = parseEventLogs({
        abi: auction.abi,
        logs: revealReceipt.logs,
        eventName: "MaxBidRevealRequested"
      });
      if (!revealEvent) throw new Error("expected a MaxBidRevealRequested event");
      const { cleartext, decryptionProof } = await publicDecryptEuint(fhevm.instance, revealEvent.args.handle);
      await send(auction.write.settle([cleartext, decryptionProof], fheTxOpts(caller.account)));
      return cleartext;
    };

    // claim() then decrypt the 1/0 win flag WITHOUT finalizing — tests inspect the flag
    // and choose how to finalize.
    const claimFlag = async (bidder: WalletWithAccount): Promise<{ flag: bigint; proof: `0x${string}` }> => {
      const auction = await getAuction();
      const claimReceipt = await send(auction.write.claim(fheTxOpts(bidder.account)));
      const [claimEvent] = parseEventLogs({
        abi: auction.abi,
        logs: claimReceipt.logs,
        eventName: "ClaimRequested"
      });
      if (!claimEvent) throw new Error("expected a ClaimRequested event");
      const { cleartext, decryptionProof } = await publicDecryptEuint(fhevm.instance, claimEvent.args.handle);
      return {
        flag: cleartext,
        proof: decryptionProof
      };
    };

    return {
      wallets, fhevm, getAuction, send, warpTime, deployAuction, encryptBid, encryptBidFor, bidOn, placeBid, revealAndSettle, claimFlag
    };
  };
}
