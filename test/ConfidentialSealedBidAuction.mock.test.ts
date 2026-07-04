/**
 * Functional correctness for ConfidentialSealedBidAuction. The privacy property under test:
 * bids stay encrypted end-to-end; ONLY the winning (clearing) price is ever decrypted — the
 * homomorphic max is tree-reduced on ciphertext and revealed through the KMS public-decrypt
 * path, a winner proves winnership via eq(bid, price), and a loser's flag decrypts to 0
 * without their bid ever being opened. Plus phase guards (bid after close, reveal before
 * close, settle before reveal).
 */
import {
  describe, it, expect
} from "vitest";
import { parseEventLogs } from "viem";

import { createTestEnvironment } from "./setup/environment";
import type { WalletWithAccount } from "./setup/environment";
import { encryptValues, publicDecryptEuint } from "./setup/fhe";
import { txOpts, fheTxOpts } from "./setup/tx";
import { assertRevertsWith } from "./setup/asserts";
import { getOrDeployConfidentialSealedBidAuction } from "../src/deployers/ConfidentialSealedBidAuction";

const ZERO_ADDRESS = "0x0000000000000000000000000000000000000000";
const BIDDING_DURATION = 1000n;

type AuctionContract = Awaited<ReturnType<typeof getOrDeployConfidentialSealedBidAuction>>["contract"];

async function boot () {
  const env = await createTestEnvironment();
  const {
    publicClient, wallets, store, fhevm, warpTime
  } = env;
  const { deployer } = wallets;

  const send = async (p: Promise<`0x${string}`>) => publicClient.waitForTransactionReceipt({ hash: await p });

  const { contract: auction } = await getOrDeployConfidentialSealedBidAuction({
    walletClient: deployer,
    publicClient,
    store,
    args: [deployer.account.address, BIDDING_DURATION],
  });

  const encryptBid = async (bidder: WalletWithAccount, value: bigint) => {
    const [handle, inputProof] = await encryptValues(
      fhevm.instance,
      [{
        type: "add64",
        value
      }],
      auction.address,
      bidder.account.address,
    );
    return {
      handle,
      inputProof
    };
  };

  const placeBid = async (bidder: WalletWithAccount, value: bigint) => {
    const { handle, inputProof } = await encryptBid(bidder, value);
    return send(auction.write.bid([handle, inputProof], fheTxOpts(bidder.account)));
  };

  // reveal() then settle() — returns the KMS-decrypted clearing price.
  const revealAndSettle = async (caller: WalletWithAccount): Promise<bigint> => {
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
    wallets, auction, send, warpTime, encryptBid, placeBid, revealAndSettle, claimFlag
  };
}

describe("ConfidentialSealedBidAuction", () => {

  describe("bidding phase", () => {
    it("records distinct bidders and rejects bids after close", async () => {
      const {
        wallets, auction, warpTime, encryptBid, placeBid
      } = await boot();

      await placeBid(wallets.alice, 100n);
      await placeBid(wallets.bob, 250n);
      expect(await auction.read.bidderCount()).toBe(2n);

      await warpTime(BIDDING_DURATION + 1n);
      const late = await encryptBid(wallets.carol, 300n);
      await assertRevertsWith(
        auction.write.bid([late.handle, late.inputProof], txOpts(wallets.carol.account)),
        "BiddingClosed",
      );
    });

    it("reverts reveal while bidding is still open", async () => {
      const { wallets, auction, placeBid } = await boot();
      await placeBid(wallets.alice, 100n);

      await assertRevertsWith(
        auction.write.reveal(txOpts(wallets.alice.account)),
        "BiddingStillOpen",
      );
    });
  });

  describe("reveal + settle", () => {
    it("reveals only the highest bid as the clearing price", async () => {
      const {
        wallets, auction, warpTime, placeBid, revealAndSettle
      } = await boot();

      await placeBid(wallets.alice, 100n);
      await placeBid(wallets.bob, 250n); // highest
      await placeBid(wallets.carol, 175n);

      await warpTime(BIDDING_DURATION + 1n);
      const clearingPrice = await revealAndSettle(wallets.deployer);

      expect(clearingPrice).toBe(250n);
      expect(await auction.read.clearingPrice()).toBe(250n);
      expect(await auction.read.settled()).toBe(true);
    });

    it("reverts settle before reveal", async () => {
      const {
        wallets, auction, warpTime, placeBid
      } = await boot();
      await placeBid(wallets.alice, 100n);
      await warpTime(BIDDING_DURATION + 1n);

      await assertRevertsWith(
        auction.write.settle([100n, "0x"], txOpts(wallets.alice.account)),
        "NotRevealed",
      );
    });
  });

  describe("claim", () => {
    it("lets the top bidder prove winnership and rejects a loser's claim", async () => {
      const {
        wallets, auction, send, warpTime, placeBid, revealAndSettle, claimFlag
      } = await boot();

      await placeBid(wallets.alice, 100n);
      await placeBid(wallets.bob, 250n); // winner
      await placeBid(wallets.carol, 175n);

      await warpTime(BIDDING_DURATION + 1n);
      await revealAndSettle(wallets.deployer);

      // Loser: eq(bid, price) flag decrypts to 0 -> finalizeClaim reverts, winner unset,
      // and carol's actual bid value was never decrypted.
      const carol = await claimFlag(wallets.carol);
      expect(carol.flag).toBe(0n);
      await assertRevertsWith(
        auction.write.finalizeClaim([carol.flag, carol.proof], txOpts(wallets.carol.account)),
        "NotWinner",
      );
      expect(await auction.read.winner()).toBe(ZERO_ADDRESS);

      // Winner: flag decrypts to 1 -> winner recorded at the clearing price.
      const bob = await claimFlag(wallets.bob);
      expect(bob.flag).toBe(1n);
      await send(auction.write.finalizeClaim([bob.flag, bob.proof], fheTxOpts(wallets.bob.account)));
      expect(await auction.read.winner()).toBe(wallets.bob.account.address);
      expect(await auction.read.clearingPrice()).toBe(250n);
    });
  });
});
