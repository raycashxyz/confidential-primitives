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
import { encryptValues, publicDecryptEuint, decryptEuint } from "./setup/fhe";
import { txOpts, fheTxOpts } from "./setup/tx";
import { assertRevertsWith } from "./setup/asserts";
import { getOrDeployConfidentialSealedBidAuction } from "../src/deployers/ConfidentialSealedBidAuction";

const ZERO_ADDRESS = "0x0000000000000000000000000000000000000000";
const BIDDING_DURATION = 1000n;
const MAX_BIDDERS = 8n;

type AuctionContract = Awaited<ReturnType<typeof getOrDeployConfidentialSealedBidAuction>>["contract"];

async function boot () {
  const env = await createTestEnvironment();
  const {
    publicClient, wallets, store, fhevm, warpTime
  } = env;
  const { deployer } = wallets;

  // FHE calls (fheTxOpts) carry an explicit gas limit, so viem skips simulation and an
  // on-chain revert lands as a receipt instead of a throw — check status so a failed
  // bid/reveal/settle surfaces immediately rather than corrupting later assertions.
  const send = async (p: Promise<`0x${string}`>) => {
    const receipt = await publicClient.waitForTransactionReceipt({ hash: await p });
    if (receipt.status !== "success") throw new Error(`tx reverted: ${receipt.transactionHash}`);
    return receipt;
  };

  // Deploy an auction with custom parameters (constructor-validation / cap tests).
  const deployAuction = (
    beneficiary: `0x${string}`,
    duration: bigint,
    maxBidders: bigint,
    force = false,
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

  const { contract: auction } = await deployAuction(deployer.account.address, BIDDING_DURATION, MAX_BIDDERS);

  type AuctionContract = typeof auction;

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

  const encryptBid = (bidder: WalletWithAccount, value: bigint) => encryptBidFor(auction, bidder, value);

  const bidOn = async (target: AuctionContract, bidder: WalletWithAccount, value: bigint) => {
    const { handle, inputProof } = await encryptBidFor(target, bidder, value);
    return send(target.write.bid([handle, inputProof], fheTxOpts(bidder.account)));
  };

  const placeBid = (bidder: WalletWithAccount, value: bigint) => bidOn(auction, bidder, value);

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
    wallets, fhevm, auction, send, warpTime, deployAuction, encryptBid, encryptBidFor, bidOn, placeBid, revealAndSettle, claimFlag
  };
}

describe("ConfidentialSealedBidAuction", () => {

  describe("constructor", () => {
    it("reverts on a zero beneficiary", async () => {
      const { deployAuction } = await boot();
      await assertRevertsWith(
        deployAuction(ZERO_ADDRESS, BIDDING_DURATION, MAX_BIDDERS, true),
        "ZeroAddress",
      );
    });

    it("reverts on a zero or above-limit bidder cap", async () => {
      const { wallets, deployAuction } = await boot();
      const beneficiary = wallets.deployer.account.address;
      await assertRevertsWith(deployAuction(beneficiary, BIDDING_DURATION, 0n, true), "InvalidMaxBidders");
      await assertRevertsWith(deployAuction(beneficiary, BIDDING_DURATION, 65n, true), "InvalidMaxBidders");
    });

    it("reverts on a zero bidding duration (would brick the auction)", async () => {
      const { wallets, deployAuction } = await boot();
      await assertRevertsWith(
        deployAuction(wallets.deployer.account.address, 0n, MAX_BIDDERS, true),
        "InvalidBiddingDuration",
      );
    });
  });

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

    it("rejects a new bidder once the cap is reached (replacements still allowed)", async () => {
      const {
        wallets, deployAuction, bidOn, encryptBidFor
      } = await boot();
      const { contract: small } = await deployAuction(
        wallets.deployer.account.address, BIDDING_DURATION, 2n, true,
      );

      await bidOn(small, wallets.alice, 100n);
      await bidOn(small, wallets.bob, 200n);
      expect(await small.read.bidderCount()).toBe(2n);

      // A third distinct bidder is refused...
      const carol = await encryptBidFor(small, wallets.carol, 300n);
      await assertRevertsWith(
        small.write.bid([carol.handle, carol.inputProof], txOpts(wallets.carol.account)),
        "TooManyBidders",
      );
      // ...but an existing bidder can still replace their own bid.
      await bidOn(small, wallets.alice, 150n);
      expect(await small.read.bidderCount()).toBe(2n);
    });

    it("lets a bidder decrypt their own stored bid via bidHandleOf (ACL grant)", async () => {
      const {
        wallets, fhevm, auction, placeBid
      } = await boot();
      await placeBid(wallets.alice, 123n);

      const handle = await auction.read.bidHandleOf([wallets.alice.account.address]);
      const value = await decryptEuint(fhevm.instance, handle, auction.address, wallets.alice);
      expect(value).toBe(123n);
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

    it("reverts reveal with no bids", async () => {
      const { wallets, auction, warpTime } = await boot();
      await warpTime(BIDDING_DURATION + 1n);

      await assertRevertsWith(
        auction.write.reveal(txOpts(wallets.alice.account)),
        "NoBids",
      );
    });

    it("rejects a second reveal and a second settle", async () => {
      const {
        wallets, auction, warpTime, placeBid, revealAndSettle, claimFlag
      } = await boot();
      await placeBid(wallets.alice, 100n);
      await warpTime(BIDDING_DURATION + 1n);
      const price = await revealAndSettle(wallets.deployer);
      expect(price).toBe(100n);

      await assertRevertsWith(
        auction.write.reveal(txOpts(wallets.deployer.account)),
        "AlreadyRevealed",
      );
      // Reuse a fresh, valid KMS proof (the claim flag's) to prove the guard fires
      // before signature verification.
      const alice = await claimFlag(wallets.alice);
      await assertRevertsWith(
        auction.write.settle([alice.flag, alice.proof], txOpts(wallets.deployer.account)),
        "AlreadySettled",
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

    it("resolves a tie first-come: the first tied claimant to finalize wins", async () => {
      const {
        wallets, auction, send, warpTime, placeBid, revealAndSettle, claimFlag
      } = await boot();

      await placeBid(wallets.alice, 250n); // tied top
      await placeBid(wallets.bob, 250n); // tied top
      await placeBid(wallets.carol, 100n);

      await warpTime(BIDDING_DURATION + 1n);
      expect(await revealAndSettle(wallets.deployer)).toBe(250n);

      // Both tied bidders hold a winning flag.
      const alice = await claimFlag(wallets.alice);
      const bob = await claimFlag(wallets.bob);
      expect(alice.flag).toBe(1n);
      expect(bob.flag).toBe(1n);

      // Alice finalizes first and takes it; bob's valid proof now bounces off AlreadyWon.
      await send(auction.write.finalizeClaim([alice.flag, alice.proof], fheTxOpts(wallets.alice.account)));
      expect(await auction.read.winner()).toBe(wallets.alice.account.address);
      await assertRevertsWith(
        auction.write.finalizeClaim([bob.flag, bob.proof], txOpts(wallets.bob.account)),
        "AlreadyWon",
      );
    });
  });
});
