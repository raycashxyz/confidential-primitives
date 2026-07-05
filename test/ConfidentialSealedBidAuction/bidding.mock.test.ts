/**
 * ConfidentialSealedBidAuction — bidding phase: distinct-bidder tracking, the bidder cap,
 * phase guards, and a bidder decrypting their own stored bid. Shares setup/suite.
 */
import {
  describe, it, expect
} from "vitest";

import { useAuctionSuite, BIDDING_DURATION } from "./setup/suite";
import { decryptEuint } from "../setup/fhe";
import { txOpts } from "../setup/tx";
import { assertRevertsWith } from "../setup/asserts";

const boot = useAuctionSuite();

describe("ConfidentialSealedBidAuction bidding phase", () => {
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
