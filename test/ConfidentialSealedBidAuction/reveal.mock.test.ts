/**
 * ConfidentialSealedBidAuction — reveal + settle: only the highest bid becomes the clearing
 * price, plus the reveal/settle phase guards. Shares setup/suite.
 */
import {
  describe, it, expect
} from "vitest";

import { useAuctionSuite, BIDDING_DURATION } from "./setup/suite";
import { txOpts } from "../setup/tx";
import { assertRevertsWith } from "../setup/asserts";

const boot = useAuctionSuite();

describe("ConfidentialSealedBidAuction reveal + settle", () => {
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
