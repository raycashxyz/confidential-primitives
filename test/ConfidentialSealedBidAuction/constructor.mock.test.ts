/**
 * ConfidentialSealedBidAuction — constructor validation.
 * (bidding / reveal+settle / claim live in the sibling *.bidding / *.reveal / *.claim files
 * so vitest runs them on separate workers; all share the harness in setup/suite.)
 */
import {
  describe, it
} from "vitest";

import { useAuctionSuite, ZERO_ADDRESS, BIDDING_DURATION, MAX_BIDDERS } from "./setup/suite";
import { assertRevertsWith } from "../setup/asserts";

const boot = useAuctionSuite();

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

});
