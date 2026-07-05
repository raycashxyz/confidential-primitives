/**
 * ConfidentialSealedBidAuction — claim: a winner proves winnership via eq(bid, price) while a
 * loser's flag decrypts to 0 without their bid ever opening; ties resolve first-come.
 * Shares setup/suite.
 */
import {
  describe, it, expect
} from "vitest";

import { useAuctionSuite, ZERO_ADDRESS, BIDDING_DURATION } from "./setup/suite";
import { txOpts, fheTxOpts } from "../setup/tx";
import { assertRevertsWith } from "../setup/asserts";

const boot = useAuctionSuite();

describe("ConfidentialSealedBidAuction claim", () => {
  it("lets the top bidder prove winnership and rejects a loser's claim", async () => {
    const {
      wallets, getAuction, send, warpTime, placeBid, revealAndSettle, claimFlag
    } = await boot();
    const auction = await getAuction();

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
      wallets, getAuction, send, warpTime, placeBid, revealAndSettle, claimFlag
    } = await boot();
    const auction = await getAuction();

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
