// SPDX-License-Identifier: MIT
pragma solidity ^0.8.27;

import {FHE, euint64, ebool, externalEuint64} from "@fhevm/solidity/lib/FHE.sol";
import {ZamaEthereumConfig} from "@fhevm/solidity/config/ZamaConfig.sol";

/**
 * @title ConfidentialSealedBidAuction
 * @notice A first-price sealed-bid auction where every bid stays encrypted and only
 *         the winning price is ever revealed. Losing bids are never decrypted.
 *
 *         This is the protocol shape fhEVM is strongest at (vs a ZK stack): the
 *         interesting computation — find the highest bid — happens ON ciphertext, and
 *         the decryption oracle reveals EXACTLY ONE value, the clearing price, with a
 *         threshold-KMS proof. No ZK circuits, no trusted auctioneer, and no
 *         commit-reveal griefing (a sealed bid cannot be withheld at reveal time).
 *
 *         Lifecycle:
 *           1. {bid}           — submit/replace an encrypted bid before `biddingEnd`.
 *           2. {reveal}        — after close, homomorphically reduce all bids to the
 *                                max (tree-reduced, O(log N) FHE depth) and mark it
 *                                publicly decryptable.
 *           3. {settle}        — feed back the KMS-decrypted clearing price + proof.
 *           4. {claim}         — a bidder proves winnership homomorphically:
 *                                eq(myBid, clearingPrice) → publicly decryptable 1/0.
 *           5. {finalizeClaim} — feed back that flag + proof; a 1 records the winner.
 *
 *         Every decryption is a euint64 through the same public-decrypt path the
 *         wrappers' finalizeUnwrap uses — no bespoke eaddress reveal flow.
 *
 *         Proof binding: each bid's `inputProof` is EIP-712 bound to `msg.sender`, so
 *         bids cannot be copied or replayed by another account.
 *
 *         Scope: this reference implementation records the winner and price and emits
 *         them; production would escrow bid bonds and pull `clearingPrice` from the
 *         winner to `beneficiary` on finalize. Ties resolve first-come: whichever tied
 *         top bidder finalizes their claim first wins.
 */
contract ConfidentialSealedBidAuction is ZamaEthereumConfig {
    /// @dev Hard cap on `maxBidders`, keeping the one-shot {reveal} provably completable:
    ///      the max-tree does N-1 FHE.max ops (~180k HCU each, depth ceil(log2 N)), so 64
    ///      bidders costs ~11.3M of the 20M total-HCU budget at depth ~1.1M — comfortable
    ///      headroom. An unbounded set would let a Sybil push reveal past the per-tx
    ///      budget and permanently block settlement.
    uint256 private constant MAX_BIDDERS_LIMIT = 64;

    /// @notice Auction proceeds recipient (informational in this reference impl).
    address public immutable beneficiary;

    /// @notice Bids submitted at or after this timestamp are rejected.
    uint256 public immutable biddingEnd;

    /// @notice Maximum number of distinct bidders admitted (bounds the reveal scan).
    uint256 public immutable maxBidders;

    /// @notice Distinct bidders, in first-bid order — the reduction set for {reveal}.
    address[] public bidders;
    mapping(address bidder => bool) public hasBid;
    mapping(address bidder => euint64) private _bids;

    /// @notice Handle of the encrypted max bid, set by {reveal}, decrypted by {settle}.
    euint64 private _pendingMaxBid;
    /// @notice Per-bidder encrypted "did I win" flag (1/0), set by {claim}. A euint64
    ///         rather than an ebool so the reveal stays on the numeric decrypt path.
    mapping(address bidder => euint64) private _pendingClaim;

    bool public revealed;
    bool public settled;
    uint64 public clearingPrice;
    address public winner;

    event BidSubmitted(address indexed bidder, bytes32 handle);
    event MaxBidRevealRequested(bytes32 handle);
    event Settled(uint64 clearingPrice);
    event ClaimRequested(address indexed bidder, bytes32 handle);
    event AuctionWon(address indexed winner, uint64 clearingPrice);

    error ZeroAddress();
    error InvalidMaxBidders();
    error TooManyBidders();
    error BiddingClosed();
    error BiddingStillOpen();
    error NoBids();
    error AlreadyRevealed();
    error NotRevealed();
    error AlreadySettled();
    error NotSettled();
    error AlreadyWon();
    error NotABidder();
    error NotWinner();

    constructor(address _beneficiary, uint256 _biddingDuration, uint256 _maxBidders) {
        if (_beneficiary == address(0)) revert ZeroAddress();
        if (_maxBidders == 0 || _maxBidders > MAX_BIDDERS_LIMIT) revert InvalidMaxBidders();
        beneficiary = _beneficiary;
        biddingEnd = block.timestamp + _biddingDuration;
        maxBidders = _maxBidders;
    }

    // -----------------------------------------------------------------------
    // 1. bid — submit or replace an encrypted bid
    // -----------------------------------------------------------------------

    /**
     * @notice Submit (or overwrite) `msg.sender`'s sealed bid. `inputProof` must be
     *         EIP-712 bound to `(this, msg.sender)`.
     */
    function bid(externalEuint64 encryptedBid, bytes calldata inputProof) external {
        if (block.timestamp >= biddingEnd) revert BiddingClosed();
        if (revealed) revert AlreadyRevealed();

        euint64 b = FHE.fromExternal(encryptedBid, inputProof);
        FHE.allowThis(b);
        // Grant the bidder persistent decrypt rights on their own stored bid: allowThis
        // only authorizes the CONTRACT to compute on the handle; without this explicit
        // grant, userDecrypt of the handle returned by {bidHandleOf} would be rejected
        // by the ACL. (Input-proof binding authorizes submission, not decryption.)
        FHE.allow(b, msg.sender);
        _bids[msg.sender] = b;

        if (!hasBid[msg.sender]) {
            if (bidders.length >= maxBidders) revert TooManyBidders();
            hasBid[msg.sender] = true;
            bidders.push(msg.sender);
        }

        emit BidSubmitted(msg.sender, FHE.toBytes32(b));
    }

    // -----------------------------------------------------------------------
    // 2. reveal — homomorphic max over all bids, then request decryption
    // -----------------------------------------------------------------------

    /**
     * @notice After close, reduce all bids to their max and mark it publicly
     *         decryptable. Permissionless. The tree reduction keeps FHE dependency
     *         depth at ceil(log2 N), so bidder count is bounded by the per-tx total
     *         HCU budget rather than a serial compare chain.
     */
    function reveal() external {
        if (block.timestamp < biddingEnd) revert BiddingStillOpen();
        if (revealed) revert AlreadyRevealed();
        uint256 n = bidders.length;
        if (n == 0) revert NoBids();

        euint64[] memory vals = new euint64[](n);
        for (uint256 i = 0; i < n; i++) {
            vals[i] = _bids[bidders[i]];
        }
        euint64 maxBid = _maxTree(vals);

        FHE.makePubliclyDecryptable(maxBid);
        _pendingMaxBid = maxBid;
        revealed = true;

        emit MaxBidRevealRequested(FHE.toBytes32(maxBid));
    }

    // -----------------------------------------------------------------------
    // 3. settle — record the KMS-decrypted clearing price
    // -----------------------------------------------------------------------

    /**
     * @notice Verify the KMS decryption of the max bid and record it as the cleartext
     *         clearing price. Anyone can relay this.
     */
    function settle(uint64 price, bytes calldata decryptionProof) external {
        if (!revealed) revert NotRevealed();
        if (settled) revert AlreadySettled();

        bytes32[] memory handles = new bytes32[](1);
        handles[0] = euint64.unwrap(_pendingMaxBid);
        FHE.checkSignatures(handles, abi.encode(price), decryptionProof);

        clearingPrice = price;
        settled = true;

        emit Settled(price);
    }

    // -----------------------------------------------------------------------
    // 4/5. claim + finalizeClaim — prove winnership, losing bids stay sealed
    // -----------------------------------------------------------------------

    /**
     * @notice A bidder asks the contract to compute, homomorphically, whether their own
     *         bid equals the (now public) clearing price, and marks the resulting 1/0
     *         flag publicly decryptable. Losing bids themselves are never decrypted.
     */
    function claim() external {
        if (!settled) revert NotSettled();
        if (winner != address(0)) revert AlreadyWon();
        if (!hasBid[msg.sender]) revert NotABidder();

        ebool isTop = FHE.eq(_bids[msg.sender], clearingPrice);
        euint64 wonFlag = FHE.select(isTop, FHE.asEuint64(1), FHE.asEuint64(0));
        FHE.makePubliclyDecryptable(wonFlag);
        _pendingClaim[msg.sender] = wonFlag;

        emit ClaimRequested(msg.sender, FHE.toBytes32(wonFlag));
    }

    /**
     * @notice Verify the KMS decryption of a claim flag (1 = won). A 1 records the
     *         winner (first tied claimant to finalize wins); a 0 reverts.
     */
    function finalizeClaim(uint64 wonFlag, bytes calldata decryptionProof) external {
        if (!settled) revert NotSettled();
        if (winner != address(0)) revert AlreadyWon();

        bytes32[] memory handles = new bytes32[](1);
        handles[0] = euint64.unwrap(_pendingClaim[msg.sender]);
        FHE.checkSignatures(handles, abi.encode(wonFlag), decryptionProof);

        if (wonFlag == 0) revert NotWinner();
        winner = msg.sender;

        emit AuctionWon(msg.sender, clearingPrice);
    }

    // -----------------------------------------------------------------------
    // Views
    // -----------------------------------------------------------------------

    function bidderCount() external view returns (uint256) {
        return bidders.length;
    }

    /// @notice Encrypted bid handle for `bidder` (bytes32). Only `bidder` can decrypt it.
    function bidHandleOf(address bidder) external view returns (bytes32) {
        return FHE.toBytes32(_bids[bidder]);
    }

    // -----------------------------------------------------------------------
    // _maxTree: pairwise (tree) reduction — O(log N) FHE dependency depth
    // -----------------------------------------------------------------------

    /**
     * @dev Reduce `xs` to its max by pairwise {FHE.max}, halving the array in place each
     *      round: xs[i] = max(xs[2i], xs[2i+1]) for i < ceil(n/2), an odd tail carried
     *      through unchanged. Same shape as BatchedAsyncWrapperV2._sumTree (see its
     *      NatSpec for the full mechanics): total ops stay N-1, but FHEVM meters
     *      SEQUENTIAL DEPTH per tx (depth(result) = opHCU + max(depth of inputs), cap
     *      5M), and the tree bounds any value's chain to one `max` per round — depth
     *      ceil(log2 N) instead of N for a serial scan. That is what lets the bidder
     *      count grow to the total-HCU budget rather than a ~30-bid depth ceiling.
     */
    function _maxTree(euint64[] memory xs) private returns (euint64) {
        uint256 n = xs.length;
        while (n > 1) {
            uint256 half = (n + 1) >> 1;
            for (uint256 i = 0; i < half; i++) {
                uint256 l = i << 1;
                uint256 r = l + 1;
                xs[i] = r < n ? FHE.max(xs[l], xs[r]) : xs[l];
            }
            n = half;
        }
        return xs[0];
    }
}
