// SPDX-License-Identifier: MIT
pragma solidity ^0.8.27;

import {FHE, euint64, ebool, eaddress, externalEaddress} from "@fhevm/solidity/lib/FHE.sol";
import {IERC7984ERC20Wrapper} from "@openzeppelin/confidential-contracts/interfaces/IERC7984ERC20Wrapper.sol";
import {StealthWrapAdapter} from "./base/StealthWrapAdapter.sol";

/**
 * @title BatchedStealthWrapAdapter
 * @author Valerio Leo (@valeriohq)
 * @author Pavlos Polianidis (@ppoliani)
 * @notice Batch-based stealth wrap adapter with a cleartext per-(batch, recipient)
 *         nullifier and a tree-reduced payout sum.
 *
 *         Same privacy model as the other adapters: a deposit is SENDER-TRANSPARENT
 *         (depositor + cleartext amount are public) but RECIPIENT-PRIVATE (an
 *         `eaddress`). finalize scans whole batches, so the decoy set is the batch and
 *         the transferred sum stays encrypted — observers learn only "R finalized batch B".
 *
 *         THAT HOLDS AGAINST OBSERVERS, NOT AGAINST CO-DEPOSITORS. The batch hides a deposit only
 *         among slots the adversary cannot rule out. Someone who deposited into the same batch
 *         knows their own encrypted recipients, so they subtract those slots and what remains is
 *         the real anonymity set; own enough of a batch and it collapses to one. With
 *         `maxBatchDeposits` capped at 48 that is cheap to attempt, and {initWrapInto} only closes
 *         the displacement half of it. This is inherent to any fixed-size set an adversary can pay
 *         to fill — the mitigation is client-side, and it is practical here precisely because
 *         deposits are sender-transparent: inspect who is already in a batch, pin it, and judge
 *         whether the crowd is real.
 *
 *         The recipient is already public at finalize time
 *            (it is an address argument, emitted in {WrapFinalized}), so a plain
 *            `finalized[batchId][recipient]` bool leaks nothing the call does not
 *            already reveal.
 *
 *         The payout sum is tree-reduced via {_sumTree}. Pairwise reduction keeps the
 *         critical path to ceil(log2 N) adds, so {finalizeWrap} is bounded by the
 *         FHEVM total-HCU budget rather than a long serial add chain.
 *
 *         Tradeoff: the nullifier is all-or-nothing per (batch, recipient), so a batch
 *         must be CLOSED (full, or timeout-sealed via {sealBatch}) before finalizing —
 *         this freezes each recipient's matched set (no later top-ups into a finalized
 *         batch). Tail batches can close only after `sealDelay`: either explicitly via
 *         {sealBatch} or automatically on the first {finalizeWrap} attempt, so funds
 *         cannot stay stuck without allowing premature one-deposit batches.
 *
 *         Recipient handshake (how the depositor never learns the recipient): the
 *         RECIPIENT encrypts their own address off-chain with the input proof bound to
 *         the DEPOSITOR as userAddress, and hands (handle, proof) to the depositor,
 *         who submits it via {initWrap}. The recipient recognises their deposit by
 *         watching for their handle in {WrapInitiated}.
 *
 *         Like the other adapters: deposits are wrapped immediately into confidential
 *         balance owned by this contract, then transferred to recipients on finalize.
 */
contract BatchedStealthWrapAdapter is StealthWrapAdapter {
    /// @dev Hard cap on batch size, set so {finalizeWrap} over ONE batch is PROVABLY
    ///      completable — an unfinalizable batch would lock funds. finalize does a
    ///      fixed amount of FHE work per slot (`eq` + `select` + tree `add`), so its
    ///      binding limit is the FHEVM 20M TOTAL-HCU/tx budget: measured on the FHEVM
    ///      coprocessor mocks (which meter HCU via the HCULimit host contract),
    ///      56 slots fits and >=60 reverts; the analytic op-cost model agrees (~60).
    ///      48 leaves ~15-20% headroom.
    ///      NOTE the budget applies to TOTAL SLOTS SCANNED PER CALL: near the cap,
    ///      finalize one batch per call; multi-batch calls suit smaller batch sizes.
    ///
    ///      THAT HEADROOM COVERS THE ADAPTER'S OWN WORK ONLY. `_transferWrapped` calls into the
    ///      configured wrapper, and whatever its `_update` costs comes out of the SAME
    ///      per-transaction budget — a cost this constant cannot see, because the wrapper is a
    ///      constructor argument. An `ERC7984Hooked` wrapper carrying a few modules can add
    ///      millions of HCU for hook aggregation and pre/post-transfer work, which is enough to
    ///      push a full 48-slot scan over the limit.
    ///
    ///      Worse, that cost is not fixed at deployment: a hooked wrapper's admin can
    ///      `installModule` AFTER deposits are already escrowed, so a batch calibrated against a
    ///      clean wrapper can become unfinalizable later. `initWrap` keeps succeeding either way,
    ///      and the all-or-nothing nullifier means a batch cannot be scanned in parts to get under
    ///      the budget. The continuous adapter has the same exposure through `minDecoys`, which is
    ///      immutable and cannot be lowered in response.
    ///
    ///      So `maxBatchDeposits` must be sized against the TARGET WRAPPER's post-module transfer
    ///      cost, not against a bare-mock measurement, and this cap is a ceiling rather than a
    ///      recommendation. Prefer a wrapper whose FHE cost cannot change under you.
    uint256 private constant MAX_BATCH_LIMIT = 48;

    uint256 public immutable maxBatchDeposits;

    /// @notice Seconds after a batch's FIRST deposit before anyone may {sealBatch} it.
    /// @dev Anchored to the first deposit, not the last. A sliding timer measured from the last
    ///      deposit is resettable by anyone: while the batch still has free slots, a depositor can
    ///      submit the minimum wrappable amount just before the delay expires and push the deadline
    ///      out again, repeating for every remaining slot — stretching the worst-case wait to about
    ///      `(maxBatchDeposits - fillCount) * sealDelay`. Worse, {finalizeWrap} takes the cleartext
    ///      recipient in calldata, so an observer can watch for a pending finalization and target
    ///      that recipient specifically, filling the remaining slots with deposits it controls and
    ///      shrinking the effective anonymity set at the same time.
    ///
    ///      An absolute deadline gives every batch a fixed maximum lifetime that no one can extend.
    ///      The tradeoff is that a slowly-filling batch becomes sealable at a fixed age rather than
    ///      after a quiet period, so size `sealDelay` as "how long a batch is allowed to spend
    ///      gathering its anonymity set", not as "how long it must be idle".
    uint256 public immutable sealDelay;

    /// @notice Batch currently accepting deposits.
    uint256 public currentBatchId;

    /// @notice Total deposits recorded across all batches. This is the COUNT; use
    ///         {getDepositsLength} to enumerate, since slot indices are sparse.
    uint256 public totalDeposits;

    /// @notice Global slot index (batchId * maxBatchDeposits + batchIndex) => deposit.
    mapping(uint256 slot => Deposit) public deposits;

    mapping(uint256 batchId => Batch) private _batches;

    struct Batch {
        uint256 fillCount;
        bool closed;
        /// @dev Anchor for the seal deadline. Set once, by the batch's first deposit.
        uint64 firstDepositAt;
        /// @dev Informational only (batch activity for indexers); the seal deadline does not
        ///      depend on it — see {sealDelay}. Packs into the same slot as the two fields above.
        uint64 lastDepositAt;
        mapping(address recipient => bool) finalized;
    }

    struct Deposit {
        address depositor;
        uint256 amount; // cleartext — the transparent side of the mix
        euint64 eAmount;
        eaddress eRecipient;
    }

    event WrapInitiated(
        uint256 indexed batchId,
        uint256 indexed slot,
        address indexed depositor,
        uint256 amount,
        bytes32 eRecipient
    );
    event WrapFinalized(address indexed recipient, bytes32 amount, uint256[] ids);
    event BatchSealed(uint256 indexed batchId, uint256 filled);

    error InvalidBatchSize();
    error BatchNotClosed();
    error BatchAlreadyClosed();
    error NotCurrentBatch();
    error NothingToSeal();
    error SealDelayNotElapsed();
    error SealDelayTooShort();
    error AlreadyFinalized();

    constructor(
        uint256 _maxBatchDeposits,
        uint256 _sealDelay,
        IERC7984ERC20Wrapper confidentialWrapper_
    )
        StealthWrapAdapter(confidentialWrapper_)
    {
        if (_maxBatchDeposits == 0 || _maxBatchDeposits > MAX_BATCH_LIMIT) revert InvalidBatchSize();
        // sealBatch's griefer-resistance IS the delay: with sealDelay = 0 anyone could
        // seal every batch at fill count 1, collapsing the anonymity set to a single
        // deposit. Zero is rejected; choosing a meaningfully large delay (hours) is
        // still the deployer's responsibility, like maxBatchDeposits itself.
        if (_sealDelay == 0) revert SealDelayTooShort();
        maxBatchDeposits = _maxBatchDeposits;
        sealDelay = _sealDelay;
    }

    /**
     * @notice EXCLUSIVE upper bound for enumerating deposit slots, NOT the number of deposits
     *         (that is {totalDeposits}).
     * @dev Slots are sparse here: a batch sealed before it filled leaves its remaining slots empty
     *      for good, so with `maxBatchDeposits = 4` and one deposit in each of batches 0 and 1 the
     *      live slots are 0 and 4. This returns 5 — the exclusive bound — while {totalDeposits}
     *      returns 2. Enumerating `[0, totalDeposits)` would have missed the deposit at slot 4.
     */
    function getDepositsLength() external view override returns (uint256) {
        uint256 batchId = currentBatchId;
        return batchId * maxBatchDeposits + _batches[batchId].fillCount;
    }

    function batchFillCount(uint256 batchId) public view returns (uint256) {
        return _batches[batchId].fillCount;
    }

    function batchClosed(uint256 batchId) public view returns (bool) {
        return _batches[batchId].closed;
    }

    /// @notice When the batch's seal deadline is anchored (its first deposit). Zero if untouched.
    function batchFirstDepositAt(uint256 batchId) public view returns (uint64) {
        return _batches[batchId].firstDepositAt;
    }

    function batchLastDepositAt(uint256 batchId) public view returns (uint64) {
        return _batches[batchId].lastDepositAt;
    }

    function finalized(uint256 batchId, address recipient) public view returns (bool) {
        return _batches[batchId].finalized[recipient];
    }

    // -----------------------------------------------------------------------
    // initWrap: pull + wrap tokens into escrow, then record a write-once deposit.
    // The token pull is an external call, so re-entry into any state-changing
    // entrypoint (initWrap / finalizeWrap / sealBatch) is blocked by nonReentrant.
    // -----------------------------------------------------------------------

    /**
     * @notice Record a deposit into the current batch by pulling `amount` underlying
     *         from `msg.sender` (who must have approved this wrapper). `inputProof`
     *         must bind `eRecipient` to `(this, msg.sender)`.
     *
     *         Non-multiple amounts are rounded down through the configured wrapper's
     *         rate. The recorded amount is the underlying actually wrapped into escrow.
     * @return slot Global slot index of the new deposit.
     */
    function initWrap(
        uint256 amount,
        externalEaddress eRecipient,
        bytes calldata inputProof
    ) external virtual override nonReentrant returns (uint256 slot) {
        slot = _pullAndRecord(amount, eRecipient, inputProof);
    }

    /**
     * @notice {initWrap}, but only if the deposit lands in `expectedBatchId`; otherwise revert
     *         {NotCurrentBatch} without moving any funds.
     *
     * @dev Which batch a deposit joins is decided at execution, so a depositor who inspected a
     *      batch before submitting has no guarantee of joining it. Anyone can fill the remaining
     *      slots ahead of the transaction and push it into a fresh, empty batch — which is the
     *      first half of a sandwich: displace the victim into a batch the attacker then fills with
     *      deposits of its own, and at finalize the attacker excludes the slots it knows are not
     *      the recipient's, leaving the victim's deposit identifiable. Pinning turns that into a
     *      revert, so the depositor keeps their funds and can reassess.
     *
     *      THIS DOES NOT MAKE THE BATCH SAFE. It fixes displacement only; nothing stops an attacker
     *      from co-depositing into the batch you pinned. An anonymity set is only as good as the
     *      share of it you do not control, and with `maxBatchDeposits` at most 48 it is cheap to
     *      own most of one. What helps is that this adapter is SENDER-TRANSPARENT: depositor and
     *      amount are cleartext in {WrapInitiated}, so a batch dominated by freshly funded
     *      addresses is visible BEFORE you join it. Pin the batch you actually inspected, and treat
     *      "who else is in here" as a decision the client must make, not one the contract makes.
     */
    function initWrapInto(
        uint256 expectedBatchId,
        uint256 amount,
        externalEaddress eRecipient,
        bytes calldata inputProof
    ) external nonReentrant returns (uint256 slot) {
        if (currentBatchId != expectedBatchId) revert NotCurrentBatch();
        slot = _pullAndRecord(amount, eRecipient, inputProof);
    }

    /// @dev Shared body of the two deposit entry points. Callers must be `nonReentrant`: the token
    ///      pull and wrap are external calls made before the deposit is recorded.
    function _pullAndRecord(
        uint256 amount,
        externalEaddress eRecipient,
        bytes calldata inputProof
    ) private returns (uint256 slot) {
        eaddress verifiedRecipient = _verifyRecipient(eRecipient, inputProof);
        (uint256 wrappedUnderlying, euint64 eAmount) = _wrapIntoEscrow(msg.sender, amount);
        slot = _recordBatchedDeposit(msg.sender, wrappedUnderlying, eAmount, verifiedRecipient);
    }

    /**
     * @dev Record an already-wrapped deposit in the current batch.
     *
     *      Kept separate from token acquisition so derived adapters can source deposits
     *      differently while preserving this adapter's batch selection, close, and
     *      accounting semantics. Callers that acquire tokens through external calls
     *      must ensure their public entrypoint is `nonReentrant` before calling this.
     */
    function _recordBatchedDeposit(
        address depositor,
        uint256 wrappedUnderlying,
        euint64 eAmount,
        eaddress verifiedRecipient
    ) internal returns (uint256 slot) {
        uint256 batchId = currentBatchId;
        Batch storage batch = _batches[batchId];
        // INVARIANT: the batch at `currentBatchId` is always open with room. Everything that fills
        // or closes a batch bumps `currentBatchId` in the same breath (see {_closeBatchUnchecked}
        // and the fill check at the end of this function), so no shipped path can violate this.
        //
        // It is asserted rather than recovered from because the recovery this replaced was wrong:
        // it re-read the unchanged `currentBatchId` and handed back the SAME closed batch, so a
        // deposit would have landed in a batch whose anonymity set is already frozen — and one
        // whose nullifier a recipient may have already consumed, stranding the match forever.
        if (batch.closed || batch.fillCount >= maxBatchDeposits) revert BatchAlreadyClosed();
        uint256 batchIndex = batch.fillCount;

        // Persist access to BOTH stored ciphertexts. `_wrapIntoEscrow` already allows the amount on
        // the bundled path, but this is the advertised storage boundary for derived adapters that
        // source confidential funds another way — and those may hold only TRANSIENT authorization,
        // which expires at the end of the transaction and would leave finalize unable to touch
        // `eAmount`, permanently unfinalizing the deposit. Re-granting is idempotent.
        FHE.allowThis(verifiedRecipient);
        FHE.allowThis(eAmount);

        slot = batchId * maxBatchDeposits + batchIndex;
        deposits[slot] = Deposit({
            depositor: depositor,
            amount: wrappedUnderlying,
            eAmount: eAmount,
            eRecipient: verifiedRecipient
        });

        batch.fillCount = batchIndex + 1;
        if (batchIndex == 0) batch.firstDepositAt = uint64(block.timestamp);
        batch.lastDepositAt = uint64(block.timestamp);
        totalDeposits += 1;

        // Emit BEFORE the close so log order matches the lifecycle. `_closeBatchUnchecked` emits
        // {BatchSealed}, so closing first made an event-only indexer see a batch seal before the
        // deposit that sealed it.
        emit WrapInitiated(batchId, slot, depositor, wrappedUnderlying, FHE.toBytes32(verifiedRecipient));

        if (batch.fillCount == maxBatchDeposits) _closeBatchUnchecked(batchId, batch);
    }

    // -----------------------------------------------------------------------
    // sealBatch: liveness escape hatch for a tail batch that never fills
    // -----------------------------------------------------------------------

    /**
     * @notice Close the current, still-open batch early so its deposits can be
     *         finalized. Permissionless, but only after `sealDelay` since the last
     *         deposit. finalizeWrap performs the same close automatically when it
     *         first sees an eligible open batch.
     */
    function sealBatch(uint256 batchId) external nonReentrant {
        if (batchId != currentBatchId) revert NotCurrentBatch();
        Batch storage batch = _batches[batchId];
        if (batch.closed) revert BatchAlreadyClosed();
        uint256 filled = batch.fillCount;
        if (filled == 0) revert NothingToSeal();
        if (!_sealDelayElapsed(batch)) revert SealDelayNotElapsed();

        _closeBatchUnchecked(batchId, batch);
    }

    // -----------------------------------------------------------------------
    // finalizeWrap: scan closed batches, tree-reduce the recipient's matches
    // -----------------------------------------------------------------------

    /**
     * @notice Transfer the encrypted sum of every deposit in the given CLOSED batches whose
     *         encrypted recipient equals `recipient`. Permissionless; replay-safe via the
     *         cleartext nullifier.
     *
     *         Batches already finalized for `recipient` are SKIPPED, not rejected — the call only
     *         reverts {AlreadyFinalized} if none of `ids` is left to claim. {WrapFinalized} reports
     *         the ids actually scanned, which is the anonymity set this call really used.
     *
     *         HCU note: the FHEVM per-tx budget bounds TOTAL SLOTS SCANNED PER CALL
     *         (~56 measured). With `maxBatchDeposits` near the 48 cap, finalize one
     *         batch per call; multi-batch calls suit smaller batch sizes.
     * @param ids Batch ids to finalize — MUST be strictly increasing (no duplicates).
     * @param recipient Address to match deposits against and transfer the total to.
     */
    function finalizeWrap(uint256[] calldata ids, address recipient) external virtual override nonReentrant {
        if (recipient == address(0)) revert ZeroAddress();
        // Without this, `finalizeWrap([], anyone)` scans nothing, sums to E_ZERO and still makes a
        // real `confidentialTransfer`, emitting a genuine ConfidentialTransfer plus
        // WrapFinalized(anyone, handle, []) — a claim no indexer can tell from a real one, against a
        // target who need never have touched the protocol, repeatable at gas cost and consuming no
        // nullifier. The continuous adapter is already covered by its `minDecoys >= 1` floor.
        if (ids.length == 0) revert InvalidId();

        (bool[] memory claimed, uint256 totalSlots, uint256 claimedCount) = _claimBatches(ids, recipient);
        if (claimedCount == 0) revert AlreadyFinalized();

        // Per-slot payouts are independent (depth ~2 each); only the reduction deepens
        // the FHE dependency chain, and the tree keeps that at ceil(log2 N) adds.
        euint64[] memory payouts = new euint64[](totalSlots);
        uint256[] memory scannedIds = new uint256[](claimedCount);
        uint256 p;
        uint256 c;
        for (uint256 k = 0; k < ids.length; k++) {
            if (!claimed[k]) continue;
            scannedIds[c++] = ids[k];
            uint256 startIndex = ids[k] * maxBatchDeposits;
            uint256 count = _batches[ids[k]].fillCount;
            for (uint256 j = 0; j < count; j++) {
                Deposit storage d = deposits[startIndex + j];
                ebool isMatch = FHE.eq(d.eRecipient, recipient);
                payouts[p++] = FHE.select(isMatch, d.eAmount, E_ZERO);
            }
        }

        euint64 total = _sumTree(payouts);
        euint64 transferred = _transferWrapped(recipient, total);

        emit WrapFinalized(recipient, FHE.toBytes32(transferred), scannedIds);
    }

    /**
     * @dev Cleartext pass of {finalizeWrap}: check ordering, close any batch that has become
     *      eligible, and claim the `(batch, recipient)` nullifier of each id not already taken.
     *
     *      Already-finalized ids are SKIPPED rather than reverting the call. `ids` and `recipient`
     *      are both visible in the mempool, so treating the set as all-or-nothing let anyone
     *      front-run `finalizeWrap([7, 8, 9], R)` with `finalizeWrap([7], R)` and revert the
     *      original on batch 7, leaving 8 and 9 unfinalized. The front-runner gains nothing — the
     *      payout still goes to `R` — but repeated cheaply it degraded multi-batch finalization
     *      into a retry loop. Skipping makes the original call succeed on whatever is left.
     *
     *      Returns a per-id flag rather than a filtered list because the caller needs both the
     *      scan set and the id ordering, and the nullifier is set here.
     */
    function _claimBatches(
        uint256[] calldata ids,
        address recipient
    ) private returns (bool[] memory claimed, uint256 totalSlots, uint256 claimedCount) {
        claimed = new bool[](ids.length);
        uint256 prev;
        for (uint256 k = 0; k < ids.length; k++) {
            uint256 batchId = ids[k];
            if (k > 0 && batchId <= prev) revert DuplicateId(); // strictly increasing, no dupes
            prev = batchId;
            Batch storage batch = _batches[batchId];
            _ensureBatchClosedForFinalize(batchId, batch);
            if (batch.finalized[recipient]) continue;
            batch.finalized[recipient] = true;
            claimed[k] = true;
            claimedCount++;
            totalSlots += batch.fillCount;
        }
    }

    function _ensureBatchClosedForFinalize(uint256 batchId, Batch storage batch) internal {
        if (batch.closed) return;
        if (batchId != currentBatchId || batch.fillCount == 0 || !_sealDelayElapsed(batch)) {
            revert BatchNotClosed();
        }

        _closeBatchUnchecked(batchId, batch);
    }

    /// @dev Callers must have established `fillCount > 0`, so `firstDepositAt` is set.
    function _sealDelayElapsed(Batch storage batch) internal view returns (bool) {
        return block.timestamp >= uint256(batch.firstDepositAt) + sealDelay;
    }

    // Raw state transition: callers must first prove the batch is full or delay-eligible.
    function _closeBatchUnchecked(uint256 batchId, Batch storage batch) internal {
        batch.closed = true;
        if (batchId == currentBatchId) currentBatchId = batchId + 1;
        emit BatchSealed(batchId, batch.fillCount);
    }
}
