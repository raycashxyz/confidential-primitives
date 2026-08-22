// SPDX-License-Identifier: MIT
pragma solidity ^0.8.27;

import {FHE, euint64, ebool, eaddress, externalEaddress} from "@fhevm/solidity/lib/FHE.sol";
import {IERC7984ERC20Wrapper} from "@openzeppelin/confidential-contracts/interfaces/IERC7984ERC20Wrapper.sol";
import {StealthWrapAdapter} from "./base/StealthWrapAdapter.sol";

/**
 * @title BatchedStealthWrapAdapter
 * @author Valerio Leo (@valeriohq)
 * @author Pavlos Polianidis (@ppoliani)
 * @notice Batch-based stealth wrap adapter with a per-(batch, recipient) encrypted claimed
 *         accumulator and a tree-reduced payout sum.
 *
 *         Same privacy model as the other adapters: a deposit is SENDER-TRANSPARENT
 *         (depositor + cleartext amount are public) but RECIPIENT-PRIVATE (an
 *         `eaddress`). finalize scans whole batches, so the decoy set is the batch and
 *         the transferred sum stays encrypted — observers learn only "R finalized batch B".
 *
 *         The batch hides a deposit only
 *         among slots the adversary cannot rule out. Someone who deposited into the same batch
 *         knows their own encrypted recipients, so they subtract those slots and what remains is
 *         the real anonymity set; own enough of a batch and it collapses to one. With
 *         `maxBatchDeposits` capped at 48 that is cheap to attempt, and {initWrapInto} only closes
 *         the displacement half of it. This is inherent to any fixed-size set an adversary can pay
 *         to fill — the mitigation is client-side, and it is practical here precisely because
 *         deposits are sender-transparent: inspect who is already in a batch, pin it, and judge
 *         whether the crowd is real.
 *
 *         REPLAY GUARD: AN ENCRYPTED PER-RECIPIENT LEDGER. Each batch tracks, per recipient, an
 *         encrypted `claimed` total; {finalizeWrap} pays `matched - claimed` and credits back only
 *         what the wrapper reports it actually moved. So `claimed` can never exceed a recipient's
 *         matched sum (no double-spend), and a soft-failed or partial transfer leaves the remainder
 *         claimable instead of destroying it — the adapter needs no exact-or-revert wrapper on the
 *         finalize path (the continuous adapter, which consumes deposits by zeroing them, still
 *         does; see its docs). A redundant finalize of a fully-claimed batch does not revert: it
 *         pays an encrypted zero. That is log noise, throttled by having to pay for the scan, and
 *         the amount was opaque either way.
 *
 *         The payout sum is tree-reduced via {_sumTree}. Pairwise reduction keeps the
 *         critical path to ceil(log2 N) adds, so {finalizeWrap} is bounded by the
 *         FHEVM total-HCU budget rather than a long serial add chain.
 *
 *         A batch must be CLOSED (full, or timeout-sealed via {sealBatch}) before finalizing, which
 *         freezes each recipient's matched set (no later top-ups into a finalized batch) — this is
 *         what makes `matched` stable enough to recompute on every retry. Tail batches can close only
 *         after `sealDelay`: either explicitly via {sealBatch} or automatically on the first
 *         {finalizeWrap} attempt, so funds cannot stay stuck without allowing premature one-deposit
 *         batches.
 *
 *         Recipient handshake (how the recipient stays hidden FROM THE CHAIN): the
 *         RECIPIENT encrypts their own address off-chain with the input proof bound to
 *         the DEPOSITOR as userAddress, and hands (handle, proof) to the depositor,
 *         who submits it via {initWrap}. The recipient recognises their deposit by
 *         watching for their handle in {WrapInitiated}. See the DEPOSITOR TRUST note on
 *         {StealthWrapAdapter} for what this does NOT hide.
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
    ///      and finalize scans a batch whole — `matched` is recomputed over every slot in it — so a
    ///      batch cannot be scanned in parts to get under the budget. The continuous adapter has the
    ///      same exposure through `minDecoys`, which is
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
        /// @dev Encrypted running total ALREADY delivered to each recipient from this batch. This is
        ///      the replay guard AND the retry ledger: {finalizeWrap} pays `matched - claimed` and
        ///      credits back what the wrapper reports actually moved, so a soft-failed or partial
        ///      transfer leaves the shortfall claimable rather than destroying it. See {finalizeWrap}.
        mapping(address recipient => euint64) claimed;
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

    /// @notice Encrypted amount already delivered to `recipient` from `batchId`. A handle equal to
    ///         that recipient's matched sum for the batch means fully claimed; a smaller one means a
    ///         soft-failed or partial finalize left a remainder still claimable. Uninitialized (zero
    ///         handle) means no finalize has touched this (batch, recipient) yet.
    /// @dev Replaces the old cleartext `finalized` bool: "fully claimed" is now an encrypted fact, so
    ///      it cannot be reported as a plain bool without decryption.
    function claimedAmount(uint256 batchId, address recipient) public view returns (euint64) {
        return _batches[batchId].claimed[recipient];
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
     *      It fixes displacement only; nothing stops an attacker
     *      from co-depositing into the batch you pinned. An anonymity set is only as good as the
     *      share of it you do not control, and with `maxBatchDeposits` at most 48 the slots are few
     *      enough to buy.
     *
     *      Buying them is not the hard part, though — knowing whose deposit to buy them around is.
     *      The attacker learns nothing from the batch itself: every recipient in it is encrypted, so
     *      filling slots blind costs gas plus capital locked until finalize and identifies nobody.
     *      The attack needs a target picked BEFORE the deposit lands, which means an off-chain link
     *      from a cleartext depositor in {WrapInitiated} to the payment worth deanonymising. Read
     *      the cost accordingly: cheap against a depositor already worth watching, pointless as a
     *      dragnet.
     *
     *      What helps is that this adapter is SENDER-TRANSPARENT: depositor and
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
        // deposit would have landed in a batch whose anonymity set is already frozen, and possibly
        // already scanned. The encrypted `claimed` ledger means the money is not lost (the late
        // deposit raises `matched`, so a further finalize pays it out), but collecting it requires
        // re-finalizing a batch observers have already watched settle, which is exactly the linkage
        // the batch was supposed to hide.
        if (batch.closed || batch.fillCount >= maxBatchDeposits) revert BatchAlreadyClosed();
        // A batch is append-only and never has holes — deposits occupy `[0, fillCount)` and nothing
        // removes one, so the next free index IS the count. A partially filled batch that seals
        // stops growing rather than leaving gaps, which is why `getDepositsLength` is a bound over
        // sparse GLOBAL slots while this per-batch index stays contiguous.
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
     *         finalized. Permissionless, but only after `sealDelay` since the batch's
     *         FIRST deposit (see {sealDelay} for why the anchor is not the last one).
     *         finalizeWrap performs the same close automatically when it first sees an
     *         eligible open batch.
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
     * @notice Transfer, per given CLOSED batch, the still-unclaimed part of the encrypted sum of
     *         that batch's deposits whose encrypted recipient equals `recipient`. Permissionless and
     *         RETRY-SAFE: a soft-failed or partial wrapper transfer leaves the remainder claimable.
     *
     *         Each batch is finalized INDEPENDENTLY — one `confidentialTransfer` per id (see
     *         {_finalizeBatch}). Passing several ids is a convenience, not a gas optimization: it
     *         does not merge the transfers, so on a hooked wrapper each id pays its own per-transfer
     *         hook cost. Near the HCU cap, finalize one batch per call; multi-batch calls suit
     *         smaller batches.
     *
     *         REPLAY / DOUBLE-SPEND. There is no cleartext nullifier. Each batch tracks an encrypted
     *         `claimed[recipient]` (see {Batch}); a finalize pays `matched - claimed` and credits back
     *         only what the wrapper reports it actually moved, so `claimed` can never exceed a
     *         recipient's matched sum and a fully-claimed batch pays an encrypted zero on any repeat.
     *         The cost of dropping the cleartext guard: a repeat call still runs the scan and emits a
     *         genuine-looking {WrapFinalized} carrying an encrypted-zero amount. That amount is opaque
     *         in every path (a finalize of a batch the recipient is not in already emits one), and the
     *         repeat is throttled by paying for the scan, so this is log noise, not a forgeable
     *         payout. An empty id set is still rejected outright.
     *
     * @param ids Batch ids to finalize — MUST be strictly increasing (no duplicates).
     * @param recipient Address to match deposits against and transfer to.
     */
    function finalizeWrap(uint256[] calldata ids, address recipient) external virtual override nonReentrant {
        if (recipient == address(0)) revert ZeroAddress();
        // `finalizeWrap([], anyone)` would otherwise scan nothing and still make a real
        // `confidentialTransfer`, emitting WrapFinalized(anyone, handle, []) against a target who
        // need never have touched the protocol. The continuous adapter is covered by `minDecoys >= 1`.
        if (ids.length == 0) revert InvalidId();

        uint256 prev;
        for (uint256 k = 0; k < ids.length; k++) {
            uint256 batchId = ids[k];
            if (k > 0 && batchId <= prev) revert DuplicateId(); // strictly increasing, no dupes
            prev = batchId;

            Batch storage batch = _batches[batchId];
            _ensureBatchClosedForFinalize(batchId, batch);
            _finalizeBatch(batchId, batch, recipient);
        }
    }

    /**
     * @dev Finalize ONE batch for `recipient`, retry- and partial-safe.
     *
     *      Pays `owed = matched - alreadyClaimed`, then credits `alreadyClaimed + transferred` with
     *      the amount the wrapper reports it ACTUALLY moved — never the amount requested. Two
     *      invariants make this safe:
     *
     *        - `credited <= owed` always, so `claimed <= matched` holds by induction and
     *          `matched - claimed` never underflows. A recipient can therefore never be paid more
     *          than their matched sum: no double-spend. An honest wrapper never returns more than it
     *          was asked to move, but this clamps rather than assuming it — see {_creditedAmount}.
     *        - crediting the ACTUAL amount means a wrapper that moved zero (freeze / pause / hook
     *          veto) credits nothing and the whole claim survives for a later retry, and one that
     *          moved only part credits that part and leaves the exact remainder claimable. This is
     *          why the batched adapter needs no exact-or-revert wrapper on the finalize path.
     *
     *      `matched` is recomputed from the batch's slots on every call, which is sound because
     *      deposits are immutable and the batch is closed before finalize — the reason this adapter
     *      does NOT zero matched amounts (unlike the continuous one). Do not add such zeroing without
     *      removing this ledger: it would make `matched` un-recomputable and break every retry.
     *
     *      REENTRANCY: the credit commits AFTER the external transfer (it needs the returned amount),
     *      so unlike the deposit path this leans entirely on {finalizeWrap} being `nonReentrant` — a
     *      reentrant finalize would otherwise read the stale `claimed` and double-pay. See the
     *      contract-level REENTRANCY note on {StealthWrapAdapter}.
     */
    function _finalizeBatch(uint256 batchId, Batch storage batch, address recipient) private {
        uint256 startIndex = batchId * maxBatchDeposits;
        uint256 count = batch.fillCount;

        // Per-slot payouts are independent (depth ~2 each); the tree keeps the reduction at
        // ceil(log2 N) adds.
        euint64[] memory payouts = new euint64[](count);
        for (uint256 j = 0; j < count; j++) {
            Deposit storage d = deposits[startIndex + j];
            ebool isMatch = FHE.eq(d.eRecipient, recipient);
            payouts[j] = FHE.select(isMatch, d.eAmount, E_ZERO);
        }
        euint64 matched = _sumTree(payouts);

        euint64 alreadyClaimed = batch.claimed[recipient];
        if (!FHE.isInitialized(alreadyClaimed)) alreadyClaimed = E_ZERO;
        euint64 owed = FHE.sub(matched, alreadyClaimed);

        euint64 transferred = _transferWrapped(recipient, owed);
        euint64 credited = _creditedAmount(transferred, owed);

        euint64 newClaimed = FHE.add(alreadyClaimed, credited);
        FHE.allowThis(newClaimed);
        batch.claimed[recipient] = newClaimed;

        uint256[] memory scannedIds = new uint256[](1);
        scannedIds[0] = batchId;
        emit WrapFinalized(recipient, FHE.toBytes32(credited), scannedIds);
    }

    /// @dev What a finalize may add to `claimed`: the amount the wrapper reported, clamped to what
    ///      was actually owed. An honest wrapper never moves more than it was asked to, so this is a
    ///      no-op on every supported configuration — but `claimed <= matched` is the invariant that
    ///      keeps {_finalizeBatch}'s `FHE.sub` from underflowing, and this makes it hold by
    ///      construction instead of by trusting the wrapper's return value. Without it an
    ///      over-reporting wrapper pushes `claimed` past `matched`, and since FHE arithmetic WRAPS
    ///      the next `matched - claimed` becomes ~2^64: against a soft-failing wrapper that oversized
    ///      request simply moves zero, so the visible effect is a stuck remainder rather than a
    ///      drain, but against an exact-or-revert one every later finalize for that recipient reverts
    ///      permanently. It also keeps {claimedAmount} truthful. One `FHE.min` per finalize CALL, not
    ///      per slot, so the cost does not scale with batch size. The clamped value is what
    ///      {WrapFinalized} reports, so the event and the ledger never disagree.
    function _creditedAmount(euint64 transferred, euint64 owed) private returns (euint64) {
        return FHE.min(transferred, owed);
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
