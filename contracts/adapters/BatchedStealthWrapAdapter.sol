// SPDX-License-Identifier: MIT
pragma solidity ^0.8.27;

import {FHE, euint64, ebool, eaddress, externalEaddress} from "@fhevm/solidity/lib/FHE.sol";
import {IERC7984ERC20Wrapper} from "@openzeppelin/confidential-contracts/interfaces/IERC7984ERC20Wrapper.sol";
import {StealthWrapAdapter} from "./base/StealthWrapAdapter.sol";
import {FHEUtils} from "../fhe/FHEUtils.sol";

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
    uint256 private constant MAX_BATCH_LIMIT = 48;

    uint256 public immutable maxBatchDeposits;

    /// @notice Seconds after a batch opens, with its first deposit, before anyone may {sealBatch} it.
    uint256 public immutable sealDelay;

    /// @notice Batch currently accepting deposits.
    uint256 public currentBatchId;

    Deposit[] public deposits;

    mapping(uint256 batchId => Batch) private _batches;

    struct Batch {
        uint256 fillCount;
        bool closed;
        uint64 openedAt;
        /// @dev The batch occupies slots `[firstSlot, firstSlot + fillCount)`.
        uint64 firstSlot;
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

    function getDepositsLength() external view override returns (uint256) {
        return deposits.length;
    }

    function batchFillCount(uint256 batchId) public view returns (uint256) {
        return _batches[batchId].fillCount;
    }

    function batchClosed(uint256 batchId) public view returns (bool) {
        return _batches[batchId].closed;
    }

    /// @notice When the batch opened, meaning its first deposit landed. Zero before that.
    function batchOpenedAt(uint256 batchId) public view returns (uint64) {
        return _batches[batchId].openedAt;
    }

    /// @notice Encrypted amount already delivered to `recipient` from `batchId`. Equal to the
    ///         recipient's matched sum once fully claimed, smaller after a soft-failed or partial
    ///         finalize, and the zero handle before any finalize touched the pair. Compare it with
    ///         the matched sum off-chain.
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
        eaddress verifiedRecipient = _verifyRecipient(eRecipient, inputProof);
        if (!FHEUtils.isFreshForThis(FHE.toBytes32(verifiedRecipient))) revert RecipientHandleAlreadyUsed();
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
        // The batch at `currentBatchId` is always open with room, since whatever fills or closes a
        // batch bumps `currentBatchId` in the same call. A deposit is rejected rather than redirected
        // here because a closed batch's anonymity set is frozen and possibly already scanned.
        if (batch.closed || batch.fillCount >= maxBatchDeposits) revert BatchAlreadyClosed();
        uint256 batchIndex = batch.fillCount;

        // Persist access to both stored ciphertexts. A derived adapter may hold only transient
        // authorization on `eAmount`, which would leave finalize unable to use it. Re-granting is
        // idempotent.
        FHE.allowThis(verifiedRecipient);
        FHE.allowThis(eAmount);

        slot = deposits.length;
        deposits.push(Deposit({
            depositor: depositor,
            amount: wrappedUnderlying,
            eAmount: eAmount,
            eRecipient: verifiedRecipient
        }));

        batch.fillCount = batchIndex + 1;
        if (batchIndex == 0) {
            batch.openedAt = uint64(block.timestamp);
            batch.firstSlot = uint64(slot);
        }

        // Emit before the close so log order matches the lifecycle.
        emit WrapInitiated(batchId, slot, depositor, wrappedUnderlying, FHE.toBytes32(verifiedRecipient));

        if (batch.fillCount == maxBatchDeposits) _closeBatchUnchecked(batchId, batch);
    }

    // -----------------------------------------------------------------------
    // sealBatch: liveness escape hatch for a tail batch that never fills
    // -----------------------------------------------------------------------

    /**
     * @notice Close the current batch early so its deposits can be finalized. Permissionless once
     *         `sealDelay` has passed since the batch opened. {finalizeWrap} performs the
     *         same close when it first finds an eligible open batch.
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
    // Finalization
    // -----------------------------------------------------------------------

    /**
     * @notice Transfer to `recipient`, for each given closed batch, the still-unclaimed part of the
     *         encrypted sum of that batch's deposits whose encrypted recipient equals `recipient`.
     *         Permissionless and retry-safe. A soft-failed or partial wrapper transfer leaves the
     *         remainder claimable, and a fully-claimed batch pays an encrypted zero.
     * @dev Each batch is finalized on its own, with one `confidentialTransfer` per id, so passing
     *      several ids merges nothing. Near the HCU cap, finalize one batch per call.
     * @param ids Batch ids to finalize. Must be strictly increasing and non-empty.
     * @param recipient Address to match deposits against and transfer to.
     */
    function finalizeWrap(uint256[] calldata ids, address recipient) external virtual override nonReentrant {
        if (recipient == address(0)) revert ZeroAddress();
        // An empty set would scan nothing and still transfer, emitting {WrapFinalized} against an
        // address that never touched the protocol.
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
     * @dev Finalize one batch for `recipient`. Pays `owed = matched - claimed`, then credits
     *      `claimed` with what the wrapper reports it moved, clamped to `owed`. `claimed <= matched`
     *      therefore holds by construction, so the subtraction cannot underflow and a recipient is
     *      never paid more than their matched sum, while a transfer that moved zero or part leaves
     *      the exact remainder claimable.
     *
     *      `matched` is recomputed from the batch on every call, which is sound because deposits
     *      are immutable and the batch is closed, and is why matched amounts are not zeroed here.
     *      The credit commits after the external transfer, so the `nonReentrant` entrypoint is what
     *      stops a re-entrant finalize from reading the stale ledger.
     */
    function _finalizeBatch(uint256 batchId, Batch storage batch, address recipient) private {
        uint256 startIndex = batch.firstSlot;
        uint256 count = batch.fillCount;

        // Per-slot payouts are independent. The tree keeps the reduction at ceil(log2 N) adds.
        euint64[] memory payouts = new euint64[](count);
        for (uint256 j = 0; j < count; j++) {
            Deposit storage d = deposits[startIndex + j];
            ebool isMatch = FHE.eq(d.eRecipient, recipient);
            payouts[j] = FHE.select(isMatch, d.eAmount, E_ZERO);
        }
        euint64 matched = FHEUtils.sum(payouts);

        euint64 alreadyClaimed = batch.claimed[recipient];
        if (!FHE.isInitialized(alreadyClaimed)) alreadyClaimed = E_ZERO;
        euint64 owed = FHE.sub(matched, alreadyClaimed);

        euint64 transferred = _transferWrapped(recipient, owed);
        // Clamp the wrapper-reported amount to what was owed, so `claimed <= matched` holds by
        // construction rather than by trusting the return value. The clamped figure is what
        // {WrapFinalized} reports.
        euint64 credited = FHE.min(transferred, owed);

        euint64 newClaimed = FHE.add(alreadyClaimed, credited);
        FHE.allowThis(newClaimed);
        batch.claimed[recipient] = newClaimed;

        uint256[] memory scannedIds = new uint256[](1);
        scannedIds[0] = batchId;
        emit WrapFinalized(recipient, FHE.toBytes32(credited), scannedIds);
    }

    function _ensureBatchClosedForFinalize(uint256 batchId, Batch storage batch) internal {
        if (batch.closed) return;
        if (batchId != currentBatchId || batch.fillCount == 0 || !_sealDelayElapsed(batch)) {
            revert BatchNotClosed();
        }

        _closeBatchUnchecked(batchId, batch);
    }

    /// @dev Callers must have established `fillCount > 0`, so `openedAt` is set.
    function _sealDelayElapsed(Batch storage batch) internal view returns (bool) {
        return block.timestamp >= uint256(batch.openedAt) + sealDelay;
    }

    // Raw state transition: callers must first prove the batch is full or delay-eligible.
    function _closeBatchUnchecked(uint256 batchId, Batch storage batch) internal {
        batch.closed = true;
        if (batchId == currentBatchId) currentBatchId = batchId + 1;
        emit BatchSealed(batchId, batch.fillCount);
    }
}
