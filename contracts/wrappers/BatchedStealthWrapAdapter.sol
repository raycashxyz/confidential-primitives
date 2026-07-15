// SPDX-License-Identifier: MIT
pragma solidity ^0.8.27;

import {FHE, euint64, ebool, eaddress, externalEaddress} from "@fhevm/solidity/lib/FHE.sol";
import {IERC7984ERC20Wrapper} from "@openzeppelin/confidential-contracts/interfaces/IERC7984ERC20Wrapper.sol";
import {StealthWrapAdapter} from "./base/StealthWrapAdapter.sol";

/**
 * @title BatchedStealthWrapAdapter
 * @notice Batch-based async wrapper with a cleartext per-(batch, recipient)
 *         nullifier and a tree-reduced payout sum.
 *
 *         Same privacy model as the other wrappers: a deposit is SENDER-TRANSPARENT
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
 *         Like the other wrappers: deposits are wrapped immediately into confidential
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

    /// @notice Seconds after a batch's last deposit before anyone may {sealBatch} it.
    uint256 public immutable sealDelay;

    /// @notice Batch currently accepting deposits.
    uint256 public currentBatchId;

    /// @notice Total deposits recorded across all batches.
    uint256 public totalDeposits;

    /// @notice Global slot index (batchId * maxBatchDeposits + batchIndex) => deposit.
    mapping(uint256 slot => Deposit) public deposits;

    mapping(uint256 batchId => Batch) private _batches;

    struct Batch {
        uint256 fillCount;
        bool closed;
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

    function getDepositsLength() external view override returns (uint256) {
        return totalDeposits;
    }

    function batchFillCount(uint256 batchId) public view returns (uint256) {
        return _batches[batchId].fillCount;
    }

    function batchClosed(uint256 batchId) public view returns (bool) {
        return _batches[batchId].closed;
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
    ) external override nonReentrant returns (uint256 slot) {
        uint256 batchId = currentBatchId;
        Batch storage batch = _batches[batchId];
        if (batch.closed || batch.fillCount == maxBatchDeposits) {
            if (!batch.closed) _closeBatchUnchecked(batchId, batch);
            batchId = currentBatchId;
            batch = _batches[batchId];
        }
        uint256 batchIndex = batch.fillCount;

        eaddress verifiedRecipient = FHE.fromExternal(eRecipient, inputProof);
        (uint256 wrappedUnderlying, euint64 eAmount) = _wrapIntoEscrow(msg.sender, amount);
        FHE.allowThis(verifiedRecipient);

        slot = batchId * maxBatchDeposits + batchIndex;
        deposits[slot] = Deposit({
            depositor: msg.sender,
            amount: wrappedUnderlying,
            eAmount: eAmount,
            eRecipient: verifiedRecipient
        });

        batch.fillCount = batchIndex + 1;
        batch.lastDepositAt = uint64(block.timestamp);
        totalDeposits += 1;

        if (batch.fillCount == maxBatchDeposits) _closeBatchUnchecked(batchId, batch);

        emit WrapInitiated(batchId, slot, msg.sender, wrappedUnderlying, FHE.toBytes32(verifiedRecipient));
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
     *         cleartext nullifier (a second call for the same (batch, recipient) reverts).
     *
     *         HCU note: the FHEVM per-tx budget bounds TOTAL SLOTS SCANNED PER CALL
     *         (~56 measured). With `maxBatchDeposits` near the 48 cap, finalize one
     *         batch per call; multi-batch calls suit smaller batch sizes.
     * @param ids Batch ids to finalize — MUST be strictly increasing (no duplicates).
     * @param recipient Address to match deposits against and transfer the total to.
     */
    function finalizeWrap(uint256[] calldata ids, address recipient) external override nonReentrant {
        if (recipient == address(0)) revert ZeroAddress();

        // Count scanned slots across batches to size the payout array.
        uint256 totalSlots;
        uint256 prev;
        for (uint256 k = 0; k < ids.length; k++) {
            uint256 batchId = ids[k];
            if (k > 0 && batchId <= prev) revert DuplicateId(); // strictly increasing, no dupes
            prev = batchId;
            Batch storage batch = _batches[batchId];
            _ensureBatchClosedForFinalize(batchId, batch);
            if (batch.finalized[recipient]) revert AlreadyFinalized();
            batch.finalized[recipient] = true;
            totalSlots += batch.fillCount;
        }

        // Per-slot payouts are independent (depth ~2 each); only the reduction deepens
        // the FHE dependency chain, and the tree keeps that at ceil(log2 N) adds.
        euint64[] memory payouts = new euint64[](totalSlots);
        uint256 p;
        for (uint256 k = 0; k < ids.length; k++) {
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

        emit WrapFinalized(recipient, FHE.toBytes32(transferred), ids);
    }

    function _ensureBatchClosedForFinalize(uint256 batchId, Batch storage batch) internal {
        if (batch.closed) return;
        if (batchId != currentBatchId || batch.fillCount == 0 || !_sealDelayElapsed(batch)) {
            revert BatchNotClosed();
        }

        _closeBatchUnchecked(batchId, batch);
    }

    function _sealDelayElapsed(Batch storage batch) internal view returns (bool) {
        return block.timestamp >= uint256(batch.lastDepositAt) + sealDelay;
    }

    // Raw state transition: callers must first prove the batch is full or delay-eligible.
    function _closeBatchUnchecked(uint256 batchId, Batch storage batch) internal {
        batch.closed = true;
        if (batchId == currentBatchId) currentBatchId = batchId + 1;
        emit BatchSealed(batchId, batch.fillCount);
    }
}
