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
 * @notice Stealth wrap adapter that groups deposits into fixed-size batches. A deposit is
 *         sender-transparent, with depositor and clear amount public, and recipient-private, with
 *         the recipient an `eaddress`. {finalizeWrap} scans whole batches, so the batch is the
 *         anonymity set and the transferred sum stays encrypted. Observers learn only that
 *         `recipient` finalized batch `B`.
 *
 * @dev Anonymity set. A batch hides a deposit only among slots the adversary cannot rule out. A
 *      co-depositor subtracts their own slots, and with `maxBatchDeposits` at most 48 filling a
 *      batch is cheap. Deposits are sender-transparent, so the defence is client-side. Inspect who
 *      is already in a batch, pin it with {initWrapInto}, and judge whether the crowd is real.
 *
 *      Lifecycle. A batch closes when it fills, or after `sealDelay` from its first deposit through
 *      {sealBatch} or the first {finalizeWrap} that finds it eligible. Only closed batches finalize,
 *      which freezes each recipient's matched set so {finalizeWrap} can recompute it on every retry
 *      against the encrypted per-recipient `claimed` ledger.
 *
 *      The recipient spots their deposit by watching for their handle in {WrapInitiated}. Deposits
 *      are wrapped into confidential balance held by this contract on deposit and transferred to
 *      recipients on finalize.
 */
contract BatchedStealthWrapAdapter is StealthWrapAdapter {
    /// @dev Hard cap on batch size, so one batch always finalizes within the FHEVM 20M HCU
    ///      per-transaction budget. Finalize does fixed FHE work per slot (`eq`, `select` and a tree
    ///      `add`). Measured on the coprocessor mocks, 56 slots fit and 60 revert, so 48 leaves
    ///      15-20% headroom for the adapter's own work. The wrapper's `confidentialTransfer` spends
    ///      from the same budget, and a hooked wrapper's admin can add modules after deposits are
    ///      escrowed, so size `maxBatchDeposits` against the target wrapper's transfer cost and
    ///      prefer a wrapper whose FHE cost cannot change. The budget is per call. Near the cap,
    ///      finalize one batch per call.
    uint256 private constant MAX_BATCH_LIMIT = 48;

    uint256 public immutable maxBatchDeposits;

    /// @notice Seconds after a batch's first deposit before anyone may {sealBatch} it.
    /// @dev Anchored to the first deposit so nobody can extend a batch's lifetime. A timer measured
    ///      from the last deposit could be pushed out by a minimum deposit just before it expires,
    ///      once per free slot, and since {finalizeWrap} names the recipient in calldata an observer
    ///      could stall and surround a specific pending finalization. Size `sealDelay` as how long a
    ///      batch may spend gathering its anonymity set.
    uint256 public immutable sealDelay;

    /// @notice Batch currently accepting deposits.
    uint256 public currentBatchId;

    /// @notice Number of deposits recorded across all batches. Enumerate with {getDepositsLength},
    ///         since slots are sparse.
    uint256 public totalDeposits;

    /// @notice Global slot index (batchId * maxBatchDeposits + batchIndex) => deposit.
    mapping(uint256 slot => Deposit) public deposits;

    mapping(uint256 batchId => Batch) private _batches;

    struct Batch {
        uint256 fillCount;
        bool closed;
        /// @dev Anchor for the seal deadline. Set once, by the batch's first deposit.
        uint64 firstDepositAt;
        /// @dev Informational, for indexers. The seal deadline uses `firstDepositAt`.
        uint64 lastDepositAt;
        /// @dev Encrypted total already delivered to each recipient from this batch. {finalizeWrap}
        ///      pays `matched - claimed` and credits back what the wrapper reports it moved.
        mapping(address recipient => euint64) claimed;
    }

    struct Deposit {
        address depositor;
        uint256 amount; // cleartext: the transparent side of the mix
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
        // With a zero delay anyone could seal every batch at one deposit. Choosing a large enough
        // delay, hours rather than minutes, is the deployer's call, like maxBatchDeposits.
        if (_sealDelay == 0) revert SealDelayTooShort();
        maxBatchDeposits = _maxBatchDeposits;
        sealDelay = _sealDelay;
    }

    /**
     * @notice Exclusive upper bound for enumerating deposit slots. {totalDeposits} is the count.
     * @dev Slots are sparse. A batch sealed before it filled leaves its remaining slots empty, so
     *      with `maxBatchDeposits = 4` and one deposit in each of batches 0 and 1 the live slots
     *      are 0 and 4, this returns 5 and {totalDeposits} returns 2.
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

    /// @notice Encrypted amount already delivered to `recipient` from `batchId`. Equal to the
    ///         recipient's matched sum once fully claimed, smaller after a soft-failed or partial
    ///         finalize, and the zero handle before any finalize touched the pair. Compare it with
    ///         the matched sum off-chain.
    function claimedAmount(uint256 batchId, address recipient) public view returns (euint64) {
        return _batches[batchId].claimed[recipient];
    }

    // -----------------------------------------------------------------------
    // Deposits
    // -----------------------------------------------------------------------

    /**
     * @notice Deposit `amount` underlying from `msg.sender`, who must have approved this adapter,
     *         into the current batch. `inputProof` must bind `eRecipient` to `(this, msg.sender)`.
     *         Amounts round down to the wrapper's rate, and the recorded amount is what was wrapped.
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
     * @notice {initWrap} pinned to `expectedBatchId`, reverting {NotCurrentBatch} otherwise.
     * @param expectedBatchId The batch the depositor inspected and means to join. Which batch a
     *        deposit joins is decided at execution, so anyone can fill the remaining slots ahead of
     *        the transaction and displace it into a fresh batch they then fill themselves, which
     *        leaves the displaced deposit identifiable at finalize. Pinning turns that into a revert.
     *        It does not stop an attacker co-depositing into the pinned batch, so judge the crowd
     *        before pinning, which the cleartext depositors in {WrapInitiated} make possible.
     * @return slot Global slot index of the new deposit.
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

    /// @dev Shared body of the two deposit entry points.
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
     * @dev Record an already-wrapped deposit in the current batch. Separate from token acquisition
     *      so derived adapters can source deposits differently while keeping this adapter's batch
     *      selection, close and accounting. Runs only inside a `nonReentrant` entrypoint, like
     *      every deposit path.
     */
    function _recordBatchedDeposit(
        address depositor,
        uint256 wrappedUnderlying,
        euint64 eAmount,
        eaddress verifiedRecipient
    ) internal onlyGuarded returns (uint256 slot) {
        uint256 batchId = currentBatchId;
        Batch storage batch = _batches[batchId];
        // The batch at `currentBatchId` is always open with room, since whatever fills or closes a
        // batch bumps `currentBatchId` in the same call. A deposit is rejected rather than redirected
        // here because a closed batch's anonymity set is frozen and possibly already scanned.
        if (batch.closed || batch.fillCount >= maxBatchDeposits) revert BatchAlreadyClosed();
        // Batches are append-only with no holes, so the next free index is the fill count.
        uint256 batchIndex = batch.fillCount;

        // Persist access to both stored ciphertexts. A derived adapter may hold only transient
        // authorization on `eAmount`, which would leave finalize unable to use it. Re-granting is
        // idempotent.
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

        // Emit before the close so log order matches the lifecycle.
        emit WrapInitiated(batchId, slot, depositor, wrappedUnderlying, FHE.toBytes32(verifiedRecipient));

        if (batch.fillCount == maxBatchDeposits) _closeBatchUnchecked(batchId, batch);
    }

    // -----------------------------------------------------------------------
    // Sealing
    // -----------------------------------------------------------------------

    /**
     * @notice Close the current batch early so its deposits can be finalized. Permissionless once
     *         `sealDelay` has passed since the batch's first deposit. {finalizeWrap} performs the
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
        uint256 startIndex = batchId * maxBatchDeposits;
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
        euint64 credited = _creditedAmount(transferred, owed);

        euint64 newClaimed = FHE.add(alreadyClaimed, credited);
        FHE.allowThis(newClaimed);
        batch.claimed[recipient] = newClaimed;

        uint256[] memory scannedIds = new uint256[](1);
        scannedIds[0] = batchId;
        emit WrapFinalized(recipient, FHE.toBytes32(credited), scannedIds);
    }

    /// @dev The amount the wrapper reported, clamped to what was owed. An honest wrapper never moves
    ///      more than asked, so this is a no-op on every supported configuration, but it keeps
    ///      `claimed <= matched` by construction rather than by trusting the return value. FHE
    ///      arithmetic wraps, so an over-report would otherwise push the next `matched - claimed`
    ///      to about 2^64 and break every later finalize for that recipient. The clamped value is
    ///      what {WrapFinalized} reports.
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

    // Raw state transition. Callers must first prove the batch is full or delay-eligible.
    function _closeBatchUnchecked(uint256 batchId, Batch storage batch) internal {
        batch.closed = true;
        if (batchId == currentBatchId) currentBatchId = batchId + 1;
        emit BatchSealed(batchId, batch.fillCount);
    }
}
