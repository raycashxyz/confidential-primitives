// SPDX-License-Identifier: MIT
pragma solidity ^0.8.27;

import {FHE, euint64, externalEuint64, ebool, eaddress, externalEaddress} from "@fhevm/solidity/lib/FHE.sol";
import {ZamaEthereumConfig} from "@fhevm/solidity/config/ZamaConfig.sol";
import {IERC20} from "@openzeppelin/contracts/interfaces/IERC20.sol";
import {SafeERC20} from "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import {SafeCast} from "@openzeppelin/contracts/utils/math/SafeCast.sol";
import {ERC7984} from "@openzeppelin/confidential-contracts/token/ERC7984/ERC7984.sol";
import {ERC7984ERC20Wrapper} from "@openzeppelin/confidential-contracts/token/ERC7984/extensions/ERC7984ERC20Wrapper.sol";
import {IERC7984AsyncWrapper} from "./IERC7984AsyncWrapper.sol";

/**
 * @title BatchedAsyncWrapper
 * @notice Batched-bitmap variant of SimpleAsyncWrapper that eliminates the
 *         per-deposit SSTORE in finalizeWrap.
 *
 *         SimpleAsyncWrapper (ERC7984AsyncWrapper._finalizeWrap) rewrites each
 *         deposit's encrypted `amount` slot every cycle (`d.amount = select(...)`)
 *         to mark it consumed — one SSTORE of a fresh ciphertext handle per
 *         deposit, per finalize.
 *
 *         This contract instead keeps deposits write-once and tracks consumption
 *         in a single per-batch confidential bitmap (`batchFinalized[batchId]`):
 *         bit j == 1 means slot j of the batch has already been paid out. A
 *         finalize over a whole batch therefore writes ONE storage slot (the
 *         bitmap), not N.
 *
 *         Deposits land in fixed-size batches of `maxBatchDeposits`. finalizeWrap
 *         takes strictly-increasing batch ids and scans each entire batch, so the
 *         decoy set is the whole batch — no caller-supplied indices or decoys. The
 *         depositor learns their batch from the `WrapInitiated` event.
 *
 *         Bitmap is a euint64, so `maxBatchDeposits` is capped at 64: bit
 *         `1 << j` must fit, otherwise slots >= 64 would never be marked consumed
 *         and could be withdrawn repeatedly.
 *
 *         Like SimpleAsyncWrapper, deposits are pulled via IERC20.transferFrom
 *         (the depositor approves first). Unwrap uses the inherited OZ
 *         ERC7984ERC20Wrapper lifecycle (`unwrap` + `finalizeUnwrap`).
 */
contract BatchedAsyncWrapper is IERC7984AsyncWrapper, ZamaEthereumConfig, ERC7984ERC20Wrapper {
    using SafeERC20 for IERC20;

    /// @dev Max batch size — bounded by the 64 bits of the bitmap.
    uint256 private constant MAX_BATCH_LIMIT = 64;

    euint64 public immutable E_ZERO;
    uint256 public immutable maxBatchDeposits;

    /// @notice Total number of deposits recorded across all batches.
    uint256 public totalDeposits;

    /// @notice Global slot index (batchId * maxBatchDeposits + batchIndex) => deposit.
    mapping(uint256 slot => Deposit) public deposits;

    /// @notice batchId => confidential bitmap of already-finalized slots.
    mapping(uint256 batchId => euint64) public batchFinalized;

    struct Deposit {
        address depositor;
        uint256 amount;
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

    // ZeroAmount, ZeroAddress, DuplicateId, ExternalWrapNotSupported are inherited from IERC7984AsyncWrapper.
    error InvalidBatchSize();
    error BatchNotComplete();

    constructor(
        uint256 _maxBatchDeposits,
        IERC20 _underlying,
        string memory name_,
        string memory symbol_
    )
        ERC7984(name_, symbol_, "")
        ERC7984ERC20Wrapper(_underlying)
    {
        if (address(_underlying) == address(0)) revert ZeroAddress();
        if (_maxBatchDeposits == 0 || _maxBatchDeposits > MAX_BATCH_LIMIT) revert InvalidBatchSize();
        maxBatchDeposits = _maxBatchDeposits;
        E_ZERO = FHE.asEuint64(0);
        FHE.allowThis(E_ZERO);
    }

    // -----------------------------------------------------------------------
    // Batch arithmetic
    // -----------------------------------------------------------------------

    /// @notice Batch currently being filled.
    function currentBatchId() public view returns (uint256) {
        return totalDeposits / maxBatchDeposits;
    }

    function _batchIndex() private view returns (uint256) {
        return totalDeposits % maxBatchDeposits;
    }

    function _batchStartIndex(uint256 batchId) private view returns (uint256) {
        return batchId * maxBatchDeposits;
    }

    // -----------------------------------------------------------------------
    // Disabled OZ wrap paths — deposits must go through initWrap
    // -----------------------------------------------------------------------

    function wrap(address, uint256) public pure override {
        revert ExternalWrapNotSupported();
    }

    function onTransferReceived(address, address, uint256, bytes calldata) public pure override returns (bytes4) {
        revert ExternalWrapNotSupported();
    }

    // -----------------------------------------------------------------------
    // IERC7984AsyncWrapper: deposit count + unwrap lifecycle
    // -----------------------------------------------------------------------

    /// @inheritdoc IERC7984AsyncWrapper
    function getDepositsLength() external view override returns (uint256) {
        return totalDeposits;
    }

    /// @inheritdoc IERC7984AsyncWrapper
    function initUnwrap(
        externalEuint64 encryptedAmount,
        bytes calldata inputProof,
        address destination
    ) external override {
        if (destination == address(0)) revert ZeroAddress();
        euint64 amount = FHE.fromExternal(encryptedAmount, inputProof);
        FHE.allowThis(amount);
        _unwrap(msg.sender, destination, amount);
    }

    /// @inheritdoc IERC7984AsyncWrapper
    function initUnwrap(uint64 compressedAmount, address destination) external override {
        if (destination == address(0)) revert ZeroAddress();
        if (compressedAmount == 0) revert ZeroAmount();
        euint64 amount = FHE.asEuint64(compressedAmount);
        FHE.allowThis(amount);
        _unwrap(msg.sender, destination, amount);
    }

    // -----------------------------------------------------------------------
    // initWrap: pull tokens via transferFrom + record deposit (write-once)
    // -----------------------------------------------------------------------

    /**
     * @notice Record a deposit into the current batch by pulling `amount` underlying
     *         from `depositor` (who must have approved this wrapper).
     * @return slot Global slot index of the new deposit.
     */
    function initWrap(
        address depositor,
        uint256 amount,
        externalEaddress eRecipient,
        bytes calldata inputProof
    ) external returns (uint256 slot) {
        if (amount == 0) revert ZeroAmount();
        uint64 compressed = SafeCast.toUint64(amount / rate());
        if (compressed == 0) revert ZeroAmount();

        uint256 batchId = currentBatchId();
        uint256 batchIndex = _batchIndex();

        eaddress verifiedRecipient = FHE.fromExternal(eRecipient, inputProof);
        euint64 eAmount = FHE.asEuint64(compressed);
        FHE.allowThis(verifiedRecipient);
        FHE.allowThis(eAmount);

        // Initialise the per-batch bitmap once, on the first deposit of the batch.
        if (batchIndex == 0) {
            batchFinalized[batchId] = E_ZERO;
        }

        slot = _batchStartIndex(batchId) + batchIndex;
        deposits[slot] = Deposit({
            depositor: depositor,
            amount: amount,
            eAmount: eAmount,
            eRecipient: verifiedRecipient
        });
        totalDeposits += 1;

        emit WrapInitiated(batchId, slot, depositor, amount, FHE.toBytes32(verifiedRecipient));

        // Interactions last (Checks-Effects-Interactions): pull tokens only after the deposit is
        // recorded, so a reentrant initWrap (via a token transfer hook) cannot observe the same
        // totalDeposits, recompute the same `slot`, and have its record overwritten by this call.
        IERC20(address(underlying())).safeTransferFrom(depositor, address(this), amount);
    }

    // -----------------------------------------------------------------------
    // finalizeWrap: scan whole batch, pay unconsumed matches, flip their bits
    // -----------------------------------------------------------------------

    /**
     * @notice Per-slot finalize — reference implementation kept for the gas benchmark.
     *         Prefer {finalizeWrap}, which produces the same result with the bitwise work bulked.
     *         Mints the sum of every not-yet-finalized deposit in `batchId` matching `recipient`
     *         and marks those slots consumed. Permissionless and replay-safe.
     */
    function finalizeWrapPerSlot(uint256 batchId, address recipient) external {
        if (recipient == address(0)) revert ZeroAddress();
        uint256 startIndex = _batchStartIndex(batchId);
        uint256 endIndex = startIndex + maxBatchDeposits;
        // Complete-batch-only, exactly like the bulk path. A partial-batch finalize here would
        // commit only some of a recipient's slots; a later bulk {finalizeWrap} over the completed
        // batch re-sums ALL their matches and would re-pay the already-finalized ones.
        if (totalDeposits < endIndex) revert BatchNotComplete();

        // Snapshot the committed bitmap once. A slot is "already finalized" only if a
        // PRIOR finalize set its bit — never within this call, since each slot is visited
        // exactly once. So the per-slot check reads this constant snapshot, not the
        // running value. Keeping `committed` constant stops the FHE dependency chain from
        // deepening per iteration (FHEVM caps HCU depth per tx at 5M); new bits accumulate
        // in a separate `newBits` and are OR'd in once after the loop.
        euint64 committed = batchFinalized[batchId];
        euint64 sum = E_ZERO;
        euint64 newBits = E_ZERO;

        for (uint256 i = startIndex; i < endIndex; i++) {
            uint64 bitMask = uint64(1) << uint8(i - startIndex);
            Deposit storage d = deposits[i];

            ebool isMatch = FHE.eq(d.eRecipient, recipient);
            // Bit set in the committed map => this slot was already paid out earlier.
            ebool alreadyFinalized = FHE.ne(FHE.and(committed, bitMask), uint64(0));

            // Pay only on a fresh match.
            euint64 payout = FHE.select(alreadyFinalized, E_ZERO, FHE.select(isMatch, d.eAmount, E_ZERO));
            sum = FHE.add(sum, payout);

            // Record bit j on a match (OR into committed below is idempotent for replays).
            newBits = FHE.select(isMatch, FHE.or(newBits, bitMask), newBits);
        }

        euint64 bitmap = FHE.or(committed, newBits);
        FHE.allowThis(bitmap);
        batchFinalized[batchId] = bitmap;

        uint256[] memory singleId = new uint256[](1);
        singleId[0] = batchId;
        emit WrapFinalized(recipient, FHE.toBytes32(sum), singleId);

        _mint(recipient, sum);
    }

    // -----------------------------------------------------------------------
    // finalizeWrap: bulk bitwise nullifier, over one or more complete batches.
    // -----------------------------------------------------------------------

    /**
     * @notice Finalize the given complete batches for `recipient`, minting the homomorphic sum
     *         of their not-yet-claimed matching deposits in a single mint.
     *
     *         The bitwise nullifier work is hoisted out of the per-slot loop into ONE bulk update
     *         per batch — cheaper EVM gas than the rewrite strategy (the extra cost is FHE HCU,
     *         not paid on-chain). See {finalizeWrapPerSlot} for the naive per-slot reference.
     *
     *         Replay-safe across calls via each batch's bitmap; within a call the bulk gate is
     *         all-or-nothing, so each id MUST be a COMPLETE batch (no later top-ups). A single
     *         batch is just a length-1 array — matching the {IERC7984AsyncWrapper} signature.
     * @param ids Batch ids to finalize — MUST be strictly increasing (no duplicates).
     * @param recipient Address to match deposits against and mint the total to.
     */
    function finalizeWrap(uint256[] calldata ids, address recipient) external override {
        if (recipient == address(0)) revert ZeroAddress();

        euint64 total = E_ZERO;
        uint256 prev;
        for (uint256 k = 0; k < ids.length; k++) {
            uint256 batchId = ids[k];
            if (k > 0 && batchId <= prev) revert DuplicateId(); // strictly increasing, no dupes
            prev = batchId;
            total = FHE.add(total, _finalizeBatchBulk(batchId, recipient));
        }

        emit WrapFinalized(recipient, FHE.toBytes32(total), ids);
        _mint(recipient, total);
    }

    /**
     * @dev Bulk-finalize ONE complete batch for `recipient`: scan its slots, mark matched slots
     *      consumed in the batch bitmap (a single bulk write), and return the fresh payout.
     *      Reverts {BatchNotComplete} if the batch is not fully filled.
     */
    function _finalizeBatchBulk(uint256 batchId, address recipient) private returns (euint64) {
        uint256 startIndex = _batchStartIndex(batchId);
        uint256 endIndex = startIndex + maxBatchDeposits;
        if (totalDeposits < endIndex) revert BatchNotComplete();

        euint64 committed = batchFinalized[batchId];
        euint64 matchMask = E_ZERO; // packed: bit j set iff slot j matches `recipient`
        euint64 sum = E_ZERO;       // sum of ALL of recipient's matches (gated by match only)

        for (uint256 i = startIndex; i < endIndex; i++) {
            uint64 bitMask = uint64(1) << uint8(i - startIndex);
            Deposit storage d = deposits[i];

            ebool isMatch = FHE.eq(d.eRecipient, recipient);
            // Set bit j in the packed match vector on a match (scalar `or`, no trivial-encrypt).
            matchMask = FHE.select(isMatch, FHE.or(matchMask, bitMask), matchMask);
            sum = FHE.add(sum, FHE.select(isMatch, d.eAmount, E_ZERO));
        }

        // Bulk nullifier work — one pass on the whole word, not per slot.
        euint64 freshMask = FHE.and(matchMask, FHE.not(committed)); // recipient's not-yet-claimed bits
        ebool hasFresh = FHE.ne(freshMask, uint64(0));              // anything new to pay?
        euint64 payout = FHE.select(hasFresh, sum, E_ZERO);         // all-or-nothing replay gate
        euint64 bitmap = FHE.or(committed, matchMask);              // mark recipient's slots consumed

        FHE.allowThis(bitmap);
        batchFinalized[batchId] = bitmap;
        return payout;
    }
}
