// SPDX-License-Identifier: MIT
pragma solidity ^0.8.27;

import {externalEaddress} from "@fhevm/solidity/lib/FHE.sol";

/**
 * @title IStealthWrapAdapter
 * @author Valerio Leo (@valeriohq)
 * @author Pavlos Polianidis (@ppoliani)
 * @notice Shared interface for stealth wrap adapters over an existing OpenZeppelin
 *         ERC7984ERC20Wrapper on the Zama FHEVM.
 * @dev ERC-7984 compliance alone is NOT sufficient. Implementations require Zama `eaddress` /
 *      `euint64` handles, the FHEVM ACL and coprocessor-issued input proofs, plus the wrapper
 *      extensions `underlying()` and `rate()`, which are not part of ERC-7984 itself. The wrapper
 *      must be exact-or-revert on `wrap`, and on `confidentialTransfer` where the adapter's
 *      finalize path is not retry-safe; see {StealthWrapAdapter}.
 */
interface IStealthWrapAdapter {
    /// @dev The requested clear amount wraps to zero after applying the underlying wrapper rate.
    error ZeroAmount();
    /// @dev Used for invalid constructor/configuration addresses and finalize recipients.
    error ZeroAddress();
    /// @dev Constructor configuration error: the confidential wrapper reports a zero wrap rate.
    error InvalidRate();
    /// @dev Constructor configuration error: minDecoys must be non-zero and no larger than the
    ///      adapter's maximum executable scan, or no finalize could ever satisfy the floor.
    error InvalidMinDecoys();
    /// @dev Runtime finalize error: the selected decoy set is smaller than minDecoys.
    error TooFewDecoys();
    /// @dev The finalize id set is empty, or names a unit the adapter rejects outright. The
    ///      continuous adapter raises it for a deposit index past the end of the pool; the batched
    ///      one raises it only for an empty set, because an id whose batch does not exist is not
    ///      closed and so reverts `BatchNotClosed` first.
    error InvalidId();
    /// @dev The finalize id set is not strictly ascending (unsorted or containing duplicates).
    error DuplicateId();
    /// @dev A deposit entry point (`initWrap`, or any other an adapter exposes such as the batched
    ///      adapter's `initWrapInto`) was called with an empty `inputProof`. Every legitimate deposit
    ///      carries a proof, so this is rejected up front with the adapter's own error; the import
    ///      itself would reject it anyway. See {StealthWrapAdapter-_verifyRecipient}.
    error MissingInputProof();
    /// @dev This encrypted-recipient handle has already funded a deposit. Handles are single-use by
    ///      default, because reusing one publicly links the deposits; ask the recipient for a fresh
    ///      encryption. A derived adapter whose deposit path already publishes the grouping (a CREATE2
    ///      deposit address keyed on the handle, where the payer's clear transfer to that address
    ///      links the deposits before the wrap runs) may permit reuse and never raise this. See
    ///      {StealthWrapAdapter-_consumeRecipientHandle}.
    error RecipientHandleAlreadyUsed();

    function confidentialWrapper() external view returns (address);
    function underlying() external view returns (address);
    function rate() external view returns (uint256);

    /// @notice EXCLUSIVE upper bound for enumerating deposit slots: every recorded deposit lives at
    ///         some `slot < getDepositsLength()`.
    /// @dev Not necessarily the NUMBER of deposits. An adapter may index slots sparsely: the
    ///      batched one uses `batchId * maxBatchDeposits + batchIndex`, so a partially filled batch
    ///      that gets sealed leaves its unused slots empty forever. Readers must therefore treat
    ///      this as a bound and skip empty slots (an unwritten `deposits(slot)` has a zero
    ///      depositor), not as a count. Where a true count exists it is exposed separately.
    function getDepositsLength() external view returns (uint256);

    /// @notice Deposit clear ERC20 into escrow with an encrypted recipient.
    /// @dev The input proof must be bound to `(address(this), msg.sender)`.
    function initWrap(
        uint256 amount,
        externalEaddress encryptedRecipient,
        bytes calldata inputProof
    ) external returns (uint256 id);

    /// @notice Finalize pending deposits, transferring their homomorphic sum to `recipient`.
    /// @param ids Finalization units: deposit indices for continuous adapters or batch ids for batched
    ///        adapters. MUST be strictly ascending (sorted, no duplicates); any non-increasing pair
    ///        reverts `DuplicateId` (so an unsorted-but-unique array is rejected too).
    /// @param recipient Non-zero address to match deposits against and transfer the total to.
    function finalizeWrap(uint256[] calldata ids, address recipient) external;
}
