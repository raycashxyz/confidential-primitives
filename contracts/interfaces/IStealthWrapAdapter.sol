// SPDX-License-Identifier: MIT
pragma solidity ^0.8.27;

import {externalEaddress} from "@fhevm/solidity/lib/FHE.sol";

/**
 * @title IStealthWrapAdapter
 * @author Valerio Leo (@valeriohq)
 * @author Pavlos Polianidis (@ppoliani)
 * @notice Shared interface for stealth wrap adapters over an existing OpenZeppelin
 *         ERC7984ERC20Wrapper on the Zama FHEVM.
 * @dev Implementations need more than ERC-7984 from the wrapper: Zama `eaddress` and `euint64`
 *      handles, the FHEVM ACL, coprocessor-issued input proofs, and the `underlying()` and `rate()`
 *      extensions. The wrapper must be exact-or-revert on `wrap`, and on `confidentialTransfer`
 *      where the adapter's finalize path is not retry-safe. See {StealthWrapAdapter}.
 */
interface IStealthWrapAdapter {
    /// @dev The clear amount wraps to zero after applying the wrapper's rate.
    error ZeroAmount();
    /// @dev A constructor address or the finalize recipient is the zero address.
    error ZeroAddress();
    /// @dev The confidential wrapper reports a zero wrap rate.
    error InvalidRate();
    /// @dev `minDecoys` is zero or above the largest scan one transaction can execute.
    error InvalidMinDecoys();
    /// @dev The finalize id set is smaller than `minDecoys`.
    error TooFewDecoys();
    /// @dev The finalize id set is empty, or names a deposit index past the end of the pool. The
    ///      batched adapter raises it for an empty set only. An id whose batch does not exist
    ///      reverts `BatchNotClosed` first.
    error InvalidId();
    /// @dev The finalize id set is not strictly ascending.
    error DuplicateId();
    /// @dev This encrypted-recipient handle has already funded a deposit. Handles are single-use by
    ///      default because a reused one publicly links its deposits. Ask the recipient for a fresh
    ///      encryption. See {StealthWrapAdapter-_consumeRecipientHandle} for adapters that permit reuse.
    error RecipientHandleAlreadyUsed();

    function confidentialWrapper() external view returns (address);
    function underlying() external view returns (address);
    function rate() external view returns (uint256);

    /// @notice Exclusive upper bound for enumerating deposit slots. Every recorded deposit lives at
    ///         some `slot < getDepositsLength()`.
    /// @dev Adapters may index slots sparsely. The batched one uses
    ///      `batchId * maxBatchDeposits + batchIndex`, so a batch sealed before it filled leaves its
    ///      unused slots empty. Treat this as a bound and skip empty slots, which read back with a
    ///      zero depositor. Where a true count exists it is exposed separately.
    function getDepositsLength() external view returns (uint256);

    /// @notice Deposit clear ERC-20 into escrow with an encrypted recipient.
    /// @dev The input proof must be bound to `(address(this), msg.sender)`.
    function initWrap(
        uint256 amount,
        externalEaddress encryptedRecipient,
        bytes calldata inputProof
    ) external returns (uint256 id);

    /// @notice Finalize pending deposits, transferring their homomorphic sum to `recipient`.
    /// @param ids Finalization units, meaning deposit indices for the continuous adapter and batch
    ///        ids for the batched one. Must be strictly ascending. Any non-increasing pair reverts
    ///        `DuplicateId`.
    /// @param recipient Non-zero address to match deposits against and transfer the total to.
    function finalizeWrap(uint256[] calldata ids, address recipient) external;
}
