// SPDX-License-Identifier: MIT
pragma solidity ^0.8.27;

import {externalEaddress} from "@fhevm/solidity/lib/FHE.sol";

/**
 * @title IERC7984AsyncWrapper
 * @notice Shared interface for async privacy layers over existing ERC7984ERC20Wrapper tokens.
 */
interface IERC7984AsyncWrapper {
    /// @dev The requested clear amount wraps to zero after applying the underlying wrapper rate.
    error ZeroAmount();
    /// @dev Used for invalid constructor/configuration addresses and finalize recipients.
    error ZeroAddress();
    /// @dev Constructor configuration error: the confidential wrapper reports a zero wrap rate.
    error InvalidRate();
    /// @dev Constructor configuration error: minDecoys must be non-zero.
    error InvalidMinDecoys();
    /// @dev Runtime finalize error: the selected decoy set is smaller than minDecoys.
    error TooFewDecoys();
    error InvalidId();
    error DuplicateId();

    function confidentialWrapper() external view returns (address);
    function underlying() external view returns (address);
    function rate() external view returns (uint256);
    function getDepositsLength() external view returns (uint256);

    /// @notice Deposit clear ERC20 into async escrow with an encrypted recipient.
    /// @dev The input proof must be bound to `(address(this), msg.sender)`.
    function initWrap(
        uint256 amount,
        externalEaddress encryptedRecipient,
        bytes calldata inputProof
    ) external returns (uint256 id);

    /// @notice Finalize pending deposits, transferring their homomorphic sum to `recipient`.
    /// @param ids Finalization units: deposit indices for simple wrappers or batch ids for batched wrappers.
    function finalizeWrap(uint256[] calldata ids, address recipient) external;
}
