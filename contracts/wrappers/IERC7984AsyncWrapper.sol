// SPDX-License-Identifier: MIT
pragma solidity ^0.8.27;

import {externalEuint64} from "@fhevm/solidity/lib/FHE.sol";

/**
 * @title IERC7984AsyncWrapper
 * @notice Abstract interface for async confidential token wrappers.
 *
 *         Shared two-phase lifecycle for any wrapper that converts cleartext
 *         ERC-20 tokens into encrypted ERC-7984 tokens:
 *           - initWrap (child-specific) / finalizeWrap — deposit with minDecoys privacy
 *           - initUnwrap / finalizeUnwrap — burn + off-chain decrypt + transfer (OZ flow)
 *
 *         Unowned — no AccessControl, no hooks, no withdrawal escape hatch.
 *         Children add their own governance, hooks, and recovery mechanisms.
 *
 *         Inherits ERC7984ERC20Wrapper for underlying(), rate(), decimals(), supply checks.
 *         Disables OZ's wrap() and onTransferReceived() — all deposits go through child-specific initWrap.
 *         Uses OZ's _unwrap() and finalizeUnwrap() for the unwrap lifecycle.
 */
interface IERC7984AsyncWrapper {

    // Deposit struct and WrapInitiated/WrapFinalized events are implementation-specific
    // (the flat wrapper and the batched wrapper store and emit different shapes), so they are
    // defined in the implementations, not here — keeping this a pure functions+errors interface.

    // -----------------------------------------------------------------------
    // Errors
    // -----------------------------------------------------------------------

    error ZeroAmount();
    error ZeroAddress();
    error ExternalWrapNotSupported();
    error InvalidMinDecoys();
    error TooFewDecoys();
    error InvalidId();
    error DuplicateId();

    // -----------------------------------------------------------------------
    // View functions
    // -----------------------------------------------------------------------

    // NOTE: underlying(), rate(), decimals() inherited from ERC7984ERC20Wrapper.
    // NOTE: finalizeUnwrap() inherited from ERC7984ERC20Wrapper (OZ flow).

    function getDepositsLength() external view returns (uint256);

    // -----------------------------------------------------------------------
    // Abstract lifecycle — children MUST implement
    // -----------------------------------------------------------------------

    /// @notice Finalize pending deposits, minting their homomorphic sum to `recipient`.
    /// @param ids Finalization units — implementation-defined: deposit indices (flat wrapper) or
    ///        batch ids (batched wrapper). MUST be strictly increasing (no duplicates).
    function finalizeWrap(uint256[] calldata ids, address recipient) external;

    /// @notice Initiate unwrap (burn confidential tokens). The unwrap handle is available
    ///         from OZ's `UnwrapRequested(receiver, amount)` event — it is NOT returned.
    ///         On-chain callers must parse the event from the receipt to get the handle.
    function initUnwrap(externalEuint64 encryptedAmount, bytes calldata inputProof, address destination) external;
    function initUnwrap(uint64 compressedAmount, address destination) external;

}
