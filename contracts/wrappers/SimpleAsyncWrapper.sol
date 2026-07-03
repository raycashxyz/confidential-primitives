// SPDX-License-Identifier: MIT
pragma solidity ^0.8.27;

import {FHE, euint64, externalEuint64, eaddress, externalEaddress} from "@fhevm/solidity/lib/FHE.sol";
import {IERC20} from "@openzeppelin/contracts/interfaces/IERC20.sol";
import {SafeERC20} from "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import {ERC7984AsyncWrapper} from "./ERC7984AsyncWrapper.sol";

/**
 * @title SimpleAsyncWrapper
 * @notice Minimal concrete {ERC7984AsyncWrapper}: deposits are pulled directly via
 *         IERC20.transferFrom — the depositor approves the wrapper first, then anyone
 *         can pull `amount` from them into a deposit.
 *
 *         No AccessControl, hooks, CREATE2 depositors, withdrawal escape hatch, or
 *         `_update` override — finalizeWrap / initUnwrap delegate straight to the base
 *         internals. It finalizes with the base's "rewrite" strategy (each matched
 *         deposit's encrypted amount is zeroed in storage), serving as the reference
 *         point for comparing finalize gas against {BatchedAsyncWrapper}.
 */
contract SimpleAsyncWrapper is ERC7984AsyncWrapper {
    using SafeERC20 for IERC20;

    uint256 public immutable minDecoys;

    constructor(
        IERC20 _underlying,
        uint256 _minDecoys
    )
        ERC7984AsyncWrapper(_underlying, "Simple Confidential Wrapped", "scWRAP")
    {
        if (_minDecoys == 0) revert InvalidMinDecoys();
        minDecoys = _minDecoys;
    }

    // -----------------------------------------------------------------------
    // initWrap: pull tokens via transferFrom + record deposit
    // -----------------------------------------------------------------------

    /**
     * @notice Record a deposit by pulling `amount` underlying from `from`.
     *         `from` must have approved this wrapper for at least `amount`.
     * @param from Depositor to pull tokens from (also recorded as the deposit owner).
     * @param encryptedRecipient FHE-encrypted recipient address.
     * @param inputProof Proof binding the encrypted recipient to (this, msg.sender).
     * @param amount Cleartext amount of underlying to deposit.
     * @return depositIndex Index of the newly recorded deposit.
     */
    function initWrap(
        address from,
        externalEaddress encryptedRecipient,
        bytes calldata inputProof,
        uint256 amount
    ) external returns (uint256 depositIndex) {
        if (amount == 0) revert ZeroAmount();
        eaddress verified = FHE.fromExternal(encryptedRecipient, inputProof);
        IERC20(address(underlying())).safeTransferFrom(from, address(this), amount);
        depositIndex = _initWrap(from, amount, verified, "");
    }

    // -----------------------------------------------------------------------
    // Implement abstract externals
    // -----------------------------------------------------------------------

    function finalizeWrap(
        uint256[] calldata depositIndices,
        address recipient
    ) external override {
        _finalizeWrap(depositIndices, recipient, minDecoys);
    }

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

    function initUnwrap(
        uint64 compressedAmount,
        address destination
    ) external override {
        if (destination == address(0)) revert ZeroAddress();
        if (compressedAmount == 0) revert ZeroAmount();
        euint64 amount = FHE.asEuint64(compressedAmount);
        FHE.allowThis(amount);
        _unwrap(msg.sender, destination, amount);
    }
}
