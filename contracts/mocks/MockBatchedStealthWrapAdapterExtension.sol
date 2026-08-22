// SPDX-License-Identifier: MIT
pragma solidity ^0.8.27;

import {eaddress, externalEaddress, euint64} from "@fhevm/solidity/lib/FHE.sol";
import {IERC7984ERC20Wrapper} from "@openzeppelin/confidential-contracts/interfaces/IERC7984ERC20Wrapper.sol";
import {BatchedStealthWrapAdapter} from "../adapters/BatchedStealthWrapAdapter.sol";

/// @dev Test-only extension exercising BatchedStealthWrapAdapter's deposit hooks.
contract MockBatchedStealthWrapAdapterExtension is BatchedStealthWrapAdapter {
    error FinalizeOverrideCalled();

    constructor(
        uint256 maxBatchDeposits_,
        uint256 sealDelay_,
        IERC7984ERC20Wrapper confidentialWrapper_
    ) BatchedStealthWrapAdapter(maxBatchDeposits_, sealDelay_, confidentialWrapper_) {}

    function initWrap(
        uint256 amount,
        externalEaddress eRecipient,
        bytes calldata inputProof
    ) external override nonReentrant returns (uint256 slot) {
        eaddress verifiedRecipient = _verifyRecipient(eRecipient, inputProof);
        (uint256 wrappedUnderlying, euint64 eAmount) = _wrapIntoEscrow(msg.sender, amount);
        slot = _recordBatchedDeposit(msg.sender, wrappedUnderlying, eAmount, verifiedRecipient);
    }

    function initWrapFor(
        address depositor,
        uint256 amount,
        externalEaddress eRecipient,
        bytes calldata inputProof
    ) external nonReentrant returns (uint256 slot) {
        eaddress verifiedRecipient = _verifyRecipient(eRecipient, inputProof);
        (uint256 wrappedUnderlying, euint64 eAmount) = _wrapIntoEscrow(depositor, amount);
        slot = _recordBatchedDeposit(depositor, wrappedUnderlying, eAmount, verifiedRecipient);
    }

    /// @dev The escrow helpers reached without `nonReentrant`. Each must revert
    ///      `ReentrancyGuardRequired` before doing anything else.
    function wrapUnguarded(uint256 amount) external returns (uint256 wrappedUnderlying, euint64 eAmount) {
        return _wrapIntoEscrow(msg.sender, amount);
    }

    function recordUnguarded(uint256 amount) external returns (uint256 slot) {
        return _recordBatchedDeposit(msg.sender, amount, E_ZERO, eaddress.wrap(0));
    }

    function transferUnguarded(address recipient) external returns (euint64 transferred) {
        return _transferWrapped(recipient, E_ZERO);
    }

    function finalizeWrap(uint256[] calldata ids, address) external override nonReentrant {
        if (ids.length == 0) revert FinalizeOverrideCalled();
    }
}
