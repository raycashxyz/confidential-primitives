// SPDX-License-Identifier: MIT
pragma solidity ^0.8.27;

import {FHE, euint64, eaddress, externalEaddress} from "@fhevm/solidity/lib/FHE.sol";
import {ZamaEthereumConfig} from "@fhevm/solidity/config/ZamaConfig.sol";
import {IERC20} from "@openzeppelin/contracts/interfaces/IERC20.sol";
import {SafeERC20} from "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import {ReentrancyGuard} from "@openzeppelin/contracts/utils/ReentrancyGuard.sol";
import {IERC7984ERC20Wrapper} from "@openzeppelin/confidential-contracts/interfaces/IERC7984ERC20Wrapper.sol";
import {IStealthWrapAdapter} from "../../interfaces/IStealthWrapAdapter.sol";
import {FHEUtils} from "../../fhe/FHEUtils.sol";

/**
 * @title StealthWrapAdapter
 * @author Valerio Leo (@valeriohq)
 * @author Pavlos Polianidis (@ppoliani)
 * @notice Abstract base for stealth wrap adapters over an existing ERC7984ERC20Wrapper.
 *
 *         This contract does not implement an ERC7984 token. It escrows confidential
 *         balances of `CONFIDENTIAL_WRAPPER`: initWrap pulls clear ERC20 from the
 *         depositor, wraps it into confidential balance owned by this contract, and
 *         records an encrypted recipient. finalizeWrap variants homomorphically select
 *         matching deposits and transfer the resulting confidential balance to the
 *         cleartext recipient.
 *
 *         REENTRANCY: {_wrapIntoEscrow} and {_transferWrapped} make external calls
 *         (safeTransferFrom / wrap / confidentialTransfer) BEFORE the caller records its own
 *         state (deposit entries, nullifiers). Implementations MUST therefore guard their public
 *         {initWrap} and {finalizeWrap} with `nonReentrant`, as the bundled adapters do.
 */
abstract contract StealthWrapAdapter is IStealthWrapAdapter, ZamaEthereumConfig, ReentrancyGuard {
    using SafeERC20 for IERC20;

    IERC7984ERC20Wrapper public immutable CONFIDENTIAL_WRAPPER;
    euint64 public immutable E_ZERO;

    constructor(IERC7984ERC20Wrapper confidentialWrapper_) {
        if (address(confidentialWrapper_) == address(0)) revert ZeroAddress();

        address underlying_ = confidentialWrapper_.underlying();
        if (underlying_ == address(0)) revert ZeroAddress();

        // rate() is the wrap divisor used in _wrapIntoEscrow (`amount % rate`); a zero rate
        // would panic on every deposit. A valid OZ ERC7984ERC20Wrapper never returns 0.
        if (confidentialWrapper_.rate() == 0) revert InvalidRate();

        CONFIDENTIAL_WRAPPER = confidentialWrapper_;

        E_ZERO = FHE.asEuint64(0);
        FHE.allowThis(E_ZERO);
    }

    function confidentialWrapper() external view returns (address) {
        return address(CONFIDENTIAL_WRAPPER);
    }

    function underlying() public view returns (address) {
        return CONFIDENTIAL_WRAPPER.underlying();
    }

    function rate() public view returns (uint256) {
        return CONFIDENTIAL_WRAPPER.rate();
    }

    /**
     * @dev Import a depositor-submitted encrypted recipient. Every deposit path must import through
     *      here. The import grants this adapter transient access only. Persist it with
     *      `FHE.allowThis` where the handle is stored.
     */
    function _verifyRecipient(externalEaddress eRecipient, bytes calldata inputProof) internal returns (eaddress) {
        return FHEUtils.fromExternalForThis(eRecipient, inputProof, msg.sender);
    }

    /// @dev External calls (safeTransferFrom / wrap) run before the caller records its deposit,
    ///      so callers MUST be `nonReentrant` (see the contract-level REENTRANCY note).
    function _wrapIntoEscrow(address depositor, uint256 amount) internal returns (uint256 wrappedUnderlying, euint64 wrappedAmount) {
        if (amount == 0) revert ZeroAmount();

        uint256 rate_ = CONFIDENTIAL_WRAPPER.rate();
        wrappedUnderlying = amount - (amount % rate_);
        if (wrappedUnderlying == 0) revert ZeroAmount();

        IERC20 token = IERC20(CONFIDENTIAL_WRAPPER.underlying());
        token.safeTransferFrom(depositor, address(this), wrappedUnderlying);
        token.forceApprove(address(CONFIDENTIAL_WRAPPER), wrappedUnderlying);

        wrappedAmount = CONFIDENTIAL_WRAPPER.wrap(address(this), wrappedUnderlying);
        FHE.allowThis(wrappedAmount);
    }

    /// @dev Makes an external `confidentialTransfer`, so callers MUST be `nonReentrant`.
    function _transferWrapped(address recipient, euint64 amount) internal returns (euint64 transferred) {
        FHE.allowThis(amount);
        FHE.allow(amount, address(CONFIDENTIAL_WRAPPER));
        transferred = CONFIDENTIAL_WRAPPER.confidentialTransfer(recipient, amount);
        FHE.allowThis(transferred);
    }

    function finalizeWrap(uint256[] calldata ids, address recipient) external virtual;
}
