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
 * @notice Abstract base for stealth wrap adapters over an existing ERC7984ERC20Wrapper. A deposit
 *         pulls clear ERC-20 from the depositor, wraps it into confidential balance held by this
 *         contract and records an encrypted recipient. {finalizeWrap} homomorphically selects the
 *         deposits matching a cleartext recipient and transfers their encrypted sum.
 */
abstract contract StealthWrapAdapter is IStealthWrapAdapter, ZamaEthereumConfig, ReentrancyGuard {
    using SafeERC20 for IERC20;

    IERC7984ERC20Wrapper public immutable CONFIDENTIAL_WRAPPER;
    euint64 public immutable E_ZERO;

    constructor(IERC7984ERC20Wrapper confidentialWrapper_) {
        if (address(confidentialWrapper_) == address(0)) revert ZeroAddress();

        address underlying_ = confidentialWrapper_.underlying();
        if (underlying_ == address(0)) revert ZeroAddress();

        // `rate()` divides every deposit in {_wrapIntoEscrow}. Zero would panic on each one.
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

    /// @notice Whether an encrypted-recipient handle has already funded a deposit here.
    function recipientHandleUsed(bytes32 handle) external view returns (bool) {
        return !FHEUtils.isFreshForThis(handle);
    }

    /**
     * @dev Import a depositor-submitted encrypted recipient. Every deposit path must import through
     *      here. The import grants this adapter transient access only. Persist it with
     *      `FHE.allowThis` where the handle is stored, which is also what marks it used for
     *      {recipientHandleUsed}.
     */
    function _verifyRecipient(externalEaddress eRecipient, bytes calldata inputProof) internal returns (eaddress) {
        return FHEUtils.fromExternalForThis(eRecipient, inputProof, msg.sender);
    }

    /**
     * @dev Pull `amount` underlying from `depositor`, rounded down to the wrapper's rate, and wrap
     *      it into confidential balance held by this adapter. Call it only from a `nonReentrant`
     *      entrypoint, since it calls out before the caller records the deposit. The wrapper must be
     *      exact-or-revert on `wrap`. A short wrap would leave the underlying with the wrapper and a
     *      zero-valued deposit here. The adapter is the wrapper's counterparty. A wrapper that gates
     *      `wrap` on its caller or recipient sees this adapter, not the depositor, so such checks
     *      belong on the adapter's deposit path instead.
     * @return wrappedUnderlying The underlying amount wrapped.
     * @return wrappedAmount The resulting encrypted balance, persisted to this adapter.
     */
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

    /// @dev Transfer `amount` of escrowed confidential balance to `recipient` and return what the
    ///      wrapper reports it moved. Call it only from a `nonReentrant` entrypoint.
    function _transferWrapped(address recipient, euint64 amount) internal returns (euint64 transferred) {
        FHE.allowThis(amount);
        FHE.allow(amount, address(CONFIDENTIAL_WRAPPER));
        transferred = CONFIDENTIAL_WRAPPER.confidentialTransfer(recipient, amount);
        FHE.allowThis(transferred);
    }

    function finalizeWrap(uint256[] calldata ids, address recipient) external virtual;
}
