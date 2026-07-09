// SPDX-License-Identifier: MIT
pragma solidity ^0.8.27;

import {FHE, euint64} from "@fhevm/solidity/lib/FHE.sol";
import {ZamaEthereumConfig} from "@fhevm/solidity/config/ZamaConfig.sol";
import {IERC20} from "@openzeppelin/contracts/interfaces/IERC20.sol";
import {SafeERC20} from "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import {ReentrancyGuard} from "@openzeppelin/contracts/utils/ReentrancyGuard.sol";
import {IERC7984ERC20Wrapper} from "@openzeppelin/confidential-contracts/interfaces/IERC7984ERC20Wrapper.sol";
import {IERC7984AsyncWrapper} from "../../interfaces/IERC7984AsyncWrapper.sol";

/**
 * @title ERC7984AsyncWrapper
 * @notice Abstract async privacy layer for an existing ERC7984ERC20Wrapper.
 *
 *         This contract does not implement an ERC7984 token. It escrows confidential
 *         balances of `CONFIDENTIAL_WRAPPER`: initWrap pulls clear ERC20 from the
 *         depositor, wraps it into confidential balance owned by this contract, and
 *         records an encrypted recipient. finalizeWrap variants homomorphically select
 *         matching deposits and transfer the resulting confidential balance to the
 *         cleartext recipient.
 */
abstract contract ERC7984AsyncWrapper is IERC7984AsyncWrapper, ZamaEthereumConfig, ReentrancyGuard {
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

    function _transferWrapped(address recipient, euint64 amount) internal returns (euint64 transferred) {
        FHE.allowThis(amount);
        FHE.allow(amount, address(CONFIDENTIAL_WRAPPER));
        transferred = CONFIDENTIAL_WRAPPER.confidentialTransfer(recipient, amount);
        FHE.allowThis(transferred);
    }

    /**
     * @dev Reduce `xs` to a single encrypted sum with a pairwise binary-tree reduction.
     *      This keeps FHE dependency depth at O(log N), unlike a serial accumulator.
     */
    function _sumTree(euint64[] memory xs) internal virtual returns (euint64) {
        uint256 n = xs.length;
        if (n == 0) return E_ZERO;

        while (n > 1) {
            uint256 half = (n + 1) >> 1;
            for (uint256 i = 0; i < half; i++) {
                uint256 l = i << 1;
                uint256 r = l + 1;
                xs[i] = r < n ? FHE.add(xs[l], xs[r]) : xs[l];
            }
            n = half;
        }

        return xs[0];
    }

    function finalizeWrap(uint256[] calldata ids, address recipient) external virtual;
}
