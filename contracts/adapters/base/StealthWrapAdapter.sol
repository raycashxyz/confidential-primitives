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
 *
 * @dev Recipient privacy. The recipient encrypts their own address with the input proof bound to
 *      the depositor and hands (handle, proof) to the depositor, who submits it. {_verifyRecipient}
 *      imports the handle through {FHEUtils-fromExternal}, which grants ACL access to this adapter
 *      only, so neither observers nor a contract depositor can read the recipient. Handles are
 *      single-use by default, see {_consumeRecipientHandle}.
 *
 *      Depositor trust. Importing a handle proves it is well-formed and bound, not which address it
 *      encrypts. A recipient who supplies an encryption of another address redirects the payment,
 *      and one who supplies the zero address destroys it, since {finalizeWrap} rejects `address(0)`.
 *      Treat a payment request as an authenticated message from the payee.
 *
 *      Exit amounts. Deposit amounts are public and rounded to the wrapper's `rate()`, and the
 *      finalize event names the scanned set. A recipient who unwraps exactly what they were paid
 *      lets anyone search the scanned amounts for the subset that sums to it.
 *
 *      Supported wrappers. ERC-7984 lets `wrap` and `confidentialTransfer` soft-fail, moving zero
 *      or less than requested while the transaction succeeds. A soft-failing `wrap` would leave the
 *      underlying with the wrapper and a zero-valued deposit here, with no refund path, so the
 *      wrapper must be exact-or-revert on `wrap`. On finalize the requirement depends on the
 *      adapter. The batched one is retry-safe, the continuous one also needs exact-or-revert on
 *      `confidentialTransfer`. A bare OpenZeppelin `ERC7984ERC20Wrapper` qualifies. A hooked one is
 *      as safe as the modules its admin can install.
 *
 *      Reentrancy. {_wrapIntoEscrow} calls out before the caller records its deposit and
 *      {_transferWrapped} calls out next to the claim commit, so both must run inside a
 *      `nonReentrant` entrypoint.
 */
abstract contract StealthWrapAdapter is IStealthWrapAdapter, ZamaEthereumConfig, ReentrancyGuard {
    using SafeERC20 for IERC20;
    using FHEUtils for FHEUtils.HandleSet;

    IERC7984ERC20Wrapper public immutable CONFIDENTIAL_WRAPPER;
    euint64 public immutable E_ZERO;

    /// @dev Recipient handles that have already funded a deposit.
    FHEUtils.HandleSet internal _recipientHandles;

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

    /// @notice Whether an encrypted-recipient handle has already funded a deposit here. Reports
    ///         history. An adapter that permits reuse still returns `true` for a handle it accepts again.
    function recipientHandleUsed(bytes32 handle) external view returns (bool) {
        return !_recipientHandles.isFresh(handle);
    }

    /**
     * @dev Import a depositor-submitted encrypted recipient and consume its handle. Every deposit
     *      path must import through here. The import grants this adapter transient access only.
     *      The caller persists it with `FHE.allowThis` where it stores the handle.
     *
     *      The coprocessor checks the handle's type against `Uint160`, which keeps a wrong-typed
     *      handle out of the `eaddress` slot. A `Bool` handle would otherwise compare equal to every
     *      non-zero recipient under the scalar `FHE.eq` and drain the pool, a `euint64` handle
     *      chained onto another slot's payout would push finalize past the FHEVM depth budget, and
     *      any other type would make the continuous adapter's `FHE.eq` revert for every id set
     *      naming the slot.
     */
    function _verifyRecipient(externalEaddress eRecipient, bytes calldata inputProof) internal returns (eaddress recipient) {
        recipient = FHEUtils.fromExternal(eRecipient, inputProof, msg.sender);
        _consumeRecipientHandle(FHE.toBytes32(recipient));
    }

    /**
     * @dev Single-use policy for recipient handles. The handle is public in the deposit event so
     *      the recipient can spot their payment, which makes a reused one a tag linking deposits to
     *      the same unknown recipient. A fresh encryption of the same address is a different handle,
     *      so a recipient can still be paid any number of times, and the depositor-bound proof means
     *      nobody else can spend a handle.
     *
     *      Override to permit reuse only where the deposit path already links the deposits. The
     *      CREATE2 deposit-address flow is the case. Its address derives from the handle
     *      (`salt == handle`), so the handle cannot rotate, and the payer's clear transfer to that
     *      address clusters the deposits before `initWrap` runs. An override should still call
     *      `_recipientHandles.markUsed(handle)` so {recipientHandleUsed} reports history, and the
     *      adapter must document that its deposits are linkable by recipient.
     */
    function _consumeRecipientHandle(bytes32 handle) internal virtual {
        if (!_recipientHandles.markUsed(handle)) revert RecipientHandleAlreadyUsed();
    }

    /**
     * @dev Pull `amount` underlying from `depositor`, rounded down to the wrapper's rate, and wrap
     *      it into confidential balance held by this adapter. The adapter is the wrapper's
     *      counterparty. A wrapper that gates `wrap` on its caller or recipient sees this adapter,
     *      not the depositor, so such checks belong on the adapter's deposit path instead.
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
    ///      wrapper reports it moved.
    function _transferWrapped(address recipient, euint64 amount) internal returns (euint64 transferred) {
        FHE.allowThis(amount);
        FHE.allow(amount, address(CONFIDENTIAL_WRAPPER));
        transferred = CONFIDENTIAL_WRAPPER.confidentialTransfer(recipient, amount);
        FHE.allowThis(transferred);
    }

    function finalizeWrap(uint256[] calldata ids, address recipient) external virtual;
}
