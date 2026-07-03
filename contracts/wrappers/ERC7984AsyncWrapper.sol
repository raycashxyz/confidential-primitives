// SPDX-License-Identifier: MIT
pragma solidity ^0.8.27;

import {FHE, euint64, externalEuint64, ebool, eaddress, externalEaddress} from "@fhevm/solidity/lib/FHE.sol";
import {ZamaEthereumConfig} from "@fhevm/solidity/config/ZamaConfig.sol";
import {IERC20} from "@openzeppelin/contracts/interfaces/IERC20.sol";
import {SafeERC20} from "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import {SafeCast} from "@openzeppelin/contracts/utils/math/SafeCast.sol";
import {ERC7984} from "@openzeppelin/confidential-contracts/token/ERC7984/ERC7984.sol";
import {ERC7984ERC20Wrapper} from "@openzeppelin/confidential-contracts/token/ERC7984/extensions/ERC7984ERC20Wrapper.sol";
import {IERC7984AsyncWrapper} from "./IERC7984AsyncWrapper.sol";

/**
 * @title ERC7984AsyncWrapper
 * @notice Abstract base for async confidential token wrappers.
 *
 *         Converts cleartext ERC-20 → encrypted ERC-7984 via a two-phase deposit model
 *         with FHE-encrypted recipients and decoy-based privacy.
 *
 *         Shared lifecycle (internal implementations):
 *           - _initWrap / _finalizeWrap — deposit recording + homomorphic matching
 *           - _unwrap / finalizeUnwrap — OZ's native two-phase unwrap (inherited)
 *
 *         Unowned — no AccessControl, no hooks, no withdrawal escape hatch.
 *         Children add their own governance, hooks, and recovery mechanisms.
 *
 *         Inherits ERC7984ERC20Wrapper for underlying(), rate(), decimals(), supply checks,
 *         and the full unwrap lifecycle (_unwrap + finalizeUnwrap).
 *         Disables OZ's wrap(), onTransferReceived(), and public unwrap() overloads.
 */
abstract contract ERC7984AsyncWrapper is IERC7984AsyncWrapper, ZamaEthereumConfig, ERC7984ERC20Wrapper {
    using SafeERC20 for IERC20;

    euint64 public immutable E_ZERO;

    Deposit[] public deposits;

    /// @notice Number of deposits (for tests / off-chain).
    function getDepositsLength() external view returns (uint256) {
        return deposits.length;
    }

    // -----------------------------------------------------------------------
    // Disabled OZ functions
    // -----------------------------------------------------------------------

    /// @dev Disabled — all deposits must go through child-specific initWrap.
    function wrap(address, uint256) public pure override {
        revert ExternalWrapNotSupported();
    }

    /// @dev Disabled — no ERC1363 auto-wrap.
    function onTransferReceived(address, address, uint256, bytes calldata) public pure override returns (bytes4) {
        revert ExternalWrapNotSupported();
    }

    /// @dev Disabled — force through child's initUnwrap for consistent interface.
    function unwrap(address, address, euint64) public pure override {
        revert ExternalWrapNotSupported();
    }

    /// @dev Disabled — force through child's initUnwrap.
    function unwrap(address, address, externalEuint64, bytes calldata) public pure override {
        revert ExternalWrapNotSupported();
    }

    // -----------------------------------------------------------------------
    // Constructor
    // -----------------------------------------------------------------------

    constructor(
        IERC20 _underlying,
        string memory name_,
        string memory symbol_
    )
        ERC7984(name_, symbol_, "")
        ERC7984ERC20Wrapper(_underlying)
    {
        if (address(_underlying) == address(0)) revert ZeroAddress();
        E_ZERO = FHE.asEuint64(0);
        FHE.allowThis(E_ZERO);
    }

    // -----------------------------------------------------------------------
    // _initWrap: record deposit (internal — child calls after acquiring tokens)
    // -----------------------------------------------------------------------

    /**
     * @dev Record a deposit after the child has acquired tokens.
     *      Validates amount, compresses to uint64, creates encrypted Deposit struct.
     *      Child handles FHE proof verification and token acquisition before calling this.
     * @param depositor Address of the deposit source (e.g. CREATE2 depositor, channel).
     * @param amount Cleartext amount of underlying tokens deposited.
     * @param verifiedRecipient Pre-verified FHE-encrypted recipient address.
     * @param data Arbitrary data for extensibility (child-specific context).
     * @return depositIndex The index of the newly recorded deposit.
     */
    function _initWrap(
        address depositor,
        uint256 amount,
        eaddress verifiedRecipient,
        bytes memory data
    ) internal returns (uint256 depositIndex) {
        if (amount == 0) revert ZeroAmount();
        uint64 compressed = SafeCast.toUint64(amount / rate());
        if (compressed == 0) revert ZeroAmount();

        FHE.allowThis(verifiedRecipient);

        euint64 encryptedAmount = FHE.asEuint64(compressed);
        FHE.allowThis(encryptedAmount);

        deposits.push(Deposit({
            depositor: depositor,
            originalAmount: amount,
            amount: encryptedAmount,
            recipient: verifiedRecipient,
            data: data
        }));

        depositIndex = deposits.length - 1;
        emit WrapInitiated(
            depositIndex,
            depositor,
            amount,
            FHE.toBytes32(verifiedRecipient),
            data
        );
    }

    // -----------------------------------------------------------------------
    // _finalizeWrap: homomorphic matching + mint (internal)
    // -----------------------------------------------------------------------

    /**
     * @dev Finalize wrap: homomorphic sum of matching deposits is minted to recipient.
     *      Permissionless — anyone can finalize on behalf of any recipient without leaking information.
     * @param depositIndices Indices of deposits (MUST be strictly increasing, no duplicates).
     * @param recipient Address to check deposit ownership and mint to.
     * @param minDecoysRequired Minimum number of deposit indices required for privacy.
     */
    function _finalizeWrap(
        uint256[] calldata depositIndices,
        address recipient,
        uint256 minDecoysRequired
    ) internal {
        if (depositIndices.length < minDecoysRequired) revert TooFewDecoys();
        if (recipient == address(0)) revert ZeroAddress();

        eaddress encryptedRecipient = FHE.asEaddress(recipient);
        euint64 sum = E_ZERO;

        uint256 prevIndex;
        for (uint256 k = 0; k < depositIndices.length; k++) {
            uint256 i = depositIndices[k];
            if (i >= deposits.length) revert InvalidDepositIndex();
            if (k > 0 && i <= prevIndex) revert DuplicateDepositIndex();
            prevIndex = i;
            Deposit storage d = deposits[i];

            ebool isMatch = FHE.eq(d.recipient, encryptedRecipient);
            euint64 payout = FHE.select(isMatch, d.amount, E_ZERO);
            sum = FHE.add(sum, payout);

            d.amount = FHE.select(isMatch, E_ZERO, d.amount);
            FHE.allowThis(d.amount);
        }

        emit WrapFinalized(
            recipient,
            FHE.toBytes32(sum),
            FHE.toBytes32(confidentialBalanceOf(recipient)),
            depositIndices
        );

        _mint(recipient, sum);
    }

    // -----------------------------------------------------------------------
    // Unwrap: OZ's _unwrap + finalizeUnwrap inherited from ERC7984ERC20Wrapper.
    //
    // Children's initUnwrap calls _unwrap(msg.sender, dest, amount) directly.
    // Children can override finalizeUnwrap to add hooks.
    // Public unwrap() overloads are disabled above.
    // -----------------------------------------------------------------------

    // -----------------------------------------------------------------------
    // Abstract functions — children MUST implement
    // -----------------------------------------------------------------------

    /// @notice Finalize wrap — child adds authorization, passes minDecoys to _finalizeWrap.
    function finalizeWrap(uint256[] calldata depositIndices, address recipient) external virtual;

    /// @notice Step 1 of unwrap (encrypted amount) — child calls _unwrap(msg.sender, dest, amount).
    function initUnwrap(
        externalEuint64 encryptedAmount,
        bytes calldata inputProof,
        address destination
    ) external virtual;

    /// @notice Step 1 of unwrap (compressed amount) — child calls _unwrap(msg.sender, dest, amount).
    function initUnwrap(uint64 compressedAmount, address destination) external virtual;

    // -----------------------------------------------------------------------
    // _update: supply check + core balance (no hooks — children add their own)
    // -----------------------------------------------------------------------

    function _update(address from, address to, euint64 amount)
        internal
        virtual
        override
        returns (euint64)
    {
        // Prevent euint64 overflow on mint. We call ERC7984._update directly (skipping
        // ERC7984ERC20Wrapper._update which has unwrap logic we override), so we must
        // re-add this check manually. Without it, total supply could silently overflow 2^64.
        if (from == address(0)) {
            _checkConfidentialTotalSupply();
        }

        // Core balance update.
        return ERC7984._update(from, to, amount);
    }

}
