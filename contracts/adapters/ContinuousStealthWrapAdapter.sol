// SPDX-License-Identifier: MIT
pragma solidity ^0.8.27;

import {FHE, euint64, ebool, eaddress, externalEaddress} from "@fhevm/solidity/lib/FHE.sol";
import {IERC7984ERC20Wrapper} from "@openzeppelin/confidential-contracts/interfaces/IERC7984ERC20Wrapper.sol";
import {StealthWrapAdapter} from "./base/StealthWrapAdapter.sol";
import {FHEUtils} from "../fhe/FHEUtils.sol";

/**
 * @title ContinuousStealthWrapAdapter
 * @author Valerio Leo (@valeriohq)
 * @author Pavlos Polianidis (@ppoliani)
 * @notice Stealth wrap adapter over one shared pool. Deposits accumulate continuously and become
 *         finalizable once the pool holds at least `minDecoys` of them. The caller chooses which
 *         ids form the anonymity set, and `minDecoys` enforces only its size.
 */
contract ContinuousStealthWrapAdapter is StealthWrapAdapter {
    /// @dev `minDecoys` is zero or above the largest scan one transaction can execute.
    error InvalidMinDecoys();
    /// @dev The finalize id set is smaller than `minDecoys`.
    error TooFewDecoys();

    /// @dev Hard cap on the decoy floor. `minDecoys` is a minimum every finalize must scan, so a
    ///      floor above what one transaction can execute would strand every deposit. Fewer ids
    ///      revert `TooFewDecoys`, more revert on the FHEVM budget, and `minDecoys` is immutable.
    uint256 private constant MAX_MIN_DECOYS = 40;

    uint256 public immutable minDecoys;

    struct Deposit {
        address depositor;
        uint256 originalAmount;
        euint64 amount;
        eaddress recipient;
    }

    event WrapInitiated(
        uint256 indexed depositIndex,
        address indexed depositor,
        uint256 amount,
        bytes32 encryptedRecipientHandle
    );
    event WrapFinalized(address indexed recipient, bytes32 amount, uint256[] ids);

    Deposit[] public deposits;

    constructor(IERC7984ERC20Wrapper confidentialWrapper_, uint256 _minDecoys)
        StealthWrapAdapter(confidentialWrapper_)
    {
        if (_minDecoys == 0 || _minDecoys > MAX_MIN_DECOYS) revert InvalidMinDecoys();
        minDecoys = _minDecoys;
    }

    function getDepositsLength() external view override returns (uint256) {
        return deposits.length;
    }

    /// @param extraData Must be empty. This adapter takes no options.
    function initWrap(
        uint256 amount,
        externalEaddress encryptedRecipient,
        bytes calldata inputProof,
        bytes calldata extraData
    ) external override nonReentrant returns (uint256 depositIndex) {
        if (extraData.length != 0) revert InvalidExtraData();
        eaddress verifiedRecipient = _verifyRecipient(encryptedRecipient, inputProof);
        if (!FHEUtils.isFreshForThis(FHE.toBytes32(verifiedRecipient))) revert RecipientHandleAlreadyUsed();
        (uint256 wrappedUnderlying, euint64 encryptedAmount) = _wrapIntoEscrow(msg.sender, amount);
        FHE.allowThis(verifiedRecipient);

        deposits.push(
            Deposit({
                depositor: msg.sender,
                originalAmount: wrappedUnderlying,
                amount: encryptedAmount,
                recipient: verifiedRecipient
            })
        );

        depositIndex = deposits.length - 1;
        emit WrapInitiated(depositIndex, msg.sender, wrappedUnderlying, FHE.toBytes32(verifiedRecipient));
    }

    /**
     * @notice Match the caller-chosen `ids` against `recipient`, transfer the encrypted sum and zero
     *         each matched deposit so it cannot pay again.
     * @dev Requires an exact-or-revert wrapper. Matched deposits are zeroed before the transfer, so
     *      a wrapper that soft-fails, moving zero or part on a freeze, pause or hook veto, consumes
     *      the claim and strands the funds. The id set is caller-chosen over a flat pool, so there is
     *      no stable unit to keep a claimed ledger against and a partial transfer cannot be
     *      attributed back to individual deposits. See {BatchedStealthWrapAdapter} for the
     *      retry-safe design.
     * @param ids Deposit indices to scan. Must be strictly increasing and at least `minDecoys` long.
     * @param recipient Address to match deposits against and transfer to.
     */
    function finalizeWrap(uint256[] calldata ids, address recipient) external override nonReentrant {
        if (ids.length < minDecoys) revert TooFewDecoys();
        if (recipient == address(0)) revert ZeroAddress();

        euint64[] memory payouts = new euint64[](ids.length);

        uint256 prevIndex;
        for (uint256 k = 0; k < ids.length; k++) {
            uint256 i = ids[k];
            if (i >= deposits.length) revert InvalidId();
            if (k > 0 && i <= prevIndex) revert DuplicateId();
            prevIndex = i;

            Deposit storage d = deposits[i];
            ebool isMatch = FHE.eq(d.recipient, recipient);
            payouts[k] = FHE.select(isMatch, d.amount, E_ZERO);

            d.amount = FHE.select(isMatch, E_ZERO, d.amount);
            FHE.allowThis(d.amount);
        }

        euint64 total = FHEUtils.sum(payouts);
        euint64 transferred = _transferWrapped(recipient, total);

        emit WrapFinalized(recipient, FHE.toBytes32(transferred), ids);
    }
}
