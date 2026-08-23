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
 * @notice Continuous stealth wrap adapter for an existing ERC7984ERC20Wrapper.
 *
 *         Deposits accumulate in one shared pool and are finalized by
 *         caller-selected ids. This gives maximum flexibility, but the caller
 *         controls the decoy set quality; `minDecoys` only enforces a lower bound.
 */
contract ContinuousStealthWrapAdapter is StealthWrapAdapter {
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
