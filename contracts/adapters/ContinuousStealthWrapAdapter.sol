// SPDX-License-Identifier: MIT
pragma solidity ^0.8.27;

import {FHE, euint64, ebool, eaddress, externalEaddress} from "@fhevm/solidity/lib/FHE.sol";
import {IERC7984ERC20Wrapper} from "@openzeppelin/confidential-contracts/interfaces/IERC7984ERC20Wrapper.sol";
import {StealthWrapAdapter} from "./base/StealthWrapAdapter.sol";

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
        if (_minDecoys == 0) revert InvalidMinDecoys();
        minDecoys = _minDecoys;
    }

    function getDepositsLength() external view override returns (uint256) {
        return deposits.length;
    }

    function initWrap(
        uint256 amount,
        externalEaddress encryptedRecipient,
        bytes calldata inputProof
    ) external override nonReentrant returns (uint256 depositIndex) {
        eaddress verifiedRecipient = _verifyRecipient(encryptedRecipient, inputProof);
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
            // Scalar overload (cleartext rhs): `recipient` is public calldata, re-emitted indexed
            // in {WrapFinalized}, so trivially encrypting it first bought no confidentiality and
            // cost 20,000 HCU per scanned slot. Since the HCU budget is what bounds `ids.length`,
            // and `ids.length` IS the anonymity set, that was a privacy cost as well as a gas one.
            //
            // The scalar path skips the operand type check, which is only safe because
            // {_verifyRecipient} rejects empty proofs — every stored handle is coprocessor-verified
            // as Uint160. Do not relax that gate while this comparison is scalar.
            ebool isMatch = FHE.eq(d.recipient, recipient);
            payouts[k] = FHE.select(isMatch, d.amount, E_ZERO);

            d.amount = FHE.select(isMatch, E_ZERO, d.amount);
            FHE.allowThis(d.amount);
        }

        euint64 total = _sumTree(payouts);
        euint64 transferred = _transferWrapped(recipient, total);

        emit WrapFinalized(recipient, FHE.toBytes32(transferred), ids);
    }
}
