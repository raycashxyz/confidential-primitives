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
 * @notice Stealth wrap adapter over one shared pool. Deposits accumulate continuously and are
 *         finalized against caller-selected ids, so the caller chooses the anonymity set and
 *         `minDecoys` enforces only its size.
 *
 * @dev Two properties of that design, neither of which the contract can check.
 *
 *      Cold start. Finalization needs at least `minDecoys` deposits in the pool and {initWrap} has
 *      no such floor, so the first `minDecoys - 1` depositors wait. A depositor can fund the missing
 *      deposits themselves, but {WrapInitiated} publishes depositor and amount, so that run is
 *      attributable to them. Seed the pool at deployment, or accept the wait.
 *
 *      Spent slots. A matched deposit's `amount` is rewritten to an encrypted zero, but the slot
 *      stays a legal id and is publicly indistinguishable from a live one. An early sybil can seed
 *      the pool, drain their own deposits and leave a victim whose id sets are mostly attacker-owned,
 *      which links {WrapInitiated} to {WrapFinalized}. Choosing ids well is the caller's job.
 */
contract ContinuousStealthWrapAdapter is StealthWrapAdapter {
    /// @dev Hard cap on the decoy floor. `minDecoys` is a minimum every finalize must scan, so a
    ///      floor above what one transaction can execute would strand every deposit. Fewer ids
    ///      revert `TooFewDecoys`, more revert on the FHEVM budget, and `minDecoys` is immutable.
    ///
    ///      Finalize costs a fixed 227,000 HCU per slot (scalar `eq` on Uint160, payout `select`,
    ///      zeroing `select`) plus 162,000 per tree `add`, against the 20M total budget. The tree
    ///      holds depth at 1,144,000 for every N in range. Measured on the coprocessor mocks, 50
    ///      slots finalize and 51 revert against the bare mock wrapper, the difference being the
    ///      wrapper's own transfer work, which spends from the same budget. 40 keeps about 20%
    ///      headroom below that cliff. A hooked wrapper's modules add to the same budget and can be
    ///      installed after deposits are escrowed. Callers may still pass more ids than this and
    ///      pay for them.
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
            // Scalar `eq`. `recipient` is public calldata, so encrypting it first would buy nothing
            // and cost 20,000 HCU more per slot, and slots are the anonymity set. The scalar path
            // skips the operand type check, which is safe only because every stored handle was
            // imported through {_verifyRecipient} and type-checked as Uint160 by the coprocessor.
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
