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
 *
 *         `minDecoys` IS A COUNT OF IDS, NOT A MEASURE OF PRIVACY. Two consequences worth knowing
 *         before choosing it, neither of which the contract can check:
 *
 *         - COLD START. Finalization needs at least `minDecoys` existing deposits, but {initWrap}
 *           has no matching floor: it escrows funds happily into a pool too small to finalize from.
 *           The first `minDecoys - 1` depositors in a quiet deployment simply wait. They are not
 *           stuck — {initWrap} is permissionless, so a depositor can fund the missing deposits
 *           themselves — but {WrapInitiated} publishes depositor and clear amount, so self-help
 *           means creating a visible run of deposits attributable to them, which costs exactly the
 *           privacy they came for. Seed the pool at deployment, or accept the wait.
 *
 *         - SPENT SLOTS STILL COUNT. A matched deposit's `amount` is rewritten to an encrypted
 *           zero, but the slot stays in the push-only array and remains a legal id forever. It is
 *           also publicly indistinguishable from a live one — `amount` is still a handle and
 *           `originalAmount` never changes. So an early sybil can seed the pool, drain their own
 *           deposits, and leave a victim whose only legal id sets are mostly attacker-owned; the
 *           attacker then knows which ids are not the recipient's and links {WrapInitiated} to
 *           {WrapFinalized}. Choosing ids well is the defence, and it is the caller's job —
 *           `ids.length >= minDecoys` says nothing about how many of them are real.
 */
contract ContinuousStealthWrapAdapter is StealthWrapAdapter {
    /// @dev Hard cap on the configurable decoy floor. `minDecoys` is a MINIMUM: every finalize must
    ///      scan at least that many ids, so a floor above what one transaction can execute leaves a
    ///      deployment where deposits still succeed but NO legal `ids` array can ever be finalized —
    ///      fewer ids revert `TooFewDecoys`, more revert on the FHEVM budget. `minDecoys` is
    ///      immutable and there is no alternative finalization path, so those funds are stuck.
    ///
    ///      finalize does a fixed amount of FHE work per slot — scalar `eq` on Uint160 (117,000) +
    ///      payout `select` (55,000) + zeroing `select` (55,000) = 227,000 HCU, the `eq` being the
    ///      SCALAR cost because the recipient is cleartext (see {finalizeWrap}) — plus (N-1) tree
    ///      `add`s at 162,000. So the binding limit is the 20M TOTAL-HCU/tx budget, not the 5M DEPTH
    ///      cap: the tree holds depth at 1,144,000 (23% of that cap) for every N in range.
    ///
    ///      Where it actually runs out, measured on the FHEVM coprocessor mocks: 50 slots finalizes
    ///      and 51 REVERTS against the bare mock wrapper. The adapter's own work alone would fit 51
    ///      (`389,000N - 162,000`, so 19,677,000 at N=51 against a cap enforced as `>=`); the
    ///      one-slot difference IS the wrapper's own transfer work, which spends from the same
    ///      budget. 40 keeps ~20% headroom below that measured cliff, because a bare mock is the
    ///      cheapest wrapper there is — a hooked wrapper's modules add to the same budget and can be
    ///      installed after deposits are escrowed (see the README's wrapper-compatibility note).
    ///
    ///      This bounds only the configurable FLOOR. A caller may still pass more ids than this and
    ///      pay for them, which is their own sizing decision.
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
