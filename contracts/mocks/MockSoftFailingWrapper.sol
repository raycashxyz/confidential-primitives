// SPDX-License-Identifier: MIT
pragma solidity ^0.8.27;

import {FHE, euint64, ebool} from "@fhevm/solidity/lib/FHE.sol";
import {IERC20} from "@openzeppelin/contracts/interfaces/IERC20.sol";
import {MockERC7984ERC20Wrapper} from "./MockERC7984ERC20Wrapper.sol";

/**
 * @dev A wrapper that can be told to SOFT-FAIL a transfer, moving less than requested while the
 *      transaction still succeeds. That is the ERC-7984 behavior issue #34 is about, where a freeze,
 *      pause, blacklist or hook veto returns an encrypted zero or partial instead of reverting.
 *      OpenZeppelin's own `confidentialTransfer` is already exact-or-zero via `FHESafeMath`, so this
 *      only makes that reducible on demand for the retry-safety regression tests.
 *
 *      The reduction is applied in `_update`, the single mover behind wrap/unwrap/transfer. Tests set
 *      the mode AFTER depositing, so only the finalize transfer is affected:
 *        - mode 0: normal (exact).
 *        - mode 1, block: moves an encrypted zero, as on a freeze, pause or blacklist.
 *        - mode 2, partial: moves `min(requested, partialAmount)`, so it never moves more than
 *          asked, exactly like a real soft-failing transfer.
 *        - mode 3, over-report: moves the correct amount but RETURNS `moved + partialAmount`. No
 *          honest wrapper does this. It exists to pin {BatchedStealthWrapAdapter}'s clamp, which
 *          keeps `claimed <= matched` from depending on the wrapper's return value being truthful.
 */
contract MockSoftFailingWrapper is MockERC7984ERC20Wrapper {
    uint8 public failMode;
    uint64 public partialAmount;

    constructor(IERC20 underlying_, string memory name_, string memory symbol_)
        MockERC7984ERC20Wrapper(underlying_, name_, symbol_)
    {}

    function setFailMode(uint8 mode_, uint64 partialAmount_) external {
        failMode = mode_;
        partialAmount = partialAmount_;
    }

    function _update(address from, address to, euint64 amount) internal override returns (euint64) {
        if (failMode == 1) {
            euint64 zero = FHE.asEuint64(0);
            FHE.allowThis(zero);
            return super._update(from, to, zero);
        }
        if (failMode == 2) {
            // min(requested, partialAmount), since a soft-fail never moves MORE than asked.
            euint64 cap = FHE.asEuint64(partialAmount);
            ebool within = FHE.le(amount, cap);
            euint64 capped = FHE.select(within, amount, cap);
            FHE.allowThis(capped);
            return super._update(from, to, capped);
        }
        if (failMode == 3) {
            // Moves honestly, lies about how much. The adapter must not credit the inflated figure.
            euint64 moved = super._update(from, to, amount);
            euint64 inflated = FHE.add(moved, FHE.asEuint64(partialAmount));
            // Mirror the grants `_update` makes on a real result, or the caller cannot use the
            // handle at all and the lie fails for the wrong reason.
            FHE.allowThis(inflated);
            FHE.allow(inflated, msg.sender);
            if (from != address(0)) FHE.allow(inflated, from);
            if (to != address(0)) FHE.allow(inflated, to);
            return inflated;
        }
        return super._update(from, to, amount);
    }
}
