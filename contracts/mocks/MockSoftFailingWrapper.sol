// SPDX-License-Identifier: MIT
pragma solidity ^0.8.27;

import {FHE, euint64, ebool} from "@fhevm/solidity/lib/FHE.sol";
import {IERC20} from "@openzeppelin/contracts/interfaces/IERC20.sol";
import {MockERC7984ERC20Wrapper} from "./MockERC7984ERC20Wrapper.sol";

/**
 * @dev A wrapper that can be told to SOFT-FAIL a transfer — move less than requested while the
 *      transaction still succeeds — which is the ERC-7984 behavior issue #34 is about (a freeze,
 *      pause, blacklist, or hook veto returns an encrypted zero or partial instead of reverting).
 *      OpenZeppelin's own `confidentialTransfer` is already exact-or-zero via `FHESafeMath`, so this
 *      only makes that reducible on demand for the retry-safety regression tests.
 *
 *      The reduction is applied in `_update`, the single mover behind wrap/unwrap/transfer. Tests set
 *      the mode AFTER depositing, so only the finalize transfer is affected:
 *        - mode 0: normal (exact).
 *        - mode 1: block — move an encrypted zero (freeze / pause / blacklist).
 *        - mode 2: partial — move `min(requested, partialAmount)`, so it never moves more than
 *          asked, exactly like a real soft-failing transfer.
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
            // min(requested, partialAmount): a soft-fail never moves MORE than asked.
            euint64 cap = FHE.asEuint64(partialAmount);
            ebool within = FHE.le(amount, cap);
            euint64 capped = FHE.select(within, amount, cap);
            FHE.allowThis(capped);
            return super._update(from, to, capped);
        }
        return super._update(from, to, amount);
    }
}
