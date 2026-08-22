// SPDX-License-Identifier: MIT
pragma solidity ^0.8.27;

import {IERC7984ERC20Wrapper} from "@openzeppelin/confidential-contracts/interfaces/IERC7984ERC20Wrapper.sol";
import {BatchedStealthWrapAdapter} from "../adapters/BatchedStealthWrapAdapter.sol";

/**
 * @dev Reference override of the recipient-handle freshness policy, and the regression test for that
 *      extension point. Models the CREATE2 deposit-address case described on
 *      {StealthWrapAdapter-_consumeRecipientHandle}: the deposit address is derived with
 *      `salt == handle`, so the handle cannot be rotated without breaking the only binding that tells
 *      the payer which recipient the address commits to. A second transfer to a live deposit address
 *      must therefore be wrappable under the same handle.
 *
 *      DEPOSITS MADE THROUGH AN ADAPTER LIKE THIS ARE PUBLICLY LINKABLE BY RECIPIENT. That is not a
 *      regression, because the payer's clear ERC-20 transfer to the public deposit address already clusters
 *      them before `initWrap` runs, so single-use would forbid the reuse without concealing anything.
 *      What it would cost is the recovery path. See the hook's docs for why re-wrapping under a
 *      fresh handle can be neither authenticated nor made safe, leaving a cleartext sweep that
 *      doxxes the first deposit. Do not point a flow needing unlinkability at this shape.
 */
contract MockReusableHandleAdapter is BatchedStealthWrapAdapter {
    constructor(
        uint256 maxBatchDeposits_,
        uint256 sealDelay_,
        IERC7984ERC20Wrapper confidentialWrapper_
    ) BatchedStealthWrapAdapter(maxBatchDeposits_, sealDelay_, confidentialWrapper_) {}

    /// @dev Reuse permitted. Still recorded, so `recipientHandleUsed` reports history honestly. The
    ///      repeat itself is already public in `WrapInitiated`, so no extra event is warranted.
    function _consumeRecipientHandle(bytes32 handle) internal override {
        _recordRecipientHandle(handle);
    }
}
