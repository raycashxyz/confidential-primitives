// SPDX-License-Identifier: MIT
pragma solidity ^0.8.27;

import {IERC7984ERC20Wrapper} from "@openzeppelin/confidential-contracts/interfaces/IERC7984ERC20Wrapper.sol";
import {BatchedStealthWrapAdapter} from "../adapters/BatchedStealthWrapAdapter.sol";
import {FHEUtils} from "../fhe/FHEUtils.sol";

/**
 * @dev Reference override of {StealthWrapAdapter-_consumeRecipientHandle}, and the regression test
 *      for that extension point. Models a CREATE2 deposit-address flow whose address derives from the
 *      handle (`salt == handle`), so a second transfer to a live deposit address must be wrappable
 *      under the same handle.
 *
 *      Deposits made through an adapter like this are publicly linkable by recipient. The payer's
 *      clear ERC-20 transfer to the deposit address already clusters them before `initWrap` runs, so
 *      single-use would forbid the reuse without concealing anything. Do not point a flow that needs
 *      unlinkability at this shape.
 */
contract MockReusableHandleAdapter is BatchedStealthWrapAdapter {
    using FHEUtils for FHEUtils.HandleSet;

    constructor(
        uint256 maxBatchDeposits_,
        uint256 sealDelay_,
        IERC7984ERC20Wrapper confidentialWrapper_
    ) BatchedStealthWrapAdapter(maxBatchDeposits_, sealDelay_, confidentialWrapper_) {}

    /// @dev Reuse permitted. The handle is still recorded so `recipientHandleUsed` reports history.
    function _consumeRecipientHandle(bytes32 handle) internal override {
        _recipientHandles.markUsed(handle);
    }
}
