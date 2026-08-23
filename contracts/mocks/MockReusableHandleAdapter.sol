// SPDX-License-Identifier: MIT
pragma solidity ^0.8.27;

import {FHE, euint64, eaddress, externalEaddress} from "@fhevm/solidity/lib/FHE.sol";
import {IERC7984ERC20Wrapper} from "@openzeppelin/confidential-contracts/interfaces/IERC7984ERC20Wrapper.sol";
import {BatchedStealthWrapAdapter} from "../adapters/BatchedStealthWrapAdapter.sol";

/**
 * @dev Adapter whose deposit path permits recipient-handle reuse, and the regression test for that
 *      freedom. Models a CREATE2 deposit-address flow whose address derives from the handle
 *      (`salt == handle`), so a second transfer to a live deposit address must be wrappable under
 *      the same handle.
 *
 *      Deposits made through an adapter like this are publicly linkable by recipient. The payer's
 *      clear ERC-20 transfer to the deposit address already clusters them before `initWrap` runs, so
 *      single-use would forbid the reuse without concealing anything. Do not point a flow that needs
 *      unlinkability at this shape.
 */
contract MockReusableHandleAdapter is BatchedStealthWrapAdapter {
    constructor(
        uint256 maxBatchDeposits_,
        uint256 sealDelay_,
        IERC7984ERC20Wrapper confidentialWrapper_
    ) BatchedStealthWrapAdapter(maxBatchDeposits_, sealDelay_, confidentialWrapper_) {}

    /// @dev The parent's deposit path minus the single-use check. `recipientHandleUsed` still
    ///      reports history, since it reads the persistent ACL grant the deposit path makes.
    function initWrap(
        uint256 amount,
        externalEaddress eRecipient,
        bytes calldata inputProof
    ) external override nonReentrant returns (uint256 slot) {
        eaddress verifiedRecipient = _verifyRecipient(eRecipient, inputProof);
        (uint256 wrappedUnderlying, euint64 eAmount) = _wrapIntoEscrow(msg.sender, amount);
        slot = _recordBatchedDeposit(msg.sender, wrappedUnderlying, eAmount, verifiedRecipient);
    }
}
