// SPDX-License-Identifier: MIT
pragma solidity ^0.8.27;

import {FHE, eaddress, externalEaddress, euint64} from "@fhevm/solidity/lib/FHE.sol";
import {IERC7984ERC20Wrapper} from "@openzeppelin/confidential-contracts/interfaces/IERC7984ERC20Wrapper.sol";
import {BatchedStealthWrapAdapter} from "../adapters/BatchedStealthWrapAdapter.sol";

/**
 * @dev A derived adapter that records a deposit whose `eAmount` it holds only TRANSIENT
 *      authorization on: the shape you get when confidential funds arrive through a callback or a
 *      pre-existing balance rather than `_wrapIntoEscrow` (which grants persistent access itself).
 *
 *      `_recordBatchedDeposit` is the advertised storage boundary for exactly these adapters, so it
 *      must persist ACL access to both ciphertexts it stores. If it does not, the transient grant
 *      expires with the transaction and `finalizeWrap` can never touch `eAmount` again.
 *
 *      Deliberately keeps the inherited `finalizeWrap` so a test can run the real scan.
 */
contract MockTransientAmountAdapter is BatchedStealthWrapAdapter {
    constructor(
        uint256 maxBatchDeposits_,
        uint256 sealDelay_,
        IERC7984ERC20Wrapper confidentialWrapper_
    ) BatchedStealthWrapAdapter(maxBatchDeposits_, sealDelay_, confidentialWrapper_) {}

    /// @dev No tokens move: the point is the ACL lifetime of `eAmount`, not the escrow.
    function recordTransientAmountDeposit(
        uint64 amount,
        externalEaddress eRecipient,
        bytes calldata inputProof
    ) external nonReentrant returns (uint256 slot) {
        eaddress verifiedRecipient = _verifyRecipient(eRecipient, inputProof);
        euint64 eAmount = FHE.asEuint64(amount); // transient only; deliberately no allowThis
        slot = _recordBatchedDeposit(msg.sender, amount, eAmount, verifiedRecipient);
    }
}
