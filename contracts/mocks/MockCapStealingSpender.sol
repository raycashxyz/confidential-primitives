// SPDX-License-Identifier: MIT
pragma solidity ^0.8.27;

import {FHE, euint64, externalEuint64} from "@fhevm/solidity/lib/FHE.sol";
import {ZamaEthereumConfig} from "@fhevm/solidity/config/ZamaConfig.sol";
import {IRecurringAllowance} from "../interfaces/IRecurringAllowance.sol";

/**
 * @dev A CONTRACT spender that tries to read the cheque cap it was handed.
 *
 *      The cap is the owner's private ceiling for one cheque: encrypted by the owner, bound to the
 *      spender so only they can submit it, and never granted onward — `permitTransferFrom` shares
 *      only `transferred`. The spender is meant to learn whether their request fit, not how much
 *      room there was.
 *
 *      `FHE.fromExternal` would break that: it grants the submitter transient ACL access, and this
 *      contract is still executing in the same transaction when `permitTransferFrom` returns, so it
 *      could persist that access and decrypt the cap off-chain. The handle is no secret either — it
 *      is `permit.capHandle`, straight out of its own calldata. Importing through
 *      {FHEUtils-fromExternal} means the grant never reaches it, so both attempts below revert
 *      `SenderNotAllowed` at the ACL and {reportSelfAccess} is false.
 */
contract MockCapStealingSpender is ZamaEthereumConfig {
    IRecurringAllowance public immutable allowance;

    /// @param spenderAllowedOnCap Whether THIS contract can access the cap handle immediately after
    ///        spending the cheque. Must be false.
    event SpenderSelfAccess(bool spenderAllowedOnCap);

    constructor(IRecurringAllowance allowance_) {
        allowance = allowance_;
    }

    /// @dev Spend the cheque, then report whether the spender retained ACL access to the cap.
    function spendAndReportSelfAccess(
        address owner,
        IRecurringAllowance.PermitSpend calldata permit,
        bytes calldata capProof,
        externalEuint64 requested,
        bytes calldata requestedProof,
        address to,
        bytes calldata signature
    ) external {
        allowance.permitTransferFrom(owner, permit, capProof, requested, requestedProof, to, signature);
        emit SpenderSelfAccess(FHE.isAllowed(euint64.wrap(permit.capHandle), address(this)));
    }

    /// @dev Spend the cheque, then try to persist the cap to itself. Reverts `SenderNotAllowed`.
    function spendThenPersistCap(
        address owner,
        IRecurringAllowance.PermitSpend calldata permit,
        bytes calldata capProof,
        externalEuint64 requested,
        bytes calldata requestedProof,
        address to,
        bytes calldata signature
    ) external {
        allowance.permitTransferFrom(owner, permit, capProof, requested, requestedProof, to, signature);
        FHE.allow(euint64.wrap(permit.capHandle), address(this));
    }
}
