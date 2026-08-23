// SPDX-License-Identifier: MIT
pragma solidity ^0.8.27;

import {FHE, eaddress, externalEaddress} from "@fhevm/solidity/lib/FHE.sol";
import {ZamaEthereumConfig} from "@fhevm/solidity/config/ZamaConfig.sol";
import {IERC20} from "@openzeppelin/contracts/interfaces/IERC20.sol";
import {IStealthWrapAdapter} from "../interfaces/IStealthWrapAdapter.sol";

/**
 * @dev The recipient-privacy attacker described on {StealthWrapAdapter}: a CONTRACT
 *      depositor that tries to unmask the recipient it just deposited for. It deposits through the
 *      adapter, then, still inside the same transaction while any transient ACL grant would still
 *      be live, tries to turn that access into something it can read off-chain.
 *
 *      Because {StealthWrapAdapter._verifyRecipient} imports the ciphertext through
 *      `FHEUtils.fromExternalForThis`, which grants access to the adapter alone, the depositor gets no ACL
 *      access at all. {depositAndReportSelfAccess} therefore reports `false`, and both escalation
 *      attempts revert `SenderNotAllowed` at the ACL. If the adapter had used `FHE.fromExternal`,
 *      the depositor would hold a transient grant here and all three would succeed.
 *
 *      The recovered handle is reconstructed from the depositor's own `externalEaddress` input. The
 *      coprocessor's input verification returns the submitted handle verbatim, so the stored
 *      `eaddress` and `externalEaddress.unwrap(eRecipient)` are the same bytes32.
 */
contract MockRecipientStealingDepositor is ZamaEthereumConfig {
    IStealthWrapAdapter public immutable adapter;

    /// @param id The deposit index/slot returned by the adapter.
    /// @param depositorAllowedOnRecipient Whether THIS contract (the depositor) can access the stored
    ///        recipient handle immediately after depositing. Must be false once [#36] is fixed.
    event DepositorSelfAccess(uint256 indexed id, bool depositorAllowedOnRecipient);

    constructor(IStealthWrapAdapter adapter_, IERC20 underlying_) {
        adapter = adapter_;
        // The adapter pulls the underlying from the depositor (this contract) via safeTransferFrom.
        underlying_.approve(address(adapter_), type(uint256).max);
    }

    /// @dev Deposit, then report whether the depositor retained any ACL access to the recipient
    ///      handle. This is the direct statement of the [#36] property.
    function depositAndReportSelfAccess(
        uint256 amount,
        externalEaddress eRecipient,
        bytes calldata inputProof
    ) external returns (uint256 id) {
        id = adapter.initWrap(amount, eRecipient, inputProof);
        bool depositorAllowed = FHE.isAllowed(eaddress.wrap(externalEaddress.unwrap(eRecipient)), address(this));
        emit DepositorSelfAccess(id, depositorAllowed);
    }

    /// @dev Deposit, then try to publish the recipient handle. Reverts `SenderNotAllowed` once fixed.
    function depositThenPublish(
        uint256 amount,
        externalEaddress eRecipient,
        bytes calldata inputProof
    ) external returns (uint256 id) {
        id = adapter.initWrap(amount, eRecipient, inputProof);
        FHE.makePubliclyDecryptable(eaddress.wrap(externalEaddress.unwrap(eRecipient)));
    }

    /// @dev Deposit, then try to persist the recipient handle to itself. Reverts `SenderNotAllowed`
    ///      once fixed.
    function depositThenPersist(
        uint256 amount,
        externalEaddress eRecipient,
        bytes calldata inputProof
    ) external returns (uint256 id) {
        id = adapter.initWrap(amount, eRecipient, inputProof);
        FHE.allow(eaddress.wrap(externalEaddress.unwrap(eRecipient)), address(this));
    }
}
