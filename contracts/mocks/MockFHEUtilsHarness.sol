// SPDX-License-Identifier: MIT
pragma solidity ^0.8.27;

import {FHE, euint64, eaddress, externalEuint64, externalEaddress} from "@fhevm/solidity/lib/FHE.sol";
import {ZamaEthereumConfig} from "@fhevm/solidity/config/ZamaConfig.sol";
import {FHEUtils} from "../fhe/FHEUtils.sol";

/**
 * @dev Exercises {FHEUtils} directly, so the library's guarantees are pinned independently of the
 *      contracts that happen to use it. The ACL containment in particular rests on the BEHAVIOUR of
 *      `FHEVMExecutor.verifyInput` rather than on its signature, so a dependency bump could break it
 *      with no compiler error. These are the tests that would catch that.
 */
contract MockFHEUtilsHarness is ZamaEthereumConfig {
    using FHEUtils for FHEUtils.HandleSet;

    /// @param importer Whether THIS contract can use the imported handle (must be true).
    /// @param submitter Whether the account that submitted it can (must be false).
    event ImportAccess(bool importer, bool submitter);

    /// @param wasFresh Whether the handle was new to the set when {markUsed} ran.
    event HandleMarked(bool wasFresh);

    /// @dev Last handle produced by {produce} / {sumOf}, so a test can read it back.
    euint64 public lastResult;

    FHEUtils.HandleSet private _seen;

    /// @dev Import an amount and report who ended up with ACL access.
    function importAndReportAccess(externalEuint64 handle, bytes calldata inputProof) external {
        euint64 imported = FHEUtils.fromExternal(handle, inputProof, msg.sender);
        emit ImportAccess(FHE.isAllowed(imported, address(this)), FHE.isAllowed(imported, msg.sender));
    }

    /// @dev Import a recipient and report the same. Separate overload, same guarantee.
    function importAddressAndReportAccess(externalEaddress handle, bytes calldata inputProof) external {
        eaddress imported = FHEUtils.fromExternal(handle, inputProof, msg.sender);
        emit ImportAccess(FHE.isAllowed(imported, address(this)), FHE.isAllowed(imported, msg.sender));
    }

    /// @dev Import an `eaddress` handle THROUGH THE euint64 OVERLOAD. The coprocessor must reject the
    ///      type mismatch, which is what makes a wrong-typed handle unable to reach a typed slot.
    function importAddressAsAmount(externalEuint64 mistyped, bytes calldata inputProof) external {
        FHEUtils.fromExternal(mistyped, inputProof, msg.sender);
    }

    /// @dev `true` only for a handle this contract holds access to. The {FHEUtils-isAuthorizedOn}
    ///      property, checked against a handle it computed itself and one another contract holds.
    function authorizedHere(euint64 handle) external view returns (bool) {
        return FHEUtils.isAuthorizedOn(handle, address(this));
    }

    /// @dev Produce a handle this contract is authorized on, for the positive case above.
    function produce(uint64 value) external {
        euint64 produced = FHE.asEuint64(value);
        FHE.allowThis(produced);
        lastResult = produced;
    }

    /// @dev Mark `handle` used and report whether it was fresh.
    function markUsed(bytes32 handle) external {
        emit HandleMarked(_seen.markUsed(handle));
    }

    /// @dev Whether `handle` has not been marked used yet.
    function isFresh(bytes32 handle) external view returns (bool) {
        return _seen.isFresh(handle);
    }

    /// @dev Tree-sum `values` and keep the total, so the reduction is exercised end to end.
    function sumOf(uint64[] calldata values) external {
        euint64[] memory xs = new euint64[](values.length);
        for (uint256 i = 0; i < values.length; i++) xs[i] = FHE.asEuint64(values[i]);
        euint64 total = FHEUtils.sum(xs);
        FHE.allowThis(total);
        FHE.allow(total, msg.sender);
        lastResult = total;
    }
}
