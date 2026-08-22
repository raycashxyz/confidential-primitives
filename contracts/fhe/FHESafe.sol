// SPDX-License-Identifier: MIT
pragma solidity ^0.8.27;

import {euint64, eaddress, externalEuint64, externalEaddress} from "@fhevm/solidity/lib/FHE.sol";
import {Impl, IFHEVMExecutor} from "@fhevm/solidity/lib/Impl.sol";
import {FheType} from "@fhevm/solidity/lib/FheType.sol";

/**
 * @title FHESafe
 * @author Valerio Leo (@valeriohq)
 * @notice Ciphertext imports that grant ACL access to the IMPORTING CONTRACT ONLY, and that always
 *         type-check the handle.
 *
 *         Use these in place of `FHE.fromExternal` wherever a contract accepts a ciphertext from a
 *         caller. Two differences, both of which matter:
 *
 *         1. NO GRANT TO THE SUBMITTER. `FHE.fromExternal` ends with an
 *            `IACL.allowTransient(result, msg.sender)` in the CALLING contract's frame, so the
 *            account that submitted the ciphertext gets transient ACL access to it. An EOA cannot
 *            use that — transient authorization dies with the transaction — but a CONTRACT caller,
 *            still executing in the same transaction, can call `FHE.allow` to make it permanent or
 *            `FHE.makePubliclyDecryptable` to publish the value, and then read a plaintext it was
 *            never meant to see. These functions stop after the coprocessor's own grant, which
 *            names the importing contract and nobody else.
 *
 *            The proof binding is unchanged: `user` is still verified against the proof, so the
 *            ciphertext remains submittable only by the party it was issued to. Pass `msg.sender`
 *            unless you have a specific reason not to. Passing an address that is not the submitter
 *            makes the ciphertext bearer-submittable by anyone — see {fromExternal}.
 *
 *         2. MANDATORY TYPE CHECK. `FHE.fromExternal` has an empty-proof branch that returns the
 *            handle VERBATIM after only an ACL check, so a caller can land a handle of ANY type in a
 *            typed slot. Passing the expected {FheType} to the coprocessor makes that unreachable: a
 *            mismatch reverts `InvalidType` at `verifyInput`, before the handle can be stored.
 *
 *         WHAT YOU STILL HAVE TO DO. The grant these make is the importing contract's TRANSIENT
 *         access, which expires with the transaction. Persist it with `FHE.allowThis` wherever the
 *         handle is stored, and grant it onward with `FHE.allow` to any party entitled to read the
 *         plaintext — for a value the caller chose themselves that is usually the caller.
 *
 *         VERSION COUPLING. This depends on the BEHAVIOUR of `FHEVMExecutor.verifyInput`, not only
 *         its signature: specifically that it grants ACL access to its own `msg.sender` and to no
 *         one else. That holds for fhevm-solidity 0.11.x. A release that changes it would break
 *         the guarantee silently, with no compiler error, so the property is asserted directly in
 *         this library's tests — keep them green across dependency bumps rather than trusting the
 *         version pin alone.
 */
library FHESafe {
    /**
     * @dev Import an `externalEuint64`, verifying the proof against `user` and granting ACL access
     *      only to the calling contract.
     * @param user The address the input proof is bound to — normally `msg.sender`.
     */
    function fromExternal(
        externalEuint64 handle,
        bytes calldata inputProof,
        address user
    ) internal returns (euint64) {
        return euint64.wrap(_verify(externalEuint64.unwrap(handle), inputProof, user, FheType.Uint64));
    }

    /**
     * @dev Import an `externalEaddress`, verifying the proof against `user` and granting ACL access
     *      only to the calling contract.
     * @param user The address the input proof is bound to — normally `msg.sender`.
     */
    function fromExternal(
        externalEaddress handle,
        bytes calldata inputProof,
        address user
    ) internal returns (eaddress) {
        return eaddress.wrap(_verify(externalEaddress.unwrap(handle), inputProof, user, FheType.Uint160));
    }

    /// @dev Resolves the executor through the same coprocessor config every `FHE.*` op uses, so it
    ///      tracks whatever config the contract installed. MUST stay `internal` (inlined): the
    ///      executor grants ACL to ITS caller, which is only the importing contract while this runs
    ///      in that contract's own frame.
    function _verify(
        bytes32 handle,
        bytes calldata inputProof,
        address user,
        FheType expectedType
    ) private returns (bytes32) {
        IFHEVMExecutor coprocessor = IFHEVMExecutor(Impl.getCoprocessorConfig().CoprocessorAddress);
        return coprocessor.verifyInput(handle, user, inputProof, expectedType);
    }
}
