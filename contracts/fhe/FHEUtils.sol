// SPDX-License-Identifier: MIT
pragma solidity ^0.8.27;

import {FHE, euint64, eaddress, externalEuint64, externalEaddress} from "@fhevm/solidity/lib/FHE.sol";
import {Impl, IACL, IFHEVMExecutor} from "@fhevm/solidity/lib/Impl.sol";
import {FheType} from "@fhevm/solidity/lib/FheType.sol";

/**
 * @title FHEUtils
 * @author Valerio Leo (@valeriohq)
 * @notice Companion to `@fhevm/solidity` for contracts that handle ciphertexts they did not create:
 *         imports that grant access to the importing contract only, a check for handles an untrusted
 *         contract returns, a freshness check for single-use input handles, and a depth-bounded sum.
 * @dev {fromExternal} relies on `FHEVMExecutor.verifyInput` granting ACL access to its `msg.sender`
 *      and to nobody else. That holds for fhevm-solidity 0.11.x and is asserted by this library's
 *      tests, which must stay green across dependency bumps.
 */
library FHEUtils {
    /// @dev {fromExternal} was given an empty `inputProof`.
    error MissingInputProof();

    // -----------------------------------------------------------------------
    // Inputs
    // -----------------------------------------------------------------------

    /**
     * @dev Import an external ciphertext, verifying `inputProof` against `user` and granting ACL
     *      access to the calling contract only. The access is transient. Persist it with
     *      `FHE.allowThis` before storing the handle.
     *
     *      `FHE.fromExternal` also grants the submitter transient access, which a contract submitter
     *      can promote with `FHE.allow` inside the same transaction and use to decrypt a value it was
     *      only meant to carry. This import makes no such grant. The proof binding is unchanged.
     *      `user` is verified against the proof, so pass `msg.sender` unless the ciphertext is meant
     *      to be submittable by someone else.
     *
     *      The expected type travels to the coprocessor, which reverts `InvalidType` on a mismatch.
     *      An empty proof reverts {MissingInputProof}.
     * @param user The address `inputProof` is bound to, normally `msg.sender`.
     */
    function fromExternal(
        externalEuint64 handle,
        bytes calldata inputProof,
        address user
    ) internal returns (euint64) {
        return euint64.wrap(_verifyInput(externalEuint64.unwrap(handle), inputProof, user, FheType.Uint64));
    }

    /// @dev `eaddress` overload of {fromExternal}.
    /// @param user The address `inputProof` is bound to, normally `msg.sender`.
    function fromExternal(
        externalEaddress handle,
        bytes calldata inputProof,
        address user
    ) internal returns (eaddress) {
        return eaddress.wrap(_verifyInput(externalEaddress.unwrap(handle), inputProof, user, FheType.Uint160));
    }

    // -----------------------------------------------------------------------
    // Returned handles
    // -----------------------------------------------------------------------

    /**
     * @dev Whether `account` holds ACL access to an initialized `handle`. Run it on every ciphertext
     *      an untrusted contract returns, before folding that ciphertext into your own state or
     *      granting it onward.
     *
     *      Handles are global, so a hostile callee can return one it read from another contract's
     *      getter or event. A contract cannot grant itself access it does not hold, so a `true`
     *      result means the callee returned a value it could already read, and a `false` result is
     *      evidence of misbehaviour rather than of a failed call. Trivially encrypted handles are
     *      content-addressed, so two contracts that trivially encrypt the same plaintext share one
     *      handle and both pass, which leaks nothing.
     */
    function isAuthorizedOn(euint64 handle, address account) internal view returns (bool) {
        return FHE.isInitialized(handle) && FHE.isAllowed(handle, account);
    }

    /// @dev `eaddress` overload of {isAuthorizedOn}.
    function isAuthorizedOn(eaddress handle, address account) internal view returns (bool) {
        return FHE.isInitialized(handle) && FHE.isAllowed(handle, account);
    }

    // -----------------------------------------------------------------------
    // Single-use handles
    // -----------------------------------------------------------------------

    /**
     * @dev Whether the calling contract has never persisted access to `handle`. A contract keeps an
     *      input handle by calling `FHE.allowThis` on it, so a handle it already holds persistent
     *      access to is one it already accepted, and the ACL's own record serves as the used-handle
     *      set. Check before `FHE.allowThis`. Transient grants, including the one {fromExternal}
     *      makes, do not count, and since `ACL.allow` requires the caller to hold access to the
     *      handle, the only account that can ever mark an input handle used for a contract is that
     *      contract, which is the only one its proof lets import it.
     */
    function isFresh(bytes32 handle) internal view returns (bool) {
        return !IACL(Impl.getCoprocessorConfig().ACLAddress).persistAllowed(handle, address(this));
    }

    // -----------------------------------------------------------------------
    // Reductions
    // -----------------------------------------------------------------------

    /**
     * @dev Sum `xs` by pairwise reduction, in place, consuming `xs`.
     *
     *      fhEVM meters total HCU and the depth of the longest dependency chain per transaction. A
     *      serial accumulator is a chain of N adds and hits the depth budget first. Pairwise
     *      reduction keeps the chain at ceil(log2 N), so the total budget is what bounds N. An empty
     *      input returns a trivial encryption of zero, with transient access only.
     */
    function sum(euint64[] memory xs) internal returns (euint64) {
        uint256 n = xs.length;
        if (n == 0) return FHE.asEuint64(0);

        while (n > 1) {
            uint256 half = (n + 1) >> 1;
            for (uint256 i = 0; i < half; i++) {
                uint256 l = i << 1;
                uint256 r = l + 1;
                xs[i] = r < n ? FHE.add(xs[l], xs[r]) : xs[l];
            }
            n = half;
        }

        return xs[0];
    }

    // -----------------------------------------------------------------------

    /// @dev Inlined into the calling contract, so the executor sees that contract as `msg.sender`
    ///      and grants access to it alone. Keep it `private`.
    function _verifyInput(
        bytes32 handle,
        bytes calldata inputProof,
        address user,
        FheType expectedType
    ) private returns (bytes32) {
        if (inputProof.length == 0) revert MissingInputProof();
        IFHEVMExecutor coprocessor = IFHEVMExecutor(Impl.getCoprocessorConfig().CoprocessorAddress);
        return coprocessor.verifyInput(handle, user, inputProof, expectedType);
    }
}
