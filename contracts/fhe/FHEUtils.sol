// SPDX-License-Identifier: MIT
pragma solidity ^0.8.27;

import {FHE, euint64, eaddress, externalEuint64, externalEaddress} from "@fhevm/solidity/lib/FHE.sol";
import {Impl, IFHEVMExecutor} from "@fhevm/solidity/lib/Impl.sol";
import {FheType} from "@fhevm/solidity/lib/FheType.sol";

/**
 * @title FHEUtils
 * @author Valerio Leo (@valeriohq)
 * @notice Helpers for fhEVM contracts that handle ciphertexts they did not create.
 *
 *         Extends fhevm-solidity with what that library leaves to the caller; import both. Sections
 *         below are INPUTS, PROVENANCE and REDUCTIONS.
 *
 *         VERSION COUPLING. {fromExternal} depends on the BEHAVIOUR of `FHEVMExecutor.verifyInput`
 *         (that it grants ACL access to its own `msg.sender` and to no one else), rather than only on its
 *         signature. That holds for fhevm-solidity 0.11.x. A release that changed it would break the
 *         guarantee with no compiler error, so the property is asserted directly in this library's
 *         tests; keep them green across dependency bumps rather than trusting a version pin.
 */
library FHEUtils {
    // -----------------------------------------------------------------------
    // INPUTS: import a caller-supplied ciphertext without granting them access
    // -----------------------------------------------------------------------

    /**
     * @dev Import an external ciphertext, verifying `inputProof` against `user` and granting ACL
     *      access to the CALLING CONTRACT ONLY. Use in place of `FHE.fromExternal` wherever a
     *      contract accepts a ciphertext from a caller.
     *
     *      `FHE.fromExternal` ends with an `IACL.allowTransient(result, msg.sender)` in the calling
     *      contract's frame, so the submitter also gets transient access. An EOA cannot use that
     *      (transient authorization dies with the transaction), but a CONTRACT submitter, still
     *      executing in the same transaction, can promote it with `FHE.allow` or publish the value
     *      with `FHE.makePubliclyDecryptable`, then read a plaintext it was never meant to see.
     *
     *      Passing the expected {FheType} also closes `FHE.fromExternal`'s empty-proof branch, which
     *      returns a handle VERBATIM after only an ACL check and lets a caller land a handle of any
     *      type in a typed slot. Here a mismatch reverts `InvalidType` at the coprocessor, and an
     *      empty proof reverts `EmptyInputProof` at the input verifier.
     *
     *      The proof binding is UNCHANGED: `user` is still verified against the proof, so the
     *      ciphertext stays submittable only by the party it was issued to. Pass `msg.sender` unless
     *      you have a specific reason not to: naming an address that is not the submitter makes the
     *      ciphertext bearer-submittable by anyone.
     *
     *      The grant this makes is the calling contract's TRANSIENT access. Persist it with
     *      `FHE.allowThis` wherever the handle is stored, and pass it on with `FHE.allow` to anyone
     *      entitled to read the plaintext (for a value the caller chose themselves, usually them).
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
    // PROVENANCE: is a handle received from an untrusted contract really its own
    // -----------------------------------------------------------------------

    /**
     * @dev Whether `author` is ACL-authorized on `handle`, which is the check to run on any ciphertext
     *      an untrusted contract HANDS BACK to you.
     *
     *      Handles are global rather than namespaced per contract, so a hostile callee can return a
     *      handle belonging to somebody else entirely: one it read from a public getter or an event.
     *      Folding that into your own state and then granting it to a caller launders a third party's
     *      ciphertext into a value that caller can decrypt.
     *
     *      A contract is always authorized on a value it computed, and cannot grant itself access to
     *      one it did not, so `isAllowed(handle, author)` separates the two. The guarantee is
     *      this: anything that passes is something the callee could already read, which is
     *      the bar that matters: a callee cannot launder a handle it holds no access to, and one it
     *      does hold access to (including any you granted it transiently for the call) it could leak
     *      by other means anyway. The initialization check rejects the zero handle, which no
     *      computation returns. This is the mirror of the check fhEVM tokens apply to amounts handed
     *      IN (OpenZeppelin's `ERC7984UnauthorizedUseOfEncryptedAmount`).
     *
     *      Two things it is not. It is not proof of unique authorship: trivially encrypted handles
     *      are content-addressed with no sender in the preimage, so two contracts that trivially
     *      encrypt the same plaintext share one handle and both pass (harmless, since a trivial
     *      encryption carries no secret). And a `false` result means the callee is misbehaving, not
     *      that the call failed: decide deliberately whether that is worth aborting for.
     */
    function isAuthoredBy(euint64 handle, address author) internal view returns (bool) {
        return FHE.isInitialized(handle) && FHE.isAllowed(handle, author);
    }

    /// @dev `eaddress` overload of {isAuthoredBy}.
    function isAuthoredBy(eaddress handle, address author) internal view returns (bool) {
        return FHE.isInitialized(handle) && FHE.isAllowed(handle, author);
    }

    // -----------------------------------------------------------------------
    // REDUCTIONS: aggregate many ciphertexts without a long dependency chain
    // -----------------------------------------------------------------------

    /**
     * @dev Sum `xs` with a pairwise binary-tree reduction, in place.
     *
     *      fhEVM meters two budgets per transaction: total HCU, and the DEPTH of the longest
     *      dependency chain. A serial accumulator (`acc = add(acc, x)`) is a chain of N adds, so it
     *      hits the depth cap long before the total one and puts a hard ceiling on N. Reducing
     *      pairwise keeps the critical path at ceil(log2 N) adds, which moves the binding limit back
     *      to total HCU.
     *
     *      Reduces IN PLACE, into the same memory, rather than allocating a new array per level, so
     *      `xs` is consumed: do not reuse it afterwards. An empty input sums to a trivially encrypted
     *      zero, on which the caller holds only transient access.
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

    /// @dev Resolves the executor through the same coprocessor config every `FHE.*` op uses, so it
    ///      tracks whatever config the contract installed. MUST stay `internal`/`private` (inlined):
    ///      the executor grants ACL to ITS caller, which is the importing contract only while this
    ///      runs in that contract's own frame.
    function _verifyInput(
        bytes32 handle,
        bytes calldata inputProof,
        address user,
        FheType expectedType
    ) private returns (bytes32) {
        IFHEVMExecutor coprocessor = IFHEVMExecutor(Impl.getCoprocessorConfig().CoprocessorAddress);
        return coprocessor.verifyInput(handle, user, inputProof, expectedType);
    }
}
