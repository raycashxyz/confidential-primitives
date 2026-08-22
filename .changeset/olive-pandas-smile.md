---
"@raycashxyz/confidential-primitives": minor
---

New `FHEUtils` library (`contracts/fhe/FHEUtils.sol`), extending `@fhevm/solidity` with what
contracts that handle ciphertexts they did not create keep needing.

`fromExternal(handle, proof, user)` imports a caller-supplied ciphertext and grants ACL access to the
importing contract only. `FHE.fromExternal` also grants the submitter transient access, which a
contract submitter can persist or publish within the same transaction. The proof binding is
unchanged, so the ciphertext stays submittable only by `user`. It passes the expected type to the
coprocessor and reverts `MissingInputProof`, declared on the library and present in every consumer's
ABI, on an empty proof, so the `FHE.fromExternal` branch that returned a handle verbatim after an ACL
check is unreachable. That branch was the entry point for the
audit's wrong-typed-handle findings: a `Bool` recipient matching every address, a `euint64` recipient
welded into a serial FHE chain that tripped the 5M depth budget, and a non-`Uint64` permission limit
that aborted whole `tryTransferFrom` batches.

`isAuthorizedOn(handle, account)` checks a ciphertext an untrusted contract hands back. Anything that
passes is something the callee could already read, so it cannot launder a third party's handle
through you. `isFresh(handle)` reports whether the calling contract has never persisted access to a
handle, which makes the ACL's own record the used-handle set for single-use inputs, with no mirror
mapping. `sum(xs)` reduces an array pairwise, keeping FHE dependency depth at `ceil(log2 N)`.

Both shipped contracts route every external ciphertext through `FHEUtils.fromExternal` and call the
library directly for the returned-handle check and the reduction. `StealthWrapAdapter._sumTree`, the
virtual reduction hook, is removed. Both finalize paths call `FHEUtils.sum` directly. This fixes one
previously unreported leak.
`RecurringAllowance.permitTransferFrom` imported the cheque cap with `FHE.fromExternal`. The cap is the
owner's, bound to the spender and never granted onward, so a contract spender could persist the cap
handle, already in its calldata, and decrypt the owner's ceiling. Not theft, but a spender who cannot
see the cap is pushed to under-request, since an over-request moves an encrypted zero and burns the
nonce. `test/fhe-utils.mock.test.ts` asserts the library's guarantees directly, including that the
submitter ends up with no access, so an `@fhevm/solidity` bump that changed `verifyInput`'s ACL
behaviour fails there.
