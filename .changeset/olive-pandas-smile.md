---
"@raycashxyz/confidential-primitives": minor
---

New `FHEUtils` library (`contracts/fhe/FHEUtils.sol`), extending `@fhevm/solidity` with
what contracts that handle ciphertexts they did not create keep needing: `fromExternal` (imports that
grant ACL access to the importing contract only, and always type-check the handle), `isAuthoredBy`
(provenance of a handle an untrusted contract hands back) and `sum` (tree reduction that keeps FHE
dependency depth at `ceil(log2 N)`).

Both shipped contracts now route every external ciphertext through `FHEUtils.fromExternal` instead of
`FHE.fromExternal`. `StealthWrapAdapter._sumTree` and `RecurringAllowance`'s returned-handle check are
thin wrappers over the library, so their own APIs and any derived adapters are unchanged.

`FHE.fromExternal` ends with a second `IACL.allowTransient(result, msg.sender)` in the calling
contract's frame, so whoever submitted the ciphertext receives transient ACL access to it. An EOA
cannot use that, but a contract caller, still executing in the same transaction, can promote it
with `FHE.allow` or publish it with `FHE.makePubliclyDecryptable`, then decrypt off-chain. Passing the
expected `FheType` to the coprocessor also closes `fromExternal`'s empty-proof branch, which returns a
handle verbatim after only an ACL check and is the entry point for the wrong-typed-handle attacks.
The proof binding is unchanged: the ciphertext still verifies against a named `user`, so it remains
submittable only by the party it was issued to.

This fixes one previously unreported leak. `RecurringAllowance.permitTransferFrom` imported the
cheque's encrypted cap (chosen by the OWNER, bound to the spender, and never granted
onward, since only `transferred` is shared) with `FHE.fromExternal`. A contract spender could
therefore persist the cap handle (it is `permit.capHandle`, already in their own calldata) and
decrypt the owner's private ceiling. Not theft, but it removes the uncertainty the design relies on:
an over-request moves an encrypted zero and still burns the nonce, so a spender who cannot see the
cap is pushed to under-request. Regression test uses a contract spender that reports its own access
and then tries to escalate.

The stealth adapters' recipient import already had this containment; it now shares the library
implementation rather than open-coding it. `test/fhe-utils.mock.test.ts` asserts the library's
guarantees directly (including that the submitter ends up with no access), so an
`@fhevm/solidity` bump that changed `verifyInput`'s ACL behaviour fails there rather than silently.
