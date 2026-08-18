---
"@raycashxyz/confidential-primitives": patch
---

`StealthWrapAdapter._verifyRecipient` now imports the encrypted recipient through the coprocessor's
`verifyInput` directly instead of `FHE.fromExternal`, so a deposit no longer leaks the recipient to
the depositor. Both shipped adapters route through this one path, so both are fixed.

`FHE.fromExternal` expands to `Impl.verify`, which after the proof check runs
`IACL.allowTransient(result, msg.sender)` — and inside `initWrap` that `msg.sender` is the depositor.
An EOA depositor cannot use that transient grant (it dies with the transaction), but a CONTRACT
depositor could promote it with `FHE.allow` or publish it with `FHE.makePubliclyDecryptable` in the
same transaction and decrypt the recipient the handshake is meant to hide. Calling `verifyInput`
directly performs the identical check with the identical `(contractAddress = adapter,
userAddress = depositor)` binding — so the depositor-bound proof still stops any third party from
submitting the handle, the property the single-use handle policy depends on — but the only ACL grant
it makes goes to the adapter (the executor's own `allowTransient(result, msg.sender)`, whose
`msg.sender` is the adapter). The depositor is named only inside the proof and receives no ACL
access. The recipient is now concealed from a contract depositor as well as from chain observers.

The direct import also makes the `Uint160` type check on the recipient handle mandatory at the
coprocessor for every deposit, closing the wrong-typed-handle attacks (`Bool`/`euint64`/other) at the
executor rather than only via the empty-proof gate.
