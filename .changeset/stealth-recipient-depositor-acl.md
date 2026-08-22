---
"@raycashxyz/confidential-primitives": patch
---

A deposit no longer leaks the encrypted recipient to a contract depositor. `StealthWrapAdapter`
imports the recipient through `FHEUtils.fromExternal`, which grants ACL access to the adapter only.
`FHE.fromExternal` also granted the submitting depositor transient access, which a contract could
persist with `FHE.allow` or publish with `FHE.makePubliclyDecryptable` within the same transaction.
The proof binding is unchanged, so only the named depositor can submit the handle. Derived adapters
must import recipients through `StealthWrapAdapter._verifyRecipient`, which is also where the
single-use check and the `Uint160` type check live. An adapter that imports with `FHE.fromExternal`
itself gets none of the three. The mechanism and its tests are described in the `FHEUtils` entry.
