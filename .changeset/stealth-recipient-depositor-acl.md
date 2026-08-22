---
"@raycashxyz/confidential-primitives": patch
---

A deposit no longer leaks the encrypted recipient to a contract depositor. `StealthWrapAdapter`
imports the recipient through `FHEUtils.fromExternal`, which grants ACL access to the adapter only.
`FHE.fromExternal` also granted the submitting depositor transient access, which a contract could
persist with `FHE.allow` or publish with `FHE.makePubliclyDecryptable` within the same transaction.
The proof binding is unchanged, so only the named depositor can submit the handle. Both shipped
adapters go through this one path. The mechanism and its tests are described in the `FHEUtils` entry.
