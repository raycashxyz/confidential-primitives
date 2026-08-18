---
"@raycashxyz/confidential-primitives": minor
---

`RecurringAllowance` now verifies the provenance of every handle a token returns.

Ciphertext handles are global rather than namespaced per token, and `token` is a caller-supplied
address, so a malicious token could return any handle in place of its transfer result. Because this
contract calls `FHE.allowThis` on every user's `limit` and `spent` — and those handles are public via
`getPermission`/`PermissionSet` — the substituted handle was added into the attacker's own `spent`
and then granted to them, making any user's encrypted limit or spend history decryptable by anyone.

`_isTokenAuthored` now requires the returned handle to be initialized and ACL-authorized to the
returning token, which an honestly-computed result always is (`ERC7984._update` ends with
`FHE.allowThis(transferred)`). `transferFrom` and `permitTransferFrom` revert `InvalidReturnedHandle`;
`tryTransferFrom` skips the item with the new `SkipReason.INVALID_RETURN_HANDLE` rather than taking
down the batch.
