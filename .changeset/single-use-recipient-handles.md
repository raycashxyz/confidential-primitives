---
"@raycashxyz/confidential-primitives": minor
---

Encrypted-recipient handles are single-use per adapter. A reused handle publicly links its deposits,
so a replay reverts `RecipientHandleAlreadyUsed`, while a fresh encryption of the same address is a
new handle. `recipientHandleUsed(bytes32)` exposes the state, and an adapter whose deposit path
already links deposits can omit the check in its own `initWrap`. The record is the adapter's own
persistent ACL grant on the stored handle, with no extra storage.
