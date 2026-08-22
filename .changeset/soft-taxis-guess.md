---
"@raycashxyz/confidential-primitives": minor
---

Encrypted-recipient handles are now single-use across both adapters. A replayed handle reverts
`RecipientHandleAlreadyUsed`, and `recipientHandleUsed(bytes32)` exposes the state.

The handle is emitted in `WrapInitiated` so the recipient can spot their own payment, which makes it
a public tag. Nothing previously enforced freshness, so a depositor handed one payment credential
could fund several deposits with it and observers could cluster them as "same unknown recipient",
without breaking any encryption. Once one member of that cluster is tied to a clear address, by a
finalize or by timing, the rest follow. Batch boundaries and decoy choice don't remove a tag that
travels with the deposit itself.

Nothing legitimate is rejected, since every payment request is meant to carry its own encryption, and a
fresh encryption of the same address produces a different handle, so a recipient can still be paid
any number of times.
