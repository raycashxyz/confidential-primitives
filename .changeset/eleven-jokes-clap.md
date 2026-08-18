---
"@raycashxyz/confidential-primitives": patch
---

Docs: declare exact-or-revert as a wrapper requirement. The adapters assume `wrap` and
`confidentialTransfer` either move exactly what was asked or revert, but ERC-7984 permits an
operation to soft-fail — returning an encrypted zero while the transaction succeeds. On deposit, OZ's
wrapper moves the underlying before `_mint`, so a rejecting mint hook makes the adapter record a
zero-valued deposit against underlying the wrapper has kept, with no refund path. On finalize, claim
state commits before the transfer, so a soft-failed payout consumes the nullifier (or zeroes the
matched amounts) and delivers nothing.

Neither is repairable in the adapter — the outcome is a ciphertext and the decisions are cleartext —
so this is a deployment constraint. Documented in `StealthWrapAdapter` and the README.
