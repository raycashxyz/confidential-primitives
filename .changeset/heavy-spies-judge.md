---
"@raycashxyz/confidential-primitives": patch
---

Docs: `StealthWrapAdapter`'s reentrancy note said both external helpers run before callers record
their state. That is true of `_wrapIntoEscrow` but backwards for finalization — the batched adapter
sets its cleartext nullifier and the continuous one zeroes matched amounts *before* calling
`_transferWrapped`. The note now splits the guidance per helper and says why the finalize ordering
is deliberate, so authors of derived finalizers preserve it.
