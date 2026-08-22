---
"@raycashxyz/confidential-primitives": patch
---

Docs: `StealthWrapAdapter`'s reentrancy note said both external helpers run before callers record
their state. That is true of `_wrapIntoEscrow` but not of finalization, where the claim commit sits
on the other side of the external call and the exact ordering differs by adapter. The continuous one
zeroes matched amounts before calling `_transferWrapped`, while the batched one credits its encrypted
`claimed` ledger after it, because the credit is the amount that call returns. The note now splits
the guidance per helper and states that neither ordering is safe without `nonReentrant`, so authors
of derived finalizers keep the guard.
