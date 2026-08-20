---
"@raycashxyz/confidential-primitives": patch
---

`BatchedStealthWrapAdapter.finalizeWrap` now rejects an empty `ids` array with `InvalidId`. Before,
it scanned nothing but still made a real `confidentialTransfer` of the encrypted zero, emitting a
`WrapFinalized` that no indexer could distinguish from a genuine claim — against any address, and
repeatable at gas cost.
