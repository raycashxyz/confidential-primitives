---
"@raycashxyz/confidential-primitives": patch
---

`BatchedStealthWrapAdapter.finalizeWrap` now rejects an empty `ids` array with `InvalidId`. Before,
it scanned nothing but still made a real `confidentialTransfer` of the encrypted zero, emitting
`WrapFinalized(recipient, handle, [])` against any address that need never have touched the
protocol, repeatable at gas cost.
