---
"@raycashxyz/confidential-primitives": patch
---

`BatchedStealthWrapAdapter.finalizeWrap` rejects an empty `ids` array with `InvalidId` instead of
transferring an encrypted zero to an arbitrary address.
