---
"@raycashxyz/confidential-primitives": patch
---

`ContinuousStealthWrapAdapter.finalizeWrap` compares recipients with the scalar `FHE.eq`, cutting
20,000 HCU per scanned slot and raising the maximum executable decoy set.
