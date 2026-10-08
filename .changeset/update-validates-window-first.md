---
"@raycashxyz/confidential-primitives": patch
---

`updatePermission` validates the time window before importing a replacement limit, so an invalid
window reverts without paying for proof verification.
