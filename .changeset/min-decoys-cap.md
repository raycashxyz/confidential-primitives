---
"@raycashxyz/confidential-primitives": minor
---

`ContinuousStealthWrapAdapter` rejects `minDecoys` above 40 at deployment. The floor is immutable
and every finalize must clear it, so a value above what one transaction can execute would leave
deposits that can never be finalized.
