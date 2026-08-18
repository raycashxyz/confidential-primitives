---
"@raycashxyz/confidential-primitives": patch
---

`BatchedStealthWrapAdapter._recordBatchedDeposit` now calls `FHE.allowThis` on the stored `eAmount`
as well as the recipient. It is the advertised deposit hook for derived adapters that acquire
confidential funds some other way, and those can hold only transient authorization on the amount —
which expires with the transaction, leaving the deposit permanently unfinalizable. The bundled path
was already safe because `_wrapIntoEscrow` grants persistent access itself.
