---
"@raycashxyz/confidential-primitives": minor
---

**Breaking:** `BatchedStealthWrapAdapter` deposit slots are dense. A deposit takes slot
`getDepositsLength()`, so `[0, getDepositsLength())` enumerates every deposit and the redundant
`totalDeposits()` is removed.
