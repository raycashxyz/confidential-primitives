---
"@raycashxyz/confidential-primitives": minor
---

**Breaking:** the batched seal deadline is anchored to a batch's first deposit instead of its last,
so later deposits cannot push it out. Adds `batchOpenedAt`; removes `batchLastDepositAt`.
