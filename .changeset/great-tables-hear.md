---
"@raycashxyz/confidential-primitives": patch
---

`BatchedStealthWrapAdapter._recordBatchedDeposit` asserts its "current batch is open with room"
invariant instead of trying to recover from a violation. The old fallback was unreachable, and wrong
if it had ever been reached: for a closed-but-not-full batch it re-read the unchanged
`currentBatchId` and returned the same closed batch, so the deposit would have landed in a batch
whose anonymity set is frozen and whose nullifier a recipient may already have consumed.
