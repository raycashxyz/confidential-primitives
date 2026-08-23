---
"@raycashxyz/confidential-primitives": patch
---

`_recordBatchedDeposit` reverts `BatchAlreadyClosed` when the current batch is closed instead of
recovering. The recovery was unreachable and would have put the deposit into a closed batch.
