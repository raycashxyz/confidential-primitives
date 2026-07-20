---
"@raycashxyz/confidential-primitives": minor
---

`BatchedStealthWrapAdapter` now exposes extension points for alternate deposit-acquisition flows. Its batch recording is available through internal `_recordBatchedDeposit`, and `initWrap` and `finalizeWrap` are virtual for derived adapters.
