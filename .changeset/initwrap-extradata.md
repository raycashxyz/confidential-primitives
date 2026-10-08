---
"@raycashxyz/confidential-primitives": minor
---

**Breaking:** `initWrap` takes a fourth parameter, `bytes calldata extraData`, so implementations
can accept options without new entrypoints. Empty selects the default behaviour and malformed
options revert `InvalidExtraData`. `BatchedStealthWrapAdapter` reads
`abi.encode(uint256 expectedBatchId)` to pin the deposit to the batch the depositor inspected,
reverting `NotCurrentBatch` without moving funds if it would land elsewhere.
`ContinuousStealthWrapAdapter` accepts only empty.
