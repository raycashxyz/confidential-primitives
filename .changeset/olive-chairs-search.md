---
"@raycashxyz/confidential-primitives": minor
---

`BatchedStealthWrapAdapter.getDepositsLength` now returns an exclusive upper bound for enumerating
deposit slots rather than the deposit count. Slots are indexed `batchId * maxBatchDeposits +
batchIndex`, so a batch sealed before it filled leaves its remaining slots empty forever. With a
batch size of four and one deposit in each of batches 0 and 1, the live slots are 0 and 4 while the
old return value was 2, so an integration iterating `[0, getDepositsLength())` silently missed the
deposit at slot 4.

The count is still available as `totalDeposits()`. `IStealthWrapAdapter` now documents
`getDepositsLength` as a bound that may include empty slots, which is also what the continuous
adapter's array length already was.
