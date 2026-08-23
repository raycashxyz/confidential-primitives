---
"@raycashxyz/confidential-primitives": minor
---

**Breaking:** `BatchedStealthWrapAdapter.finalizeWrap` is retry-safe. Each batch keeps an encrypted
per-recipient `claimed` total; a finalize pays `matched - claimed` and credits back what the wrapper
reports it moved, clamped to what was owed. A transfer that moves zero or part leaves the exact
remainder claimable, and a repeat finalize pays an encrypted zero instead of reverting.
`AlreadyFinalized` and the `finalized(batchId, recipient)` view are replaced by
`claimedAmount(batchId, recipient)`, and `WrapFinalized` is emitted once per batch. This lifts the
exact-or-revert wrapper requirement from the batched finalize path.
