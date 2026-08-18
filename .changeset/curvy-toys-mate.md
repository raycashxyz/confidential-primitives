---
"@raycashxyz/confidential-primitives": minor
---

`BatchedStealthWrapAdapter.finalizeWrap` now skips batches already finalized for the recipient
instead of reverting the whole call, and reverts `AlreadyFinalized` only when none of `ids` is left
to claim.

`ids` and `recipient` are both visible in the mempool, so treating the set as all-or-nothing let
anyone front-run `finalizeWrap([7, 8, 9], R)` with `finalizeWrap([7], R)`: the original reverted on
batch 7 and none of the remaining batches were finalized. The front-runner gained nothing — the
payout still went to `R` — but repeated cheaply it degraded multi-batch finalization into a retry
loop.

`WrapFinalized` now reports the ids actually scanned rather than everything requested, so the event
reflects the anonymity set the call really used.
