---
"@raycashxyz/confidential-primitives": minor
---

`BatchedStealthWrapAdapter.finalizeWrap` no longer has an all-or-nothing outcome per batch. Every id
in the set is processed. Each batch pays `matched - claimed` for the recipient and credits back what
the wrapper reports it moved, so a batch with nothing left to claim transfers an encrypted zero
instead of reverting. `AlreadyFinalized` is gone, along with the cleartext per-(batch, recipient)
flag it guarded.

That removes a front-running nuisance. `ids` and `recipient` are both visible in the mempool, so
when a repeat reverted, anyone could front-run `finalizeWrap([7, 8, 9], R)` with `finalizeWrap([7],
R)` and take the original down on batch 7, leaving 8 and 9 unfinalized. The front-runner never
gained funds, since the payout still went to `R`, but repeated cheaply it degraded multi-batch
finalization into a retry loop. A no-op repeat cannot do that.

`WrapFinalized` is now emitted once per batch, carrying that batch's id and the amount
credited, rather than once per call over the whole requested set.
