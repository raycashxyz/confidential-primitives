---
"@raycashxyz/confidential-primitives": patch
---

`BatchedStealthWrapAdapter` finalize is now retry-safe against a soft-failing wrapper. The cleartext
`(batch, recipient)` nullifier is replaced by an encrypted per-(batch, recipient) `claimed`
accumulator. `finalizeWrap` pays `matched - claimed` and credits back only the amount the wrapper
reports it moved. A transfer that soft-fails to zero, as on a freeze, pause, blacklist or hook veto,
or moves only part now leaves the exact remainder claimable instead of destroying the claim, and no
sequence can pay a recipient more than their matched sum. Each batch id is finalized independently
(one transfer per batch), so a partial fill is attributed correctly. Passing several ids is a
convenience, not a merge.

Consequences: `finalizeWrap` reverts `AlreadyFinalized` no longer, since a replay of a fully-claimed
batch is a no-op that transfers an encrypted zero. The `finalized(batchId, recipient)` bool view is
replaced by `claimedAmount(batchId, recipient)` returning the encrypted claimed handle, and
`WrapFinalized` is emitted once per batch. The claim commit now happens after the transfer, so the
finalize path relies on `nonReentrant` (already present).

This removes the exact-or-revert wrapper requirement on the batched finalize path only. The deposit
path, where `wrap` soft-fails while the underlying is retained, and the continuous adapter's finalize
, which consumes deposits by zeroing them and cannot attribute a partial in a flat pool, still require
an exact-or-revert wrapper. Both are documented.
