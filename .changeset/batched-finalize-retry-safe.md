---
"@raycashxyz/confidential-primitives": minor
---

`BatchedStealthWrapAdapter` finalize is retry-safe and no longer all-or-nothing per batch. The
cleartext `(batch, recipient)` nullifier is replaced by an encrypted per-(batch, recipient) `claimed`
accumulator. `finalizeWrap` pays `matched - claimed` and credits back only what the wrapper reports
it moved, so a transfer that soft-fails to zero, as on a freeze, pause, blacklist or hook veto, or
moves only part leaves the exact remainder claimable, and no sequence can pay a recipient more than
their matched sum. A batch with nothing left to claim transfers an encrypted zero instead of
reverting.

That also removes a front-running nuisance. `ids` and `recipient` are visible in the mempool, so when
a repeat reverted, anyone could front-run `finalizeWrap([7, 8, 9], R)` with `finalizeWrap([7], R)`
and take the original down on batch 7, leaving 8 and 9 unfinalized. The front-runner never gained
funds, since the payout still went to `R`, but repeated cheaply it degraded multi-batch finalization
into a retry loop. A no-op repeat cannot do that.

**Breaking:** `AlreadyFinalized` and the `finalized(batchId, recipient)` bool view are gone. Read
`claimedAmount(batchId, recipient)` instead, the encrypted claimed handle. `WrapFinalized` is emitted
once per batch, carrying that batch's id and the amount credited, rather than once per call. Each
batch id is finalized on its own, with one transfer per batch, so passing several ids is a
convenience rather than a merge, and all ids still share one transaction, so a batch that reverts
takes the whole call with it. The claim commit happens after the transfer, so the finalize path
relies on the `nonReentrant` entrypoint, which the escrow helpers now enforce.

This removes the exact-or-revert wrapper requirement on the batched finalize path only. The deposit
path, where `wrap` soft-fails while the underlying is retained, and the continuous adapter's
finalize, which consumes deposits by zeroing them and cannot attribute a partial in a flat pool,
still require an exact-or-revert wrapper. Both are documented.
