---
"@raycashxyz/confidential-primitives": minor
---

Adds `RecurringAllowance.activePermissionCount(user, token, spender)` — the number of permissions a
spend would actually evaluate, which is what drives its FHE cost — and documents batch sizing on
both batch entry points.

`tryTransferFrom` exists so one bad item doesn't kill a batch, but it cannot cover budget
exhaustion: permission evaluation runs before the `try` opens, so an over-large batch reverts the
whole call and no `SkipReason` can name it. Items share no FHE work, so cost is the sum over items
and one payer's tier count moves the ceiling for everyone else in the call — from this repo's
benchmark, roughly 10 items at 2 active permissions each, 6 at 4, and 3 at 8.

Deliberately a view rather than an on-chain guard: an in-contract HCU model would silently skip valid
transfers as soon as the coprocessor repriced an operation.
