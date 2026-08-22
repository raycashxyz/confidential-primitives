---
"@raycashxyz/confidential-primitives": minor
---

Adds `RecurringAllowance.activePermissionCount(user, token, spender)`, the number of permissions a
spend would evaluate, which is what drives its FHE cost. Batch sizing is documented on both
batch entry points.

`tryTransferFrom` exists so one bad item doesn't kill a batch, but it cannot cover budget
exhaustion, because permission evaluation runs before the `try` opens, so an over-large batch reverts the
whole call, with `HCULimit`'s `HCUTransactionLimitExceeded` or `HCUTransactionDepthLimitExceeded`
naming the budget, and the items that would have fit are lost with it. Items share no FHE work, so
cost is the sum over items and one payer's tier count moves the ceiling for everyone else in the
call. From this repo's benchmark, roughly 10 items at 2 active permissions each, 6 at 4, and 3 at 8.

This is a view for callers to plan with rather than an on-chain guard. The per-transaction budget
also pays for the token's own `confidentialTransferFrom`, which this contract cannot measure and
which can change under it, so a pre-count would need a margin that either over-skips items that
would have fit or under-skips and reverts anyway. The documented figures are a floor. Size batches
with them and with the token in mind.
