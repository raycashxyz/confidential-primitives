---
"@raycashxyz/confidential-primitives": minor
---

**Breaking:** `RecurringAllowance.updatePermission` and `invalidatePermission` now address a
permission by its stable `permissionId` alone. The `permissionIndex` parameter is gone, and
`PermissionMismatch` — which could no longer occur — has been removed from `IRecurringAllowance`.

An index was not an address the owner controlled. `_evaluatePermissions` swap-and-pops expired
entries, and a spender reaches that prune with a `tryTransferFrom` carrying an encrypted zero — no
funds move, and it does not even need an active permission, since the prune runs before `anyActive`
is decided and the lenient path returns rather than reverting, so the reorder commits. A spender
could therefore front-run the owner's revocation and make it revert on a stale index, surviving to
the next period reset and buying a further full limit.

Migration: drop the index argument. `updatePermission(token, spender, id, limit, proof, duration,
startTime, endTime)` and `invalidatePermission(token, spender, id)`. `MAX_PERMISSIONS` is 8, so the
lookup scan is cheap.
