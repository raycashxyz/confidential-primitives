---
"@raycashxyz/confidential-primitives": minor
---

`RecurringAllowance` no longer overloads `PermissionNotFound` for three unrelated lookups. It was
declared as `PermissionNotFound(uint256 permissionIndex)` but raised with a permission index, a
stable permission id, and a granted-pair index, so the parameter name and NatSpec were wrong at two
of the three sites.

`PermissionNotFound(uint256 permissionId)` now means exactly what it says. `getPermission` reverts
`PermissionIndexOutOfRange` and `getGrantedPairAt` reverts `GrantedPairIndexOutOfRange`.
