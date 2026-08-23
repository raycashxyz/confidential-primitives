---
"@raycashxyz/confidential-primitives": minor
---

**Breaking:** `updatePermission` and `invalidatePermission` address a permission by its stable
`permissionId` alone. Array indices shift under the owner, so the index parameter and
`PermissionMismatch` are gone. `PermissionNotFound(permissionId)` now means what it says, with
`PermissionIndexOutOfRange` and `GrantedPairIndexOutOfRange` covering the view lookups.
