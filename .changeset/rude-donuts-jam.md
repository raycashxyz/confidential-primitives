---
"@raycashxyz/confidential-primitives": patch
---

Docs: `_trySpend`'s comment claimed "our state writes only happen on success". That holds for spend
accounting, but `_evaluatePermissions` runs before the try/catch and its permission maintenance
persists when the catch branch fires: expired entries stay pruned, a crossed period boundary stays
reset with `PermissionReset` emitted, and an emptied key stays unlisted from `getGrantedPairs`. The
comment now says which writes are conditional and which are not.
