---
"@raycashxyz/confidential-primitives": minor
---

`updatePermission` no longer resets `spent` on a `duration`/`startTime` change. The value carries
into the first period of the new grid and clears at that grid's next boundary, so a grid change
never releases budget. Owners who want a fresh budget revoke and re-grant.
