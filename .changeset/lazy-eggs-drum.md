---
"@raycashxyz/confidential-primitives": patch
---

Docs: `setPermission`'s `endTime` is documented as "must not be in the past" rather than "must be in
the future". `_checkWindow` only rejects `endTime < block.timestamp`, so `endTime ==
block.timestamp` is accepted when the window stays valid, with `startTime` resolving below it, which is correct given the interface's inclusive-expiry semantics
(active while `block.timestamp <= endTime`). Only the wording was wrong.
