---
"@raycashxyz/confidential-primitives": patch
---

Docs: `updatePermission` now warns that a `duration`/`startTime` change should be treated as issuing
a fresh budget. Because the re-anchor zeroes `spent`, a live spender who sees the pending update can
frontrun it to drain the old grid's remaining room, let the reset land, then backrun and spend up to
the limit again — roughly 2x one period around a single transaction, on top of the ~2x the existing
PERIOD GRID note describes for a natural rollover.

To tighten a live permission, prefer `invalidatePermission`/`lockdown` and re-grant, or lower only
the `limit` — a limit-only update keeps `spent` and blocks further spending immediately.
