---
"@raycashxyz/confidential-primitives": patch
---

`BatchedStealthWrapAdapter` clamps the amount a finalize credits to `claimed` at what was owed, so
`claimed <= matched` holds by construction rather than by trusting the configured wrapper's return
value. An honest wrapper never reports moving more than it was asked to, but that invariant is what
keeps `matched - claimed` from underflowing, and FHE arithmetic wraps, so an over-report would land
the next `matched - claimed` near 2^64. Against a soft-failing wrapper the oversized request just
moves zero and the recipient's remainder is stuck. Against an exact-or-revert one every later
finalize for that recipient reverts for good. Costs one `FHE.min` per batch finalized, not per slot,
and the clamped figure is what `WrapFinalized` reports, so the event and the ledger cannot disagree.
