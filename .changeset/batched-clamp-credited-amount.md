---
"@raycashxyz/confidential-primitives": patch
---

`BatchedStealthWrapAdapter` clamps the amount a finalize credits to `claimed` at what was owed, so
`claimed <= matched` holds by construction rather than by trusting the configured wrapper's return
value. An honest wrapper never reports moving more than it was asked to, but the adapter's
no-double-spend argument rests on that bound: exceed it and, because FHE arithmetic wraps, the next
`matched - claimed` lands near 2^64. Against a soft-failing wrapper the oversized request just moves
zero and the recipient's remainder is stuck; against an exact-or-revert one every later finalize for
that recipient reverts for good. Costs one `FHE.min` per finalize call, not per slot, and the clamped
figure is what `WrapFinalized` reports so the event and the ledger cannot disagree.
