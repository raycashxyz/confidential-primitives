---
"@raycashxyz/confidential-primitives": patch
---

Docs: `ContinuousStealthWrapAdapter` now documents the two ways `minDecoys` misleads.

Cold start — finalization needs at least `minDecoys` existing deposits while `initWrap` has no
matching floor, so the first `minDecoys - 1` depositors in a quiet pool must wait. They can unblock
it by funding the missing deposits themselves, but `WrapInitiated` publishes depositor and clear
amount, so self-help costs exactly the privacy they came for.

Spent slots still count — a matched deposit's amount is zeroed but its slot stays a legal id forever
and is publicly indistinguishable from a live one, so an early sybil can seed the pool, drain their
own deposits, and leave a victim choosing decoys the attacker can rule out. `ids.length >= minDecoys`
says nothing about how many are real.
