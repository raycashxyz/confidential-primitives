---
"@raycashxyz/confidential-primitives": minor
---

`BatchedStealthWrapAdapter`'s seal deadline is now anchored to a batch's FIRST deposit instead of its
last. The sliding timer was resettable by anyone: while a batch still had free slots, a depositor
could submit the minimum wrappable amount just before the delay expired and push the deadline out
again, once per remaining slot, which stretches the worst case to roughly
`(maxBatchDeposits - fillCount) * sealDelay`. Because `finalizeWrap` names its recipient in cleartext
calldata, an observer could aim this at a specific pending finalization while also filling the
remaining slots with deposits it controls.

Adds `batchFirstDepositAt`. `batchLastDepositAt` is retained but is now informational only.

Size `sealDelay` as "how long a batch may spend gathering its anonymity set", not "how long it must
be idle": a slowly-filling batch is now sealable at a fixed age rather than after a quiet period.
