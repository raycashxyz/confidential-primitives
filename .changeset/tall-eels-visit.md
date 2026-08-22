---
"@raycashxyz/confidential-primitives": patch
---

`BatchedStealthWrapAdapter` emits `WrapInitiated` before `BatchSealed` when a deposit fills a batch.
The close ran first, so an event-only indexer replaying logs in order saw a batch seal before the
deposit that caused it. On-chain state was always correct. Only the log order was off.
