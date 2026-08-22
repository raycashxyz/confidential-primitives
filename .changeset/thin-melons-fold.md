---
"@raycashxyz/confidential-primitives": patch
---

Docs: `MAX_BATCH_LIMIT`'s headroom claim now says what it does and does not cover. The 15-20%
margin accounts for the adapter's own per-slot work. `finalizeWrap` also calls into the configured
wrapper, and its `_update` draws on the same per-transaction budget. An `ERC7984Hooked` wrapper with
a few modules can add millions of HCU, enough to push a full 48-slot scan over the limit, and its
admin can `installModule` *after* deposits are escrowed, so a batch calibrated against a clean
wrapper can become unfinalizable later. `minDecoys` has the same exposure and is immutable.

Documented in `BatchedStealthWrapAdapter` and the README: size against the target wrapper's
post-module transfer cost, not a bare-mock measurement.
