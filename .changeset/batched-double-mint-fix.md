---
"@raycashxyz/confidential-primitives": patch
---

Fix a cross-path double-mint in `BatchedAsyncWrapper`. `finalizeWrapPerSlot` now requires a complete batch (like the bulk `finalizeWrap`), so slot commitment is all-or-nothing per recipient and the bulk replay gate stays sound even if both finalize paths run on the same batch. `initWrap` now follows Checks-Effects-Interactions (record the deposit before pulling tokens). Adds regression tests for the incomplete-batch guard and the cross-path no-double-mint invariant, plus event-assertion coverage, and narrows the gas-benchmark catch to rethrow non-revert errors.
