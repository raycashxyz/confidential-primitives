---
"@raycashxyz/confidential-primitives": minor
---

`ContinuousStealthWrapAdapter`'s constructor now rejects `minDecoys` above `MAX_MIN_DECOYS` (40),
mirroring the batched adapter's `MAX_BATCH_LIMIT`. `minDecoys` is a floor every finalize must clear
and it is immutable, so a value above the executable scan size produced a deployment where deposits
still succeeded but no legal `ids` array could ever be finalized, since fewer ids revert `TooFewDecoys`,
more exceed the FHEVM budget, and there is no alternative finalization path.

This bounds only the configurable floor. A caller may still pass more ids and pay for them.
