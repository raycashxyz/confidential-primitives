---
"@raycashxyz/confidential-primitives": minor
---

Rearchitect the async wrappers as an escrow layer over an existing `ERC7984ERC20Wrapper`, and consolidate the module set.

- **`StealthWrapAdapter`** (now `contracts/wrappers/base`) is no longer an ERC-7984 token itself. Instead of minting synthetic confidential balance on finalize, it escrows real confidential balance of a configured `CONFIDENTIAL_WRAPPER`: `initWrap` pulls clear ERC-20, calls `ERC7984ERC20Wrapper.wrap(address(this), amount)`, and records an encrypted recipient; `finalizeWrap` homomorphically selects matching deposits and `confidentialTransfer`s the tree-reduced sum to the cleartext recipient. This removes the OZ `wrap`/`unwrap`/`onTransferReceived` overrides and the manual supply-overflow check.
- **`ContinuousStealthWrapAdapter`**: caller-selected deposit ids from one shared pool with a `minDecoys` lower bound; matched deposit amounts are rewritten to encrypted zero (per-deposit nullifier).
- **`BatchedStealthWrapAdapter`**: fixed-size batches with a cleartext `(batch, recipient)` nullifier, tree-reduced payout sum (`O(log N)` FHE depth), and a timeout-gated `sealBatch` liveness escape hatch. Batch cap 48 (bounded by the FHEVM total-HCU budget). This folds in the former `BatchedAsyncWrapperV2`.
- **Removed** `BatchedAsyncWrapperV2` (folded into `BatchedStealthWrapAdapter`) and `ConfidentialSealedBidAuction`.
- **Layout**: `IStealthWrapAdapter` moved to `contracts/interfaces`; the abstract base moved to `contracts/wrappers/base`. Added `contracts/mocks/MockERC7984ERC20Wrapper` (a concrete OZ wrapper) for tests and local deploys.
- **Hardening**: `sealBatch` is `nonReentrant`, so a callback-capable underlying token can no longer seal the in-flight batch during `initWrap`'s token pull; the base constructor rejects a confidential wrapper whose `rate()` is zero (new `InvalidRate` error).
