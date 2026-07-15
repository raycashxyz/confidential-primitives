# @raycashxyz/confidential-primitives

## 0.4.0

### Minor Changes

- Rename the wrapper family to `StealthWrapAdapter` (breaking) and restructure the README.

  Existing consumers swap the type and import names:

  - `IERC7984AsyncWrapper` → `IStealthWrapAdapter`
  - `ERC7984AsyncWrapper` (abstract base) → `StealthWrapAdapter`
  - `SimpleAsyncWrapper` → `ContinuousStealthWrapAdapter`
  - `BatchedAsyncWrapper` → `BatchedStealthWrapAdapter`

  `initWrap` / `finalizeWrap`, the `WrapInitiated` / `WrapFinalized` events, and the error set are unchanged. Only the type names and file paths change: imports move from `contracts/wrappers/` to `contracts/adapters/`.

## 0.3.0

### Minor Changes

- e2e396b: Rearchitect the async wrappers as an escrow layer over an existing `ERC7984ERC20Wrapper`, and consolidate the module set.

  - **`ERC7984AsyncWrapper`** (now `contracts/wrappers/base`) is no longer an ERC-7984 token itself. Instead of minting synthetic confidential balance on finalize, it escrows real confidential balance of a configured `CONFIDENTIAL_WRAPPER`: `initWrap` pulls clear ERC-20, calls `ERC7984ERC20Wrapper.wrap(address(this), amount)`, and records an encrypted recipient; `finalizeWrap` homomorphically selects matching deposits and `confidentialTransfer`s the tree-reduced sum to the cleartext recipient. This removes the OZ `wrap`/`unwrap`/`onTransferReceived` overrides and the manual supply-overflow check.
  - **`SimpleAsyncWrapper`**: caller-selected deposit ids with a `minDecoys` lower bound; matched deposit amounts are rewritten to encrypted zero (per-deposit nullifier).
  - **`BatchedAsyncWrapper`**: fixed-size batches with a cleartext `(batch, recipient)` nullifier, tree-reduced payout sum (`O(log N)` FHE depth), and a timeout-gated `sealBatch` liveness escape hatch. Batch cap 48 (bounded by the FHEVM total-HCU budget). This folds in the former `BatchedAsyncWrapperV2`.
  - **Removed** `BatchedAsyncWrapperV2` (folded into `BatchedAsyncWrapper`) and `ConfidentialSealedBidAuction`.
  - **Layout**: `IERC7984AsyncWrapper` moved to `contracts/interfaces`; the abstract base moved to `contracts/wrappers/base`. Added `contracts/mocks/MockERC7984ERC20Wrapper` (a concrete OZ wrapper) for tests and local deploys.
  - **Hardening**: `sealBatch` is `nonReentrant`, so a callback-capable underlying token can no longer seal the in-flight batch during `initWrap`'s token pull; the base constructor rejects a confidential wrapper whose `rate()` is zero (new `InvalidRate` error).

## 0.2.0

### Minor Changes

- 002e42c: Add BatchedAsyncWrapperV2 and ConfidentialSealedBidAuction; upgrade to OpenZeppelin confidential-contracts 0.5.1.

  - **BatchedAsyncWrapperV2**: cleartext `(batch, recipient)` nullifier + tree-reduced payout sum (`O(log N)` FHE depth). Finalizes batches the serial designs cannot (the depth cap binds them at ~28); cheapest finalize at every batch size; `sealBatch` liveness escape hatch for partial tail batches; batch cap 48 (bounded by the 20M total-HCU budget, measured + analytic).
  - **ConfidentialSealedBidAuction**: first-price sealed-bid auction — bids stay encrypted forever, only the clearing price is decrypted (KMS proof verified on-chain), winner self-identifies via `eq(bid, price)`.
  - **Deps**: `@openzeppelin/confidential-contracts` 0.3.1 → 0.5.1, `@fhevm/solidity` 0.10 → 0.11.1, `@openzeppelin/contracts` ^5.6.1, `fhevm-tevm-mocks` ^0.3.0 (wrap/unwrap overrides updated for the new return types; `finalizeUnwrap` now takes an unwrap-request id).
  - **Benchmark fix**: gas rows are recorded only from receipts with status `success` — FHE calls send with an explicit gas limit, so reverted finalizes still produced receipts and their gas-to-revert-point was previously recorded as a measurement. This surfaced that the bulk-bitmap finalize actually reverts at N=28 (HCU depth incl. the mint's balance update).

## 0.1.1

### Patch Changes

- ec62afa: Fix a cross-path double-mint in `BatchedAsyncWrapper`. `finalizeWrapPerSlot` now requires a complete batch (like the bulk `finalizeWrap`), so slot commitment is all-or-nothing per recipient and the bulk replay gate stays sound even if both finalize paths run on the same batch. `initWrap` now follows Checks-Effects-Interactions (record the deposit before pulling tokens). Adds regression tests for the incomplete-batch guard and the cross-path no-double-mint invariant, plus event-assertion coverage, and narrows the gas-benchmark catch to rethrow non-revert errors.
