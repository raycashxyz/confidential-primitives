---
"@raycashxyz/confidential-primitives": minor
---

Add BatchedAsyncWrapperV2 and ConfidentialSealedBidAuction; upgrade to OpenZeppelin confidential-contracts 0.5.1.

- **BatchedAsyncWrapperV2**: cleartext `(batch, recipient)` nullifier + tree-reduced payout sum (`O(log N)` FHE depth). Finalizes batches the serial designs cannot (the depth cap binds them at ~28); cheapest finalize at every batch size; `sealBatch` liveness escape hatch for partial tail batches; batch cap 48 (bounded by the 20M total-HCU budget, measured + analytic).
- **ConfidentialSealedBidAuction**: first-price sealed-bid auction — bids stay encrypted forever, only the clearing price is decrypted (KMS proof verified on-chain), winner self-identifies via `eq(bid, price)`.
- **Deps**: `@openzeppelin/confidential-contracts` 0.3.1 → 0.5.1, `@fhevm/solidity` 0.10 → 0.11.1, `@openzeppelin/contracts` ^5.6.1, `fhevm-tevm-mocks` ^0.3.0 (wrap/unwrap overrides updated for the new return types; `finalizeUnwrap` now takes an unwrap-request id).
- **Benchmark fix**: gas rows are recorded only from receipts with status `success` — FHE calls send with an explicit gas limit, so reverted finalizes still produced receipts and their gas-to-revert-point was previously recorded as a measurement. This surfaced that the bulk-bitmap finalize actually reverts at N=28 (HCU depth incl. the mint's balance update).
