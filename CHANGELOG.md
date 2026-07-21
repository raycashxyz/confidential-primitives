# @raycashxyz/confidential-primitives

## 0.5.0

### Minor Changes

- 3030e0c: `BatchedStealthWrapAdapter` now exposes extension points for alternate deposit-acquisition flows. Its batch recording is available through internal `_recordBatchedDeposit`, and `initWrap` and `finalizeWrap` are virtual for derived adapters.
- 2542768: RecurringAllowance grows three integrator-facing features:

  - **Signature permits (the Permit2 analog for confidential tokens).** Because amounts are ciphertexts, a permit signs the ciphertext handle, with the input proof bound to the named spender as submitter. `permitSetPermission` creates a permission from an owner's off-chain EIP-712 signature (gasless grants — the spender submits and pays); `permitTransferFrom` executes a one-shot transfer up to a signed encrypted cap, optionally recipient-bound (a "confidential cheque", oblivious over-cap denial). Permit2-style unordered nonce bitmaps with `invalidateUnorderedNonces` for bulk cancellation; ECDSA and ERC-1271 signers.
  - **On-chain grant enumeration.** `getGrantedPairs`/`getGrantedPairCount`/`getGrantedPairAt` list every (token, spender) pair a user has permissions for, maintained as an invariant across create/invalidate/lockdown/prune — wallets can render and revoke every grant without an indexer.
  - **`tryTransferFrom`.** Lenient batch for payment processors: items failing a cleartext precondition (no active permission window, token call reverting — e.g. an expired operator grant) are skipped with a `TransferSkipped(reason)` event instead of reverting the whole batch. Encrypted denials still execute obliviously, exactly like `transferFrom`.

- 03af1a2: New primitive: `RecurringAllowance` — encrypted, period-based spending permissions for ERC-7984 confidential tokens ("100 USDC/day", with the amount encrypted). A user makes the contract an ERC-7984 operator once, then grants per-spender budgets that `transferFrom` enforces homomorphically; denied spends transfer an encrypted zero and are indistinguishable on-chain from permitted ones.

  Migrated from the internal FHEPermit and hardened in review:

  - underflow-safe limit checks — FHE arithmetic wraps, so the previous `amount <= limit - spent` check turned "limit lowered below current spend" into a near-unlimited budget
  - validated `updatePermission` with period-grid re-anchoring — moving `startTime` forward can no longer brick a key with a checked-arithmetic panic
  - `MAX_PERMISSIONS` cap per (user, token, spender) so a key can never grow past the FHEVM HCU budget
  - reentrancy guards on both `transferFrom` overloads (the token address is caller-supplied)
  - `spent` is credited with the token's actual transferred amount, so balance-short pulls no longer burn allowance
  - added the missing `invalidatePermission` (single-grant revocation) and an `AllowanceTransfer` event
  - ships with `IRecurringAllowance` and a `MockConfidentialToken` test mock

### Patch Changes

- 217b247: RecurringAllowance signature-permit hardening and correctness fixes (pre-audit review follow-up):

  - **HIGH — ERC-1271 cross-account replay.** The permit digest now binds `owner`, so a signature authorizing one smart account can no longer be replayed against a sibling account that shares the same underlying signer. Added a `Mock1271Wallet` and cross-account replay regression tests for both `permitSetPermission` and `permitTransferFrom`.
  - **Permit epoch / `invalidateAllPermits`.** A per-owner epoch is mixed into every permit digest; bumping it cancels all outstanding permit signatures at once — the signature-level counterpart to `lockdown` (which only revokes stored permissions). `lockdown` docs now cross-reference it.
  - **`updatePermission` no longer resets `spent` on an unchanged value.** Re-submitting the same `duration`/`startTime` is now a no-op, so a wallet echoing back a full record can't silently refresh a spender's budget. A grid change re-anchors `lastUpdated` to the current time (not the past `startTime`), so the current period stays fresh without an immediate re-reset.
  - **Efficiency.** `SignatureChecker.isValidSignatureNowCalldata`; grant ACL + pair-tracking only on the first permission under a key (E_ZERO is shared and grants are permanent); cleartext checks moved before `FHE.fromExternal` so invalid inputs revert without paying for proof verification; cached loop lengths, unchecked increments, and skipped self-assignment before `pop`. Measured `transferFrom` at 8 active permissions dropped ~2%.
  - **Docs.** Corrected the `lastUpdated` invariant for future-dated permissions; `getGrantedPairAt` reverts `PermissionNotFound` on an out-of-range index instead of a bare panic.

- 516d627: Production housecleaning:

  - **Published package no longer ships the test mocks.** `files` now lists the `adapters`, `allowances`, and `interfaces` source only — `contracts/mocks/*` (MockUSDC, MockConfidentialToken, Mock1271Wallet, MockERC7984ERC20Wrapper) were being published and could be mistaken for production contracts.
  - **`IRecurringAllowance` gains per-function NatSpec.** The interface is the consumer-facing API surface; every function now carries a `@notice`.
  - **Type-safety.** Added a `typecheck` script (`tsc --noEmit`) and CI step, and fixed three latent `bigint`/`number` type errors in the test suite that esbuild silently tolerated (ERC-7984 `until` is a uint48 → `number`). Switched `moduleResolution` to `bundler` so `tsc` resolves the ESM dependency graph (tevm/`ox`, which ship raw `.ts`) through their declaration files, which `skipLibCheck` then skips — otherwise `tsc` type-checks that source and errors on it.
  - **Shared nonce-space caveat documented.** `PermitGrant` and `PermitSpend` draw from one per-owner nonce space; `UnorderedNonces` and the interface now warn integrators to allocate from a single shared sequence per owner rather than restarting per permit type.

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
