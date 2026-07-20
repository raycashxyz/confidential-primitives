---
"@raycashxyz/confidential-primitives": patch
---

Production housecleaning:

- **Published package no longer ships the test mocks.** `files` now lists the `adapters`, `allowances`, and `interfaces` source only — `contracts/mocks/*` (MockUSDC, MockConfidentialToken, Mock1271Wallet, MockERC7984ERC20Wrapper) were being published and could be mistaken for production contracts.
- **`IRecurringAllowance` gains per-function NatSpec.** The interface is the consumer-facing API surface; every function now carries a `@notice`.
- **Type-safety.** Added a `typecheck` script (`tsc --noEmit`) and CI step, and fixed three latent `bigint`/`number` type errors in the test suite that esbuild silently tolerated (ERC-7984 `until` is a uint48 → `number`). Switched `moduleResolution` to `bundler` so `tsc` resolves the ESM dependency graph (tevm/`ox`, which ship raw `.ts`) through their declaration files, which `skipLibCheck` then skips — otherwise `tsc` type-checks that source and errors on it.
- **Shared nonce-space caveat documented.** `PermitGrant` and `PermitSpend` draw from one per-owner nonce space; `UnorderedNonces` and the interface now warn integrators to allocate from a single shared sequence per owner rather than restarting per permit type.
