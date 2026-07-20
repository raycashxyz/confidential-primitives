---
"@raycashxyz/confidential-primitives": patch
---

RecurringAllowance signature-permit hardening and correctness fixes (pre-audit review follow-up):

- **HIGH — ERC-1271 cross-account replay.** The permit digest now binds `owner`, so a signature authorizing one smart account can no longer be replayed against a sibling account that shares the same underlying signer. Added a `Mock1271Wallet` and cross-account replay regression tests for both `permitSetPermission` and `permitTransferFrom`.
- **Permit epoch / `invalidateAllPermits`.** A per-owner epoch is mixed into every permit digest; bumping it cancels all outstanding permit signatures at once — the signature-level counterpart to `lockdown` (which only revokes stored permissions). `lockdown` docs now cross-reference it.
- **`updatePermission` no longer resets `spent` on an unchanged value.** Re-submitting the same `duration`/`startTime` is now a no-op, so a wallet echoing back a full record can't silently refresh a spender's budget. A grid change re-anchors `lastUpdated` to the current time (not the past `startTime`), so the current period stays fresh without an immediate re-reset.
- **Efficiency.** `SignatureChecker.isValidSignatureNowCalldata`; grant ACL + pair-tracking only on the first permission under a key (E_ZERO is shared and grants are permanent); cleartext checks moved before `FHE.fromExternal` so invalid inputs revert without paying for proof verification; cached loop lengths, unchecked increments, and skipped self-assignment before `pop`. Measured `transferFrom` at 8 active permissions dropped ~2%.
- **Docs.** Corrected the `lastUpdated` invariant for future-dated permissions; `getGrantedPairAt` reverts `PermissionNotFound` on an out-of-range index instead of a bare panic.
