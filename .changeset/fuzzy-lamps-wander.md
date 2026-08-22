---
"@raycashxyz/confidential-primitives": minor
---

Recipient-handle freshness is now an overridable policy rather than a hard-coded rule.
`StealthWrapAdapter._consumeRecipientHandle(bytes32)` is `virtual` and still single-use by default,
and the bundled adapters behave as before. The used-handle record is the adapter's own persistent
ACL grant on the stored handle, read back through `FHEUtils.isFresh`, so an override that permits
reuse is an empty body and `recipientHandleUsed` still reports history.

The typed import in `_verifyRecipient`, which also rejects an empty proof, stays outside the hook
and non-overridable, so a derived adapter can relax freshness without being handed a way to relax the
type check that closes the `Bool` / `euint64` recipient attacks.

This exists for deposit paths that already publish the grouping single-use protects. A CREATE2
deposit-address flow derives its address from the handle (`salt == handle`), which is the only binding that
tells a payer which recipient the address commits to, so it cannot rotate the handle, while the
payer's clear ERC-20 transfer to that public address already clusters the deposits before `initWrap`
runs. There single-use forbids the reuse without concealing anything, and blocks the only safe
recovery for a second (often accidental) transfer. Re-wrapping under a fresh handle can be neither
authenticated nor made safe. The deposit address cannot identify its own recipient, so recovery must
be permissionless and a bystander can substitute their own handle. Proving a match means either
publicly decrypting `FHE.eq(old, new)`, which reveals the very linkage, or `FHE.select`-ing to an
unclaimable recipient on mismatch, which lets anyone burn the funds. That leaves only a cleartext
sweep that doxxes the first deposit.

`MockReusableHandleAdapter` is the reference override and regression test for the extension point.
Adapters that take it are publicly linkable by recipient and must say so.
