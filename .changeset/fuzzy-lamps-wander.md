---
"@raycashxyz/confidential-primitives": minor
---

Recipient-handle freshness is now an overridable policy rather than a hard-coded rule.
`StealthWrapAdapter._consumeRecipientHandle(bytes32)` is `virtual` and still single-use by default
(the bundled adapters behave exactly as before), with `_recordRecipientHandle(bytes32)` available so an
override that permits reuse can keep `recipientHandleUsed` truthful.

The empty-proof gate in `_verifyRecipient` is deliberately NOT part of the hook and remains
non-overridable: it is the coprocessor type check that closes the `Bool` / `euint64` recipient
attacks, so a derived adapter can relax freshness without being handed a way to relax that.

This exists for deposit paths that already publish the grouping single-use protects. A CREATE2
deposit-address flow derives its address from the handle (`salt == handle`), which is the only binding that
tells a payer which recipient the address commits to, so it cannot rotate the handle, while the
payer's clear ERC-20 transfer to that public address already clusters the deposits before `initWrap`
runs. There single-use forbids the reuse without concealing anything, and blocks the only safe
recovery for a second (often accidental) transfer: re-wrapping under a fresh handle can be neither
authenticated (the deposit address cannot identify its own recipient, so recovery must be
permissionless and a bystander can substitute their own handle) nor made safe (proving a match means
either publicly decrypting `FHE.eq(old, new)`, which reveals the very linkage, or `FHE.select`-ing to
an unclaimable recipient on mismatch, which lets anyone burn the funds), leaving only a cleartext
sweep that doxxes the first deposit.

`MockReusableHandleAdapter` is the reference override and regression test for the extension point.
Adapters that take it are publicly linkable by recipient and must say so.
