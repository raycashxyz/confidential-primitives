---
"@raycashxyz/confidential-primitives": patch
---

Docs: declare exact-or-revert as a wrapper requirement where it is load-bearing. ERC-7984 permits an
operation to soft-fail, returning an encrypted zero (or less than requested) while the transaction
succeeds, and OpenZeppelin's own transfer is exact-or-zero rather than exact-or-revert.

On deposit, both adapters need the guarantee: OZ's wrapper moves the underlying before `_mint`, so a
rejecting mint hook makes the adapter record a zero-valued deposit against underlying the wrapper has
kept, with no refund path. That is not repairable here, because the shortfall is a cleartext amount
already pulled and the outcome that would have to gate it is a ciphertext.

On finalize the exposure differs by adapter, and the batched one no longer has it (see the
retry-safe finalize change in this release). The continuous adapter still does. It consumes deposits
by zeroing them before the transfer, and a flat pool cannot attribute a partial payout back to
individual deposits. Documented in `StealthWrapAdapter` and the README.
