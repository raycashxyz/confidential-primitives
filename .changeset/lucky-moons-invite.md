---
"@raycashxyz/confidential-primitives": minor
---

Require a non-empty `inputProof` when importing an encrypted input that is stored.

`FHE.fromExternal` has two branches: with a proof it calls the coprocessor's `verifyInput`, which
checks the handle's type; with an EMPTY proof it returns the handle verbatim after nothing but an
ACL check. Every path that persists an imported handle now rejects the empty-proof branch, so a
handle of the wrong type can no longer be stored:

- `StealthWrapAdapter._verifyRecipient` (used by both adapters' `initWrap`) — closes a pooled-escrow
  drain via a `Bool` recipient that compares equal to every address, a permanent escrow freeze via a
  `euint64` handle welded into a serial FHE dependency chain that trips the 5M per-tx depth budget,
  and a permanent brick of continuous finalize via any other wrong type.
- `RecurringAllowance.setPermission` / `permitSetPermission` — a non-`Uint64` limit made
  `_evaluatePermissions` revert, aborting a whole `tryTransferFrom` batch instead of skipping one row.

`updatePermission` still reads an empty proof as "leave the limit unchanged"; that sentinel is
unaffected.
