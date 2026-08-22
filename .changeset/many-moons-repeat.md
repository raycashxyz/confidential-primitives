---
"@raycashxyz/confidential-primitives": patch
---

Docs: `_chequeAmount` and `permitTransferFrom` no longer describe the cheque cap as `min(requested,
cap)`. The rule is all-or-nothing. A request of 150 against a cap of 100 moves an encrypted zero,
not 100. Both under-cap and over-cap submissions consume the nonce when the call succeeds, so the signer
must issue a fresh cheque to retry.
The implementation is unchanged. The `min` label could have led an integrator to build the wrong
client-side expectation.
