---
"@raycashxyz/confidential-primitives": patch
---

Docs: `_chequeAmount` and `permitTransferFrom` no longer describe the cheque cap as `min(requested,
cap)`. The rule is all-or-nothing: a request of 150 against a cap of 100 moves an encrypted zero,
not 100. The nonce is consumed either way, so the signer must issue a fresh cheque to retry.
The implementation is unchanged; the `min` label could have led an integrator to build the wrong
client-side expectation.
