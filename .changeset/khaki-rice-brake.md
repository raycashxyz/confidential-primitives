---
"@raycashxyz/confidential-primitives": patch
---

Docs: a payment request is a message from the payee and must be authenticated out of band. The
depositor pays for whatever address the ciphertext encodes and cannot inspect it, so an encryption of
any address other than the intended recipient loses the payment. Another party's address redirects
it, and the zero address strands it in escrow, since `finalizeWrap` rejects `address(0)` and no
permitted recipient can match such a deposit.
