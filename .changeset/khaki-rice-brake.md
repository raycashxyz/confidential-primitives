---
"@raycashxyz/confidential-primitives": patch
---

Docs: state that a depositor cannot verify the encrypted recipient they're handed. Importing the
handle proves the ciphertext is well-formed and correctly bound but says nothing about the address
inside, so the handshake requires trusting whoever produced the handle. An encryption of someone else's
address redirects the payment. An encryption of the zero address destroys it, since `finalizeWrap`
rejects `address(0)` in cleartext and no permitted recipient can ever match such a deposit.

Client-side validation cannot close this, because the party encrypting is the party being trusted, and the
depositor cannot decrypt to check. Verify payment requests out of band.
