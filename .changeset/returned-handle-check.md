---
"@raycashxyz/confidential-primitives": minor
---

`RecurringAllowance` rejects a token-returned handle the token is not ACL-authorized on, reverting
`InvalidReturnedHandle` on every spend path. Handles are global, so a caller-supplied token could
otherwise return someone else's stored ciphertext and have it folded into state the caller can
decrypt.
