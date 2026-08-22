---
"@raycashxyz/confidential-primitives": patch
---

Docs: the "a submitted cheque always burns its nonce" guarantee is narrowed to successful
submissions. `permitTransferFrom` writes the nonce before the token call, so a token that REVERTS,
rather than returning an encrypted zero, rolls the bitmap write back and leaves the cheque
submittable until `sigDeadline`. The case that matters is an owner who has never received
confidential tokens, where some implementations revert on the uninitialized balance handle instead
of treating it as zero. Owners who need such a cheque gone must cancel it with
`invalidateUnorderedNonces` or `invalidateAllPermits`.
