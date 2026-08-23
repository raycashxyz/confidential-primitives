---
"@raycashxyz/confidential-primitives": patch
---

`permitTransferFrom` no longer grants the spender ACL access to the signed cheque cap, so a contract
spender cannot persist the grant and decrypt the owner's ceiling.
