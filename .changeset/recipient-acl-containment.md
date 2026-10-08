---
"@raycashxyz/confidential-primitives": patch
---

A deposit no longer grants the depositor transient ACL access to the encrypted recipient, so a
contract depositor cannot escalate that grant and decrypt the recipient it deposited for.
