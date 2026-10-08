---
"@raycashxyz/confidential-primitives": patch
---

`_recordBatchedDeposit` persists ACL access to the stored `eAmount`, so a derived adapter holding
only transient authorization cannot record a deposit that finalize could never use.
