---
"@raycashxyz/confidential-primitives": patch
---

`RecurringAllowance.updatePermission` resolves and validates the effective time window before
importing a replacement limit. It previously ran `FHE.fromExternal` and three ACL grants first, so a
caller whose window was invalid still paid for coprocessor proof verification only to have it rolled
back — even though every reason to reject was already available in cleartext, and permission
creation validates in that order.
