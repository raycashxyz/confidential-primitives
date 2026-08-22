---
"@raycashxyz/confidential-primitives": minor
---

Adds `BatchedStealthWrapAdapter.initWrapInto(expectedBatchId, …)`, which deposits only if the caller
lands in the batch they inspected and otherwise reverts `NotCurrentBatch` without moving funds.

Which batch a deposit joins is decided at execution, so anyone could fill the remaining slots ahead
of a pending `initWrap` and displace it into a fresh, empty batch, the first half of a sandwich
whose second half is filling that batch with attacker-owned deposits and, at finalize, excluding
every slot the attacker knows isn't the recipient's.

Pinning closes the displacement half only. Nothing stops an attacker co-depositing into the batch you
pinned, and that has no contract-side fix, because an anonymity set is only as good as the share of it you
don't control. The README's privacy-model section now says so, and points at the client-side defence
this design does support. Deposits are sender-transparent, so a batch dominated by freshly funded
addresses is visible *before* you join it.
