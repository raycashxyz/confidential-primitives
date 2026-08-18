---
"@raycashxyz/confidential-primitives": patch
---

`ContinuousStealthWrapAdapter.finalizeWrap` now uses the scalar `FHE.eq` overload, matching the
batched adapter. It was trivially encrypting the public `recipient` argument before comparing, which
forced the ciphertext-ciphertext overload at 137,000 HCU per scanned slot instead of 117,000. Since
the per-transaction HCU budget is what bounds `ids.length`, and `ids.length` is the anonymity set,
this raises the maximum decoy set as well as cutting gas.
