---
"@raycashxyz/confidential-primitives": patch
---

Docs: warn that an exact exit forfeits unlinkability. Deposit amounts are public and rounded to the
wrapper's `rate()`, and finalize names the scanned set. The payout stays encrypted on-chain, but the
recipient can unwrap it publicly — and once its clear value is known, anyone can search the scanned
amounts for a subset summing to it. A unique match identifies the recipient's deposits exactly.

Nothing on-chain can prevent it: it happens after delivery under the recipient's own key. Recipients
should unwrap a different amount than they received, split withdrawals, or mix with other funds
first.
