---
"@raycashxyz/confidential-primitives": patch
---

Docs:

- the wrapper must be exact-or-revert on `wrap`, and on `confidentialTransfer` where the adapter's
  finalize path is not retry-safe
- wrapper-level transfer restrictions see the adapter as the counterparty, not the depositor
- verify a payment request really comes from the payee. The recipient address is encrypted by the
  payee and the depositor cannot decrypt it to check where the funds go
- unwrapping the exact amount received reveals which deposits paid you
- size `maxBatchDeposits` and `minDecoys` against the target wrapper's transfer cost
- a cheque moves the requested amount or an encrypted zero; a successful submission consumes its
  nonce, a reverting token call rolls it back
- `endTime` expiry is inclusive
- `tryTransferFrom`'s permission maintenance, pruning and period resets, persists on a skipped item
- a README Compatibility section states the Zama FHEVM requirements
