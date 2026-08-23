---
"@raycashxyz/confidential-primitives": patch
---

Docs:
- verify a payment request really comes from the payee. The recipient address is encrypted by the
  payee and the depositor cannot decrypt it to check where the funds go
- unwrapping the exact amount received reveals which deposits paid you
- a cheque moves the requested amount or an encrypted zero
