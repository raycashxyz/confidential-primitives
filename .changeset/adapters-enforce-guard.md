---
"@raycashxyz/confidential-primitives": minor
---

`StealthWrapAdapter` enforces its reentrancy requirement in code. `_wrapIntoEscrow`,
`_transferWrapped` and `BatchedStealthWrapAdapter._recordBatchedDeposit` revert
`ReentrancyGuardRequired` when reached outside a `nonReentrant` entrypoint, so a derived adapter that
drops the guard fails on its first deposit or finalize instead of shipping a double-claim.

The ordering the guard protects differs per helper, and the NatSpec says so. `_wrapIntoEscrow` calls
out before the caller records its deposit. Around `_transferWrapped` it depends on the adapter. The
continuous one zeroes matched amounts before the transfer, the batched one credits its encrypted
`claimed` ledger after it, because the credit is the amount that call returns.
