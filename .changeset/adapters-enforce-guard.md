---
"@raycashxyz/confidential-primitives": minor
---

`StealthWrapAdapter` enforces its reentrancy requirement in code. `_wrapIntoEscrow`,
`_transferWrapped` and `BatchedStealthWrapAdapter._recordBatchedDeposit` revert
`ReentrancyGuardRequired` when reached outside a `nonReentrant` entrypoint, so a derived adapter that
drops the guard fails on its first deposit or finalize instead of shipping a double-claim.
