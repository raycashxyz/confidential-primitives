---
"@raycashxyz/confidential-primitives": minor
---

New primitive: `RecurringAllowance` — encrypted, period-based spending permissions for ERC-7984 confidential tokens ("100 USDC/day", with the amount encrypted). A user makes the contract an ERC-7984 operator once, then grants per-spender budgets that `transferFrom` enforces homomorphically; denied spends transfer an encrypted zero and are indistinguishable on-chain from permitted ones.

Migrated from the internal FHEPermit and hardened in review:

- underflow-safe limit checks — FHE arithmetic wraps, so the previous `amount <= limit - spent` check turned "limit lowered below current spend" into a near-unlimited budget
- validated `updatePermission` with period-grid re-anchoring — moving `startTime` forward can no longer brick a key with a checked-arithmetic panic
- `MAX_PERMISSIONS` cap per (user, token, spender) so a key can never grow past the FHEVM HCU budget
- reentrancy guards on both `transferFrom` overloads (the token address is caller-supplied)
- `spent` is credited with the token's actual transferred amount, so balance-short pulls no longer burn allowance
- added the missing `invalidatePermission` (single-grant revocation) and an `AllowanceTransfer` event
- ships with `IRecurringAllowance` and a `MockConfidentialToken` test mock
