---
"@raycashxyz/confidential-primitives": minor
---

RecurringAllowance grows three integrator-facing features:

- **Signature permits (the Permit2 analog for confidential tokens).** Because amounts are ciphertexts, a permit signs the ciphertext handle, with the input proof bound to the named spender as submitter. `permitSetPermission` creates a permission from an owner's off-chain EIP-712 signature (gasless grants — the spender submits and pays); `permitTransferFrom` executes a one-shot transfer up to a signed encrypted cap, optionally recipient-bound (a "confidential cheque", oblivious over-cap denial). Permit2-style unordered nonce bitmaps with `invalidateUnorderedNonces` for bulk cancellation; ECDSA and ERC-1271 signers.
- **On-chain grant enumeration.** `getGrantedPairs`/`getGrantedPairCount`/`getGrantedPairAt` list every (token, spender) pair a user has permissions for, maintained as an invariant across create/invalidate/lockdown/prune — wallets can render and revoke every grant without an indexer.
- **`tryTransferFrom`.** Lenient batch for payment processors: items failing a cleartext precondition (no active permission window, token call reverting — e.g. an expired operator grant) are skipped with a `TransferSkipped(reason)` event instead of reverting the whole batch. Encrypted denials still execute obliviously, exactly like `transferFrom`.
