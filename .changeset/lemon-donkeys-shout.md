---
"@raycashxyz/confidential-primitives": minor
---

`RecurringAllowance.tryTransferFrom` now escalates instead of skipping when a token returns an
encrypted handle it is not itself ACL-authorized on: the call reverts `InvalidReturnedHandle` and
the whole batch is unwound. `SkipReason.INVALID_RETURN_HANDLE` is removed, since it can no longer be
emitted (the enum value was last, so the remaining reasons keep their numbering).

Every other lenient-path failure is a cleartext precondition the caller can fix — no permission
window, no operator grant — and skipping those is the point of the function. An unauthorized return
handle is different in kind: no conforming ERC-7984 can produce one, because OpenZeppelin's `_update`
ends with `FHE.allowThis(transferred)`. It is evidence the counterparty is hostile rather than merely
unusable, and `token` is supplied per item by the caller, so skipping meant settling unrelated payers
in the same transaction as a contract already caught lying about its return value. Reverting also
unwinds the transfer that call had already made, which a skip could not.

The trade is explicit: one hostile token now takes the honest items in its batch with it. Screen
tokens before batching, or submit suspect ones in their own call.
