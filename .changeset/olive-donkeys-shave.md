---
"@raycashxyz/confidential-primitives": minor
---

`RecurringAllowance` now checks that every handle a token returns is one the token is authorized
on, and reverts `InvalidReturnedHandle` on every path when the check fails.

Ciphertext handles are global rather than namespaced per token, and `token` is a caller-supplied
address, so a malicious token could return any handle in place of its transfer result. Because this
contract calls `FHE.allowThis` on every user's `limit` and `spent`, and those handles are public via
`getPermission`/`PermissionSet`, the substituted handle was added into the attacker's own `spent` and
then granted to them, making any user's encrypted limit or spend history decryptable by anyone.

The returned handle must now be initialized and ACL-authorized to the returning token, which an
honestly computed result always is (`ERC7984._update` ends with `FHE.allowThis(transferred)`). The
check is `FHEUtils.isAuthorizedOn`.

`tryTransferFrom` reverts here too, rather than skipping the item. Every other lenient-path failure
is a cleartext precondition the caller can fix, such as no permission window or no operator grant, and skipping
those is the point of the function. An unauthorized return handle is different in kind. No conforming
ERC-7984 can produce one, so it is evidence the counterparty is hostile, and `token` is supplied per
item by the caller, so skipping would settle unrelated payers in the same transaction as a contract
already caught lying about its return value. Reverting also unwinds the transfer that call had
already made, which a skip could not. The trade is that one hostile token takes the honest items in
its batch with it. Screen tokens before batching, or submit suspect ones in their own call.
