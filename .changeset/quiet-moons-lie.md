---
"@raycashxyz/confidential-primitives": patch
---

Docs: correct the recipient-privacy guarantee. `BatchedStealthWrapAdapter` described its handshake as
"how the depositor never learns the recipient", which does not hold against a contract depositor.

`FHE.fromExternal` grants transient ACL access on the verified ciphertext to `msg.sender` — and must,
since the input proof binds the handle to the depositor, which is the only reason a third party
cannot submit it. Transient access dies with the transaction, so an EOA gains nothing. A contract
depositor, still inside the same transaction, can call `FHE.allow` to persist it or
`FHE.makePubliclyDecryptable` to publish the value, and read the recipient address.

There is no adapter-layer fix: the grant happens inside `FHE.fromExternal` before any of our code
runs, FHEVM cannot revoke a transient allowance, and re-encrypting what is stored does not help
because the leak is on the input handle the depositor already holds. A real fix means the depositor
is not the proof-bound party — a different deposit API, not a patch.

The guarantee is now stated as what it is: the recipient is hidden from OBSERVERS.
