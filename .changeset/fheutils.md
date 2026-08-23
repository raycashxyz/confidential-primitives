---
"@raycashxyz/confidential-primitives": minor
---

New `FHEUtils` library extending `@fhevm/solidity` for contracts that handle ciphertexts they did
not create. `fromExternalForThis` imports a caller-supplied ciphertext and grants ACL access to the
importing contract only, with an overload for every type `FHE.fromExternal` supports, passes the
expected type to the coprocessor, and reverts `MissingInputProof` on an empty proof. `isAuthorizedOn`
checks a handle an untrusted contract returns, taking the raw `bytes32` so one function covers every
type. `isFreshForThis` reads the ACL to tell whether the contract has accepted a handle before. `sum`
tree-reduces an array within the FHEVM depth budget. Both shipped contracts import every external
ciphertext through it, and the package publishes `contracts/fhe`.
