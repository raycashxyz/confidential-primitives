---
"@raycashxyz/confidential-primitives": patch
---

Docs: narrow the compatibility claims to what works. The README said the adapters work with
"any existing `ERC7984ERC20Wrapper`" and `IRecurringAllowance` described permissions over "any
ERC-7984 confidential token", but ERC-7984 treats confidential amounts as opaque `bytes32` pointers
and leaves their resolution implementation-specific, so it admits FHE, zero-knowledge systems and
enclaves alike. These contracts require Zama `euint64`/`eaddress` handles, the FHEVM ACL,
coprocessor-issued input proofs, and (for the adapters) OpenZeppelin's `underlying()`/`rate()`
wrapper extensions, which aren't part of ERC-7984 at all.

Adds a Compatibility section to the README stating the real requirements.
