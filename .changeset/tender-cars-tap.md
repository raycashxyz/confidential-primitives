---
"@raycashxyz/confidential-primitives": patch
---

Docs: note that wrapper-local transfer restrictions see the adapter, not the depositor. `initWrap`
pulls the underlying itself and then calls `wrap(address(this), amount)`, so a wrapper that gates on
`msg.sender` or the wrap recipient (a deny-list or compliance module) checks the adapter and
passes. A depositor the wrapper would have blocked on a direct `wrap` can still originate one through
the adapter. This is inherent to interposing a contract; wrapper operators who need those checks
enforced must apply them to the adapter's deposit path or decline to have one pointed at their
wrapper.
