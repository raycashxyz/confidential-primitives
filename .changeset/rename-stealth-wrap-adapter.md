---
"@raycashxyz/confidential-primitives": minor
---

Rename the wrapper family to `StealthWrapAdapter` (breaking) and restructure the README.

Upgrading from 0.3.0, swap the type and import names:

- `IERC7984AsyncWrapper` → `IStealthWrapAdapter`
- `ERC7984AsyncWrapper` (abstract base) → `StealthWrapAdapter`
- `SimpleAsyncWrapper` → `ContinuousStealthWrapAdapter`
- `BatchedAsyncWrapper` → `BatchedStealthWrapAdapter`

`initWrap` / `finalizeWrap`, the `WrapInitiated` / `WrapFinalized` events, and the error set are unchanged — only the type names and file paths change.
