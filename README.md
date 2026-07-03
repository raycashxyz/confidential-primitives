# @raycashxyz/confidential-primitives

Reusable confidential (FHE) smart-contract primitives for the [Zama FHEVM](https://docs.zama.ai/fhevm) stack — starting with async **ERC-7984** token wrappers and a gas-optimized *batched-bitmap* finalize.

Built on [`@openzeppelin/confidential-contracts`](https://github.com/OpenZeppelin/openzeppelin-confidential-contracts) and [`@fhevm/solidity`](https://www.npmjs.com/package/@fhevm/solidity). MIT-licensed.

## Modules

### Async wrappers (`contracts/wrappers`)

Convert a cleartext ERC-20 into a confidential ERC-7984 token through a two-phase **deposit → finalize** flow with decoy-based recipient privacy: each deposit records an *encrypted* recipient, and `finalizeWrap` homomorphically sums the deposits belonging to a recipient without revealing which ones.

- **`ERC7984AsyncWrapper`** — abstract base: deposit recording, homomorphic decoy matching, and OpenZeppelin's async unwrap lifecycle.
- **`SimpleAsyncWrapper`** — minimal concrete wrapper; deposits are pulled via a direct `transferFrom`. Finalizes with the *rewrite* strategy (zero each matched deposit's encrypted amount).
- **`BatchedAsyncWrapper`** — deposits land in fixed-size batches tracked by a single **confidential bitmap** nullifier. Its `finalizeWrap(uint256[] ids, …)` takes *batch ids* (a length-1 array = one batch), matching the shared `IERC7984AsyncWrapper` signature, and hoists the per-slot bitwise + ACL work into one bulk pass per batch. (`finalizeWrapPerSlot` is kept as the naive per-slot reference for the benchmark.)

## Why the batched-bitmap finalize

Naively, a bitmap (one storage word for the whole batch) should be cheaper than rewriting each deposit. In an FHE contract it isn't — per-op FHE cost dwarfs an `SSTORE`. But once the bitwise nullifier work is **hoisted out of the per-slot loop** and the per-slot `SSTORE` + `FHE.allowThis` are collapsed into a single bulk write, it draws even at small batches and pulls increasingly ahead as the batch grows (≈24% cheaper at N=28).

`finalizeWrap` gas (FHEVM mock = pure EVM gas), N deposits for one recipient:

| batch N | rewrite | bitmap (per-slot) | **bitmap (batched)** | Δ vs rewrite |
| ---: | ---: | ---: | ---: | ---: |
| 4  | 628,093   | 709,314   | **632,008**   | +0.6%  |
| 8  | 972,509   | 1,099,222 | **888,816**   | −8.6%  |
| 16 | 1,661,352 | 1,879,050 | **1,402,437** | −15.6% |
| 28 | 2,694,628 | 3,048,822 | **2,044,350** | −24.1% |

> Reproduce with `pnpm test` (see the finalize gas benchmark). Numbers are from the FHEVM mock, i.e. on-chain EVM gas; absolute values shift on a live FHEVM network but the ranking holds.

## Install

```bash
pnpm add @raycashxyz/confidential-primitives
```

Solidity consumers import the sources directly:

```solidity
import {BatchedAsyncWrapper} from "@raycashxyz/confidential-primitives/contracts/wrappers/BatchedAsyncWrapper.sol";
```

## Develop

```bash
pnpm install
pnpm compile   # hardhat compile (+ deployoor typed deployers)
pnpm test      # vitest + fhevm-tevm-mocks
```

## License

[MIT](./LICENSE)
