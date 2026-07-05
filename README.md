# @raycashxyz/confidential-primitives

Reusable confidential (FHE) smart-contract primitives for the [Zama FHEVM](https://docs.zama.ai/fhevm) stack — async **ERC-7984** token wrappers with recipient privacy, and a fully sealed first-price auction.

Built on [`@openzeppelin/confidential-contracts`](https://github.com/OpenZeppelin/openzeppelin-confidential-contracts) and [`@fhevm/solidity`](https://www.npmjs.com/package/@fhevm/solidity). MIT-licensed.

## Modules

### Async wrappers (`contracts/wrappers`)

Convert a cleartext ERC-20 into a confidential ERC-7984 token through a two-phase **deposit → finalize** flow with decoy-based recipient privacy: each deposit records an *encrypted* recipient, and `finalizeWrap` homomorphically sums the deposits belonging to a recipient without revealing which ones.

- **`ERC7984AsyncWrapper`** — abstract base: deposit recording, homomorphic decoy matching, and OpenZeppelin's async unwrap lifecycle.
- **`SimpleAsyncWrapper`** — minimal concrete wrapper; deposits are pulled via a direct `transferFrom`. Finalizes with the *rewrite* strategy (zero each matched deposit's encrypted amount).
- **`BatchedAsyncWrapper`** — deposits land in fixed-size batches tracked by a single **confidential bitmap** nullifier; the per-slot bitwise + ACL work is hoisted into one bulk pass per batch. (`finalizeWrapPerSlot` is the naive per-slot reference for the benchmark.)
- **`BatchedAsyncWrapperV2`** — the recommended wrapper. Replaces the confidential bitmap with a **cleartext `(batch, recipient)` nullifier** (the recipient is already public at finalize, so the bool leaks nothing new) and **tree-reduces** the payout sum so the FHE dependency *depth* is `O(log N)` instead of `O(N)`. Adds `sealBatch` (timeout-gated) so a tail batch that never fills can't strand funds. Batch cap 48.

### Sealed-bid auction (`contracts/auctions`)

- **`ConfidentialSealedBidAuction`** — first-price sealed-bid auction where **every bid stays encrypted forever**; the only value ever decrypted is the clearing price (threshold-KMS proof, verified on-chain via `FHE.checkSignatures`). The homomorphic max is tree-reduced; the winner self-identifies by proving `eq(myBid, clearingPrice)` — losing bids are never opened. No ZK circuits, no trusted auctioneer, no commit-reveal griefing.

## Why V2: the FHEVM cost model has two budgets

Every FHE op costs *HCU* on top of EVM gas, metered per transaction against **two caps**: total HCU (20M) and **sequential depth** (5M — the longest dependency chain). A serial accumulator `sum = FHE.add(sum, …)` is a depth-N chain (~162k HCU per add), so every serial finalize design hits the depth cliff near **N ≈ 28** — the bulk-bitmap path first (its outer add + the mint's balance update ride the same chain, so it already reverts at 28). V2's pairwise tree cuts the critical path to `ceil(log2 N)` adds; its binding limit becomes the *total* budget (~60 slots analytic), hence the 48 cap with headroom.

`finalizeWrap` gas (fhevm-tevm mock; rows only counted from receipts with status `success`), N deposits for one recipient:

| batch N | rewrite | bitmap (per-slot) | bitmap (batched) | **v2** |
| ---: | ---: | ---: | ---: | ---: |
| 4  | 628,049   | 709,226   | 631,920   | **458,137** |
| 8  | 972,465   | 1,099,134 | 888,728   | **626,399** |
| 16 | 1,661,308 | 1,878,962 | 1,402,349 | **962,763** |
| 28 | 2,694,584 | 3,048,734 | REVERT    | **1,467,534** |
| 32 | —         | —         | REVERT    | **1,635,338** |
| 48 | —         | —         | REVERT    | **2,308,230** |

V2 is the cheapest wherever a competitor fits (−27% vs rewrite at 4, −46% at 28) and the only design past the depth cliff. The benchmark also prints analytic total-HCU and depth-HCU tables derived from the `HCULimit` op-cost table.

> Reproduce with `pnpm test` (see the finalize gas benchmark). Numbers are from the FHEVM mock, i.e. on-chain EVM gas; absolute values shift on a live FHEVM network but the ranking holds.

## Install

```bash
pnpm add @raycashxyz/confidential-primitives
```

Solidity consumers import the sources directly:

```solidity
import {BatchedAsyncWrapper} from "@raycashxyz/confidential-primitives/contracts/wrappers/BatchedAsyncWrapper.sol";
import {BatchedAsyncWrapperV2} from "@raycashxyz/confidential-primitives/contracts/wrappers/BatchedAsyncWrapperV2.sol";
import {ConfidentialSealedBidAuction} from "@raycashxyz/confidential-primitives/contracts/auctions/ConfidentialSealedBidAuction.sol";
```

## Develop

```bash
pnpm install
pnpm compile   # hardhat compile (+ deployoor typed deployers)
pnpm test      # vitest + fhevm-tevm-mocks
```

## License

[MIT](./LICENSE)
