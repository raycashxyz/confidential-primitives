# @raycashxyz/confidential-primitives

Reusable confidential (FHE) smart-contract primitives for the [Zama FHEVM](https://docs.zama.ai/fhevm) stack.

Built on [`@openzeppelin/confidential-contracts`](https://github.com/OpenZeppelin/openzeppelin-confidential-contracts) and [`@fhevm/solidity`](https://www.npmjs.com/package/@fhevm/solidity). MIT-licensed.

## Async Wrappers

The wrappers add recipient privacy to an existing OpenZeppelin `ERC7984ERC20Wrapper` through a two-phase **deposit -> finalize** flow.

1. Deploy or choose an `ERC7984ERC20Wrapper` for the ERC20.
2. Deploy an async wrapper with that confidential wrapper address.
3. The depositor approves the async wrapper for clear ERC20, then calls `initWrap` with an encrypted recipient.
4. `initWrap` pulls clear ERC20, calls `ERC7984ERC20Wrapper.wrap(address(this), amount)`, and records the encrypted recipient.
5. `finalizeWrap` homomorphically selects matching deposits and transfers the resulting confidential balance from async escrow to the public recipient.

Unwrapping is handled by the configured `ERC7984ERC20Wrapper` after the recipient receives confidential balance.

## Layout

- `contracts/interfaces/IERC7984AsyncWrapper.sol` — shared interface and common errors.
- `contracts/wrappers/base/ERC7984AsyncWrapper.sol` — abstract ERC20 async adapter, escrow funding, wrapper transfer helper, and tree sum helper.
- `contracts/wrappers/SimpleAsyncWrapper.sol` — concrete arbitrary-id implementation.
- `contracts/wrappers/BatchedAsyncWrapper.sol` — concrete batch implementation.
- `contracts/mocks/MockERC7984ERC20Wrapper.sol` — test-only configured OZ wrapper.

## Implementations

| Property | `SimpleAsyncWrapper` | `BatchedAsyncWrapper` |
| --- | --- | --- |
| Finalization unit | Caller-selected deposit ids | Closed batch ids |
| Anonymity set | The selected ids, with `minDecoys` as a lower bound | Every deposit in the closed batch |
| Decoy quality | Flexible, but caller-controlled | Protocol-shaped by batch size and seal delay |
| Replay protection | Matched encrypted deposit amounts are rewritten to zero | Clear `(batch, recipient)` nullifier |
| Liveness | Can finalize as soon as enough decoys exist | Batch fills, or closes after `sealDelay` on `sealBatch` / first finalize |
| Max measured finalize | 32 ids in the current benchmark; 48 reverts | 48-slot batch succeeds |

## Privacy Model

| Signal | Visibility |
| --- | --- |
| Depositor | Public on `initWrap` |
| Clear ERC20 amount | Public on `initWrap` |
| Recipient before finalize | Encrypted `eaddress` |
| Recipient at finalize | Public function argument |
| Finalized amount | Encrypted `euint64` transfer |
| Which deposits matched | Hidden inside the selected set or batch |

`SimpleAsyncWrapper` is the flexible primitive: callers can choose any sorted deposit ids, but weak decoy selection produces a weak anonymity set. `BatchedAsyncWrapper` is stricter: the anonymity set is the whole closed batch, which gives a clearer privacy rule at the cost of batching latency. Partial tail batches can close after `sealDelay`, either via `sealBatch` or automatically on the first eligible `finalizeWrap`.

## Tree-Reduced Finalize

Every FHE op costs HCU on top of EVM gas, with both total-work and sequential-depth caps. A serial accumulator like `sum = FHE.add(sum, payout)` creates a depth-N dependency chain. Both wrappers collect per-deposit payouts and reduce them pairwise, so the add depth is `ceil(log2 N)`.

The batched wrapper caps batches at 48 slots so a one-batch finalize stays inside the current FHEVM budget with headroom. Near that cap, finalize one batch per transaction; multi-batch finalization is for smaller batches.

## Gas Snapshot

Measured with `pnpm test:bench` on `fhevm-tevm-mocks`. This table only compares `finalizeWrap`, where the privacy/anonymity tradeoff matters most. For `SimpleAsyncWrapper`, `N` is the number of selected deposit ids. For `BatchedAsyncWrapper`, `N` is the closed batch size.

| Anonymity set size `N` | Simple finalize | Batched finalize |
| ---: | ---: | ---: |
| 1 | 488,380 | 439,529 |
| 2 | 576,964 | 483,640 |
| 4 | 753,970 | 571,699 |
| 8 | 1,107,818 | 747,653 |
| 16 | 1,815,357 | 1,099,400 |
| 32 | 3,230,298 | 1,802,742 |
| 48 | REVERT | 2,528,895 |

The important result is the ceiling, not just the gas delta: the simple wrapper finalizes 32 selected ids in this benchmark but reverts at 48, while the batched wrapper reaches the configured 48-slot cap. Batched finalization is also cheaper at every measured size because it does not rewrite every matched deposit amount in storage and uses a clear `(batch, recipient)` nullifier.

## Install

```bash
pnpm add @raycashxyz/confidential-primitives
```

Solidity consumers import the sources directly:

```solidity
import {SimpleAsyncWrapper} from "@raycashxyz/confidential-primitives/contracts/wrappers/SimpleAsyncWrapper.sol";
import {BatchedAsyncWrapper} from "@raycashxyz/confidential-primitives/contracts/wrappers/BatchedAsyncWrapper.sol";
import {IERC7984AsyncWrapper} from "@raycashxyz/confidential-primitives/contracts/interfaces/IERC7984AsyncWrapper.sol";
```

## Develop

```bash
pnpm install
pnpm compile
pnpm test
pnpm test:bench
```

## License

[MIT](./LICENSE)
