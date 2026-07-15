# @raycashxyz/confidential-primitives

Reusable confidential (FHE) smart-contract primitives for the [Zama FHEVM](https://docs.zama.org/fhevm), built on [`@openzeppelin/confidential-contracts`](https://github.com/OpenZeppelin/openzeppelin-confidential-contracts) and [`@fhevm/solidity`](https://www.npmjs.com/package/@fhevm/solidity). MIT-licensed.

## Why this exists

[Raycash](https://www.raycash.xyz/) is a self-custodial money account built on confidential stablecoins: you deposit ordinary USDC or USDT and hold it as a balance whose amount stays encrypted on-chain, powered by [Zama](https://www.zama.org/)'s fully homomorphic encryption. Getting money *into* that confidential world means turning a public ERC-20 into a confidential [ERC-7984](https://docs.openzeppelin.com/confidential-contracts/token) balance. It's the step we run most, and today it's the last one that isn't private by default.

Building Raycash, we kept rewriting the same low-level plumbing for that step. `confidential-primitives` is those pieces, pulled out of our own stack and hardened into standalone, reusable contracts. We built them for Raycash, but nothing here is Raycash-specific: if you're building on confidential tokens, they're meant to drop straight into your project.

This is our first release, and we're starting with the primitive we reached for first: our wrappers. More will follow.

## The wrappers

An [`ERC7984`](https://docs.openzeppelin.com/confidential-contracts/token) confidential token keeps balances and transfer amounts encrypted. That part is solved, and it works exactly as intended. Since most value already lives as ordinary ERC-20 (the USDC and USDT in circulation), the usual way for it to *become* confidential is to wrap: you deposit an ERC-20 and OpenZeppelin's [`ERC7984ERC20Wrapper`](https://docs.openzeppelin.com/confidential-contracts/token) mints the confidential equivalent one-for-one. That wrap happens in a single transaction through `wrap(to, amount)`. It keeps the on-ramp simple and cheap, but it leaves that one transaction publicly observable: `to` and `amount` are cleartext, so the chain records who received how much at the moment of entry. Everything after the wrap is private by design; the wrap itself is the only step on view.

For someone wrapping to their own address, that's a fine and widely accepted trade. But when you wrap *to* someone else (paying a counterparty, funding a desk), that first transaction ties a public deposit to the recipient of the freshly minted confidential tokens. It's a link, and it's often the one fact you wanted to keep private.

Our wrappers close that last gap. They give the first mile the same privacy as everything after it, without changing the token itself. A depositor puts in a **public** amount for an **encrypted** recipient. The funds are wrapped into confidential balance held in escrow, then delivered to the recipient in a separate, mixed step, so an observer sees public deposits go in and confidential balances come out but can't tie a given deposit to the recipient it funded. The privacy comes from mixing each deposit into a crowd, so delivery can't share a transaction with the deposit. The flow is two-phase:

- **`initWrap`** escrows a deposit and records an *encrypted* recipient.
- **`finalizeWrap`** homomorphically hands each recipient the sum of the deposits addressed to them, mixed in with decoys so observers can't tell which deposits were real.

[Valerio's article](https://x.com/valerioHQ/status/2071658396583948427) introduced the design: decoys plus an asynchronous, two-step wrap that break the link between the ERC-20 you deposit and the confidential ERC-7984 you receive. These contracts sit on top of an existing `ERC7984ERC20Wrapper`: they don't reimplement the confidential token, they escrow it. Downstream nothing changes. Once finalized, the recipient holds ordinary ERC-7984.

We ship two, trading caller control for built-in structure:

- **`SimpleAsyncWrapper`** is the flexible one: the caller chooses exactly which deposits to finalize together, so they control the decoy set. That's maximum control, but privacy is only as strong as the decoys they pick.
- **`BatchedAsyncWrapper`** is the opinionated one: deposits fall into fixed-size batches, and the whole batch *is* the anonymity set, so privacy is structural instead of caller-chosen. The cost is waiting for a batch to fill (or time out).

Both are detailed below.

## How it works

1. Deploy or choose an `ERC7984ERC20Wrapper` for your ERC-20.
2. Deploy an async wrapper pointed at that confidential wrapper.
3. The depositor approves the async wrapper for the clear ERC-20, then calls `initWrap` with an encrypted recipient.
4. `initWrap` pulls the clear ERC-20, calls `ERC7984ERC20Wrapper.wrap(address(this), amount)`, and records the encrypted recipient in escrow.
5. `finalizeWrap` homomorphically selects the deposits matching a recipient and transfers the resulting confidential balance from escrow to that recipient.

The underlying `ERC7984ERC20Wrapper` handles unwrapping back to the clear ERC-20 once the recipient holds confidential balance.

## Choosing a wrapper

| Property | `SimpleAsyncWrapper` | `BatchedAsyncWrapper` |
| --- | --- | --- |
| Finalization unit | Caller-selected deposit ids | Closed batch ids |
| Anonymity set | The selected ids, with `minDecoys` as a lower bound | Every deposit in the closed batch |
| Decoy quality | Flexible, but caller-controlled | Protocol-shaped by batch size and seal delay |
| Replay protection | Matched encrypted deposit amounts are rewritten to zero | Clear `(batch, recipient)` nullifier |
| Liveness | Can finalize as soon as enough decoys exist | Batch fills, or closes after `sealDelay` on `sealBatch` / first finalize |
| Max measured finalize | 32 ids in the current benchmark; 48 reverts | 48-slot batch succeeds |

`SimpleAsyncWrapper` is the flexible primitive: callers can choose any sorted deposit ids, but weak decoy selection produces a weak anonymity set. `BatchedAsyncWrapper` is stricter: the anonymity set is the whole closed batch, which gives a clearer privacy rule at the cost of batching latency. Partial tail batches can still close after `sealDelay`, either through `sealBatch` or automatically on the first eligible `finalizeWrap`, so funds can't get stranded in a batch that never fills.

## Privacy model

| Signal | Visibility |
| --- | --- |
| Depositor | Public on `initWrap` |
| Clear ERC-20 amount | Public on `initWrap` |
| Recipient before finalize | Encrypted `eaddress` |
| Recipient at finalize | Public function argument |
| Finalized amount | Encrypted `euint64` transfer |
| Which deposits matched | Hidden inside the selected set or batch |

## Tree-reduced finalize

Every FHE op costs HCU on top of EVM gas, with both total-work and sequential-depth caps. A serial accumulator like `sum = FHE.add(sum, payout)` creates a depth-N dependency chain. Both wrappers instead collect per-deposit payouts and reduce them pairwise, so the add depth is `ceil(log2 N)`.

The batched wrapper caps batches at 48 slots so a one-batch finalize stays inside the current FHEVM budget with headroom. Near that cap, finalize one batch per transaction; multi-batch finalization is for smaller batches.

## Gas snapshot

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

The ceiling matters more than the gas delta: the simple wrapper finalizes 32 selected ids here but reverts at 48, while the batched wrapper reaches the configured 48-slot cap. Batched finalization is also cheaper at every measured size because it doesn't rewrite every matched deposit amount in storage and uses a clear `(batch, recipient)` nullifier.

## Repository layout

- `contracts/interfaces/IERC7984AsyncWrapper.sol`: shared interface and common errors.
- `contracts/wrappers/base/ERC7984AsyncWrapper.sol`: the abstract base, holding escrow funding, the confidential-transfer helper, and the tree-sum reduction.
- `contracts/wrappers/SimpleAsyncWrapper.sol`: concrete caller-selected-id implementation.
- `contracts/wrappers/BatchedAsyncWrapper.sol`: concrete batched implementation.
- `contracts/mocks/`: test-only helpers (a configured OZ wrapper and a mock ERC-20).

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
