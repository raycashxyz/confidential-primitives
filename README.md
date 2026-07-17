# @raycashxyz/confidential-primitives

Reusable confidential (FHE) smart-contract primitives for the [Zama FHEVM](https://docs.zama.org/fhevm), built on [`@openzeppelin/confidential-contracts`](https://github.com/OpenZeppelin/openzeppelin-confidential-contracts) and [`@fhevm/solidity`](https://www.npmjs.com/package/@fhevm/solidity). MIT-licensed.

## Why this exists

[Raycash](https://www.raycash.xyz/) is a self-custodial money account built on confidential stablecoins: you deposit ordinary USDC or USDT and hold it as a balance whose amount stays encrypted on-chain, powered by [Zama](https://www.zama.org/)'s fully homomorphic encryption. Getting money *into* that confidential world means turning a public ERC-20 into a confidential [ERC-7984](https://docs.openzeppelin.com/confidential-contracts/token) balance. It's the step we run most, and today it's the last one that isn't private by default.

Building Raycash, we kept rewriting the same low-level plumbing for that step. `confidential-primitives` is those pieces, pulled out of our own stack and hardened into standalone, reusable contracts. We built them for Raycash, but nothing here is Raycash-specific: if you're building on confidential tokens, they're meant to drop straight into your project.

Two primitives so far, and more will follow:

- **[Stealth wrap adapters](#the-stealth-wrap-adapters)** — get funds *into* the confidential world without linking the deposit to its recipient.
- **[`RecurringAllowance`](#recurringallowance)** — let a spender pull funds on a budget ("100 USDC/day") without publishing the budget.

## The stealth wrap adapters

An [`ERC7984`](https://docs.openzeppelin.com/confidential-contracts/token) confidential token keeps balances and transfer amounts encrypted. That part is solved, and it works exactly as intended. Since most value already lives as ordinary ERC-20 (the USDC and USDT in circulation), the usual way for it to *become* confidential is to wrap: you deposit an ERC-20 and OpenZeppelin's [`ERC7984ERC20Wrapper`](https://docs.openzeppelin.com/confidential-contracts/token) mints the confidential equivalent one-for-one. That wrap happens in a single transaction through `wrap(to, amount)`. It keeps the on-ramp simple and cheap, but it leaves that one transaction publicly observable: `to` and `amount` are cleartext, so the chain records who received how much at the moment of entry. Everything after the wrap is private by design; the wrap itself is the only step on view.

For someone wrapping to their own address, that's a fine and widely accepted trade. But when you wrap *to* someone else (paying a counterparty, funding a desk), that first transaction ties a public deposit to the recipient of the freshly minted confidential tokens. It's a link, and it's often the one fact you wanted to keep private.

Our adapters close that last gap, and without replacing anything: a stealth wrap adapter works in concert with any existing `ERC7984ERC20Wrapper`, giving the first mile the same privacy as everything after it while handing back the very same confidential token. A depositor puts in a **public** amount for an **encrypted** recipient. The funds are wrapped into confidential balance held in escrow, then delivered to the recipient in a separate, mixed step, so an observer sees public deposits go in and confidential balances come out but can't tie a given deposit to the recipient it funded. The privacy comes from mixing each deposit into a crowd, so delivery can't share a transaction with the deposit. The flow is two-phase:

- **`initWrap`** escrows a deposit and records an *encrypted* recipient.
- **`finalizeWrap`** homomorphically hands each recipient the sum of the deposits addressed to them, mixed in with decoys so observers can't tell which deposits were real.

[Valerio's article](https://x.com/valerioHQ/status/2071658396583948427) introduced the design: decoys plus an asynchronous, two-step wrap that break the link between the ERC-20 you deposit and the confidential ERC-7984 you receive. Downstream nothing changes: once finalized, the recipient holds ordinary ERC-7984.

**`StealthWrapAdapter`** is the abstract base and the core of the design. It owns the escrow lifecycle (pull a deposit in, wrap it into escrowed confidential balance, and on finalize deliver the sum of a recipient's matched deposits back out) and leaves a single decision to its implementations: **how the anonymity set, the crowd of decoys, is formed.** That one axis is the only thing the two contracts we ship differ on:

- **`ContinuousStealthWrapAdapter`** is the flexible one: the caller chooses exactly which deposits to finalize together, so they control the decoy set. That's maximum control, but privacy is only as strong as the decoys they pick.
- **`BatchedStealthWrapAdapter`** is the opinionated one: deposits fall into fixed-size batches, and the whole batch *is* the anonymity set, so privacy is structural instead of caller-chosen. The cost is waiting for a batch to fill (or time out).

These two are a starting point, not the whole space. `StealthWrapAdapter` is built to be extended: implement `finalizeWrap` over its escrow and delivery, and you can form the anonymity set your own way (time-windowed, tiered by amount, allowlist-scoped, whatever your threat model calls for). If you build one, we'd love to see it.

### How it works

1. Deploy or choose an `ERC7984ERC20Wrapper` for your ERC-20.
2. Deploy a `ContinuousStealthWrapAdapter` or `BatchedStealthWrapAdapter` pointed at that confidential wrapper.
3. The depositor approves that adapter for the clear ERC-20, then calls `initWrap` with an encrypted recipient.
4. `initWrap` pulls the clear ERC-20, calls `ERC7984ERC20Wrapper.wrap(address(this), amount)`, and records the encrypted recipient in escrow.
5. `finalizeWrap` homomorphically selects the deposits matching a recipient and transfers the resulting confidential balance from escrow to that recipient.

The underlying `ERC7984ERC20Wrapper` handles unwrapping back to the clear ERC-20 once the recipient holds confidential balance.

### Choosing an adapter

Both `ContinuousStealthWrapAdapter` and `BatchedStealthWrapAdapter` are implementations of the abstract `StealthWrapAdapter` and share its escrow-and-deliver machinery. They differ only in how the anonymity set is formed, and that one difference cascades into privacy, liveness, and gas.

| Property | `ContinuousStealthWrapAdapter` | `BatchedStealthWrapAdapter` |
| --- | --- | --- |
| Finalization unit | Caller-selected deposit ids | Closed batch ids |
| Anonymity set | The selected ids, with `minDecoys` as a lower bound | Every deposit in the closed batch |
| Decoy quality | Flexible, but caller-controlled | Protocol-shaped by batch size and seal delay |
| Replay protection | Matched encrypted deposit amounts are rewritten to zero | Clear `(batch, recipient)` nullifier |
| Liveness | Can finalize as soon as enough decoys exist | Batch fills, or closes after `sealDelay` on `sealBatch` / first finalize |

`ContinuousStealthWrapAdapter` is the flexible primitive: callers can choose any sorted deposit ids, but weak decoy selection produces a weak anonymity set. `BatchedStealthWrapAdapter` is stricter: the anonymity set is the whole closed batch, which gives a clearer privacy rule at the cost of batching latency. Partial tail batches can still close after `sealDelay`, either through `sealBatch` or automatically on the first eligible `finalizeWrap`, so funds can't get stranded in a batch that never fills.

Gas is part of the same tradeoff. Measured with `pnpm test:bench` on `fhevm-tevm-mocks`, comparing `finalizeWrap` (`N` is the anonymity-set size: selected ids for continuous, batch size for batched):

| Anonymity set size `N` | Continuous finalize | Batched finalize |
| ---: | ---: | ---: |
| 1 | 488,380 | 439,529 |
| 2 | 576,964 | 483,640 |
| 4 | 753,970 | 571,699 |
| 8 | 1,107,818 | 747,653 |
| 16 | 1,815,357 | 1,099,400 |
| 32 | 3,230,298 | 1,802,742 |
| 48 | REVERT | 2,528,895 |

Batched is cheaper at every size and scales to a full 48-slot set; continuous costs more per decoy and reverts at 48 here. The gap is that continuous does more encrypted work per deposit: it matches against an encrypted recipient and rewrites each scanned deposit's amount in storage, where batched matches a cleartext recipient and uses a plain `(batch, recipient)` nullifier. That extra cost is the price of picking your own crowd: the same flexibility-versus-structure tradeoff, now in gas.

### Privacy model

Finalizing for a recipient `R` reveals only that "`R` ran a finalize over this set of deposits (or this batch)." It does **not** reveal which of those deposits were `R`'s: each deposit's encrypted recipient is compared to `R` homomorphically (`FHE.eq`, under encryption) and selected obliviously, so the chain never learns the per-deposit match. It doesn't even reveal whether *any* deposit matched: the payout is an encrypted sum that can be zero. So `R`'s address is public at finalize, but it stays unlinkable to any individual deposit.

| Signal | Visibility |
| --- | --- |
| Depositor | Public on `initWrap` |
| Clear ERC-20 amount | Public on `initWrap` |
| A deposit's recipient | Encrypted `eaddress`, set at `initWrap` |
| Recipient at finalize | Public address argument, but matched homomorphically against every scanned deposit, so unlinkable to any of them |
| Which deposits matched | Hidden (oblivious `FHE.select`) |
| Amount delivered | Encrypted `euint64`; can be zero |

## RecurringAllowance

The wrap adapters cover money coming *into* the confidential world. `RecurringAllowance` covers a step that comes after: letting someone spend your confidential balance on your behalf, within limits — without publishing the limits.

ERC-7984 has exactly one delegation tool, `setOperator`, and it's all-or-nothing: an operator can move **any** amount of your balance while approved. There is no `approve(spender, 100)` in confidential-token land — a cleartext allowance sitting next to an encrypted balance would leak the very numbers the balance math hides. `RecurringAllowance` fills that gap: you make the contract your operator once, then grant per-spender budgets here — "100 USDC per day", with the 100 encrypted. A spender can only move your funds through `transferFrom`, which enforces every budget homomorphically. Think Permit2's allowance module or a card's spending limit, for confidential tokens.

- **`setPermission`** grants a spender an encrypted per-period limit on a token, with an optional start time and expiry — or **`permitSetPermission`** does the same from an off-chain signature, so granting costs the user zero gas (see [Signature permits](#signature-permits-gasless-grants-and-confidential-cheques)).
- **`transferFrom`** (called by the spender) checks all of the user's active permissions under encryption and transfers either the requested amount or an encrypted zero — a denied spend is indistinguishable on-chain from a permitted one. **`tryTransferFrom`** is the payment-processor variant: items that fail a *cleartext* precondition (revoked grant, expired operator) are skipped with a `TransferSkipped` event instead of reverting the batch.
- **`updatePermission`**, **`invalidatePermission`** and **`lockdown`** manage the lifecycle: change a budget, revoke a single grant, or wipe every grant for a set of (token, spender) pairs in one call. **`getGrantedPairs`** enumerates every (token, spender) a user has granted, on-chain — a wallet can render (and revoke) the "who can spend my money" screen without an indexer.

### How it works

1. The user calls `setOperator(recurringAllowance, until)` on the ERC-7984 token (once; keep `until` beyond your permission windows).
2. The user calls `setPermission(token, spender, encryptedLimit, proof, duration, startTime, endTime)`.
3. The spender calls `transferFrom(from, to, encryptedAmount, proof, token)` — or the batch overload for many pulls in one transaction.
4. The contract checks every active permission homomorphically, moves the encrypted amount (or zero) via `confidentialTransferFrom`, and credits `spent` with what the token reports actually moved.

### Semantics that matter

- **Budgets stack conjunctively.** Every active permission for a (user, token, spender) key must pass (AND logic), so "100/day AND 500/week" is just two `setPermission` calls. The corollary: adding a permission only ever *tightens* the allowance — to raise a limit, update the existing permission instead of adding one.
- **Periods are fixed windows**, anchored at `startTime` (period `n` is `[startTime + n*duration, startTime + (n+1)*duration)`), not a sliding window. `spent` resets lazily at the first spend attempt in a new period. A spender straddling a boundary can move up to 2x the limit inside one `duration`-long span — inherent to fixed windows; size limits with that in mind.
- **Allowance tracks value moved, not attempts.** `spent` is credited with the amount the token reports as actually transferred, so a pull against an insufficient balance consumes nothing and can be retried after a top-up.
- **Denied spends don't revert.** They transfer an encrypted zero with storage writes and events identical to a permitted spend. The only cleartext reverts are structural: no active permission window (`NoPermissions`) — which is public information anyway.
- **The limits bind only this contract.** Any *other* operator the user approves on the token bypasses them entirely. `RecurringAllowance` is scoped delegation, not a token-level firewall — and `lockdown` cannot revoke the operator status itself (do that on the token for belt and braces).

### Signature permits (gasless grants and confidential cheques)

Permit2 taught EVM users to authorize token movements with signatures instead of transactions. The confidential version has one twist: the amount is a ciphertext, so **the permit signs the ciphertext handle**. The owner encrypts the amount off-chain with the input proof bound to `(this contract, spender)` — meaning only that spender can ever submit it — and signs EIP-712 over the struct including the handle. Substituting any other ciphertext breaks the signature; submitting as anyone else breaks the proof.

Two flows:

- **`permitSetPermission`** — gasless grants. The owner signs a `PermitGrant`; the spender submits it and pays the gas; the result is a completely normal permission. Granting a subscription budget costs the user zero transactions.
- **`permitTransferFrom`** — one-shot transfers up to a signed encrypted cap, optionally bound to a recipient: a *confidential cheque*. The spender chooses the actual amount at execution; over-cap requests move an encrypted zero, obliviously.

Nonces are Permit2-style unordered bitmaps: any number of permits can be outstanding, and `invalidateUnorderedNonces` cancels signed-but-unsubmitted ones in bulk. Signatures verify via ECDSA or ERC-1271 (smart accounts).

Two caveats to design around:

- **A submitted cheque burns its nonce regardless of the encrypted outcome.** The outcome cannot be read in cleartext, so a cheque drawn against an insufficient balance is consumed unspent — like a bounced paper cheque, the owner re-issues. (Gasless *grants* don't have this problem: a grant against an empty wallet just sits there until funded.)
- **How long an input proof stays submittable after signing is an operational property of the FHEVM gateway**, not of this contract. Size `sigDeadline` accordingly; for grants the natural pattern (spender submits immediately on receiving the signature) makes the window a non-issue.

The user who signs sees only a `bytes32` handle — **only the client that encrypted the amount can show them the number they're committing to**, so the signing UI and the encryption client must be the same trusted surface.

### Cost

Every active permission on a key adds a fixed amount of encrypted work to each `transferFrom` (two `le`, one `sub`, one `and`, one `add`), which is why permissions are capped at `MAX_PERMISSIONS = 8` per (user, token, spender) — comfortably inside the FHEVM HCU budget with room to spare, and far above the realistic 2–4 tiers. Measured with `pnpm test:bench` on `fhevm-tevm-mocks` (`N` is the number of active permissions; ±1% run-to-run mock variance):

| Active permissions `N` | `transferFrom` gas |
| ---: | ---: |
| 1 | 581,489 |
| 2 | 682,246 |
| 4 | 878,159 |
| 8 | 1,269,988 |

A denied spend costs exactly the same as a permitted one — same op sequence, so gas is not a side channel on the outcome. The benchmark asserts this.

### Privacy model

| Signal | Visibility |
| --- | --- |
| That a permission exists (user, token, spender) | Public |
| Period shape (duration, start, expiry) | Public |
| Limit and spent amounts | Encrypted; decryptable by the user **and the spender** — the spender needs to see its own budget, and an active spender could infer it by probing anyway |
| Spend attempts (spender, from, to, when) | Public (the transaction, plus the token's own `ConfidentialTransfer` event) |
| Spend amounts | Encrypted `euint64` |
| Whether a spend was permitted or denied | Hidden on-chain: identical writes and events either way; the recipient learns the outcome from their balance |

## Install

```bash
pnpm add @raycashxyz/confidential-primitives
```

Solidity consumers import the sources directly:

```solidity
import {ContinuousStealthWrapAdapter} from "@raycashxyz/confidential-primitives/contracts/adapters/ContinuousStealthWrapAdapter.sol";
import {BatchedStealthWrapAdapter} from "@raycashxyz/confidential-primitives/contracts/adapters/BatchedStealthWrapAdapter.sol";
import {IStealthWrapAdapter} from "@raycashxyz/confidential-primitives/contracts/interfaces/IStealthWrapAdapter.sol";
import {RecurringAllowance} from "@raycashxyz/confidential-primitives/contracts/allowances/RecurringAllowance.sol";
import {IRecurringAllowance} from "@raycashxyz/confidential-primitives/contracts/interfaces/IRecurringAllowance.sol";
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
