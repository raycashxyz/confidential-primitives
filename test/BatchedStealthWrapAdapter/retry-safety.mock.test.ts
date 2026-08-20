/**
 * BatchedStealthWrapAdapter — finalize is retry-safe against a soft-failing wrapper (issue #34).
 *
 * The batched adapter replaced its cleartext (batch, recipient) nullifier with an encrypted
 * `claimed` accumulator: finalize pays `matched - claimed` and credits back only what the wrapper
 * reports it actually moved. So a transfer that soft-fails to zero (freeze / pause / blacklist) or
 * moves only part leaves the remainder claimable, and no sequence can pay a recipient more than
 * their matched sum. These tests drive a wrapper that soft-fails on command and assert exactly that.
 */
import {
  beforeAll, beforeEach, describe, expect, it
} from "vitest";
import { zeroHash } from "viem";

import { createHarness } from "../setup/harness";
import type { Harness } from "../setup/harness";
import type { WalletWithAccount } from "../setup/environment";
import { decryptEuint, encryptRecipient } from "../setup/fhe";
import { txOpts, fheTxOpts } from "../setup/tx";

// finalize here runs against a wrapper that does EXTRA FHE work per transfer (the soft-fail
// reduction), and tevm under-estimates gas for FHE writes, so the suite's 15M `fheTxOpts` limit
// trips a spurious OOG. Give these mock-heavy finalizes headroom just under the 30M block limit.
const finalizeGas = 29_000_000n;
import { getOrDeployMockUSDC } from "../../src/deployers/MockUSDC";
import { getOrDeployMockSoftFailingWrapper } from "../../src/deployers/MockSoftFailingWrapper";
import { getOrDeployBatchedStealthWrapAdapter } from "../../src/deployers/BatchedStealthWrapAdapter";

const AMOUNT = 100n;
const SEAL_DELAY = 3600n;

type USDC = Awaited<ReturnType<typeof getOrDeployMockUSDC>>["contract"];
type Wrapper = Awaited<ReturnType<typeof getOrDeployMockSoftFailingWrapper>>["contract"];
type Adapter = Awaited<ReturnType<typeof getOrDeployBatchedStealthWrapAdapter>>["contract"];

// Soft-fail modes on MockSoftFailingWrapper.
const NORMAL = 0;
const BLOCK = 1;
const PARTIAL = 2;
const OVER_REPORT = 3;

describe("BatchedStealthWrapAdapter retry safety (#34)", () => {
  let H: Harness;
  let underlying: USDC;
  let wrapper: Wrapper;

  beforeAll(async () => {
    H = await createHarness(async (env) => {
      const { contract: token } = await getOrDeployMockUSDC({
        walletClient: env.wallets.deployer,
        publicClient: env.publicClient,
        store: env.store,
        args: [6]
      });
      underlying = token;

      const { contract: w } = await getOrDeployMockSoftFailingWrapper({
        walletClient: env.wallets.deployer,
        publicClient: env.publicClient,
        store: env.store,
        args: [
          underlying.address,
          "Confidential USDC",
          "cUSDC"
        ]
      });
      wrapper = w;
    });
  });

  beforeEach(() => H.reset());

  const send = async (p: Promise<`0x${string}`>) => {
    const receipt = await H.publicClient.waitForTransactionReceipt({ hash: await p });
    if (receipt.status !== "success") throw new Error(`tx reverted: ${receipt.transactionHash}`);
    return receipt;
  };

  const deployAdapter = async (maxBatch: bigint): Promise<Adapter> => {
    const { contract } = await getOrDeployBatchedStealthWrapAdapter({
      walletClient: H.wallets.deployer,
      publicClient: H.publicClient,
      store: H.store,
      args: [
        maxBatch,
        SEAL_DELAY,
        wrapper.address
      ],
      force: true,
    });
    return contract;
  };

  const fundAndApprove = async (adapter: Adapter, who: WalletWithAccount, count: bigint) => {
    await send(underlying.write.transfer([who.account.address, AMOUNT * count], txOpts(H.wallets.deployer.account)));
    await send(underlying.write.approve([adapter.address, AMOUNT * count], txOpts(who.account)));
  };

  const initWrap = async (adapter: Adapter, depositor: WalletWithAccount, recipient: `0x${string}`) => {
    const { handle, inputProof } = await encryptRecipient(
      H.fhevm.instance,
      adapter.address,
      depositor.account.address,
      recipient,
    );
    return send(adapter.write.initWrap([
      AMOUNT,
      handle,
      inputProof
    ], fheTxOpts(depositor.account)));
  };

  // Explicit gas: tevm under-estimates for a plain write issued right after an FHE-heavy tx, which
  // otherwise reverts this toggle and silently leaves the wrapper in its previous mode.
  const setMode = (mode: number, partial: bigint) =>
    send(wrapper.write.setFailMode([mode, partial], { ...txOpts(H.wallets.deployer.account), gas: 200_000n }));

  const balanceOf = async (owner: WalletWithAccount): Promise<bigint> => {
    const handle = await wrapper.read.confidentialBalanceOf([owner.account.address]);
    if (handle === zeroHash) return 0n;
    return decryptEuint(H.fhevm.instance, handle, wrapper.address, owner);
  };

  const finalize = (adapter: Adapter, ids: bigint[], recipient: `0x${string}`, caller: WalletWithAccount) =>
    send(adapter.write.finalizeWrap([ids, recipient], { ...txOpts(caller.account), gas: finalizeGas }));

  // A blocked transfer (freeze / pause / blacklist returns encrypted zero) must not consume the
  // claim: the recipient retries once the block lifts and is made whole.
  it("retries a finalize the wrapper blocked entirely", async () => {
    const { alice } = H.wallets;
    const adapter = await deployAdapter(2n);
    await fundAndApprove(adapter, alice, 2n);
    await initWrap(adapter, alice, alice.account.address);
    await initWrap(adapter, alice, alice.account.address); // batch 0 full -> closed

    await setMode(BLOCK, 0n);
    await finalize(adapter, [0n], alice.account.address, alice);
    expect(await balanceOf(alice)).toBe(0n); // nothing delivered, claim survives

    await setMode(NORMAL, 0n);
    await finalize(adapter, [0n], alice.account.address, alice);
    expect(await balanceOf(alice)).toBe(AMOUNT * 2n); // made whole on retry
  });

  // A partial transfer credits exactly what moved and leaves the exact remainder claimable.
  it("credits a partial transfer and delivers the remainder on retry", async () => {
    const { alice } = H.wallets;
    const adapter = await deployAdapter(2n);
    await fundAndApprove(adapter, alice, 2n);
    await initWrap(adapter, alice, alice.account.address);
    await initWrap(adapter, alice, alice.account.address); // matched = 200

    await setMode(PARTIAL, 50n);
    await finalize(adapter, [0n], alice.account.address, alice);
    expect(await balanceOf(alice)).toBe(50n); // only the partial landed

    await setMode(NORMAL, 0n);
    await finalize(adapter, [0n], alice.account.address, alice);
    expect(await balanceOf(alice)).toBe(AMOUNT * 2n); // remainder delivered, total = matched
  });

  // The invariant that matters: no sequence of soft-fails can pay a recipient more than their
  // matched sum. Hammer partial finalizes and confirm it converges to matched, never past it.
  it("never pays more than the matched sum under repeated partials", async () => {
    const { alice } = H.wallets;
    const adapter = await deployAdapter(2n);
    await fundAndApprove(adapter, alice, 2n);
    await initWrap(adapter, alice, alice.account.address);
    await initWrap(adapter, alice, alice.account.address); // matched = 200

    await setMode(PARTIAL, 70n);
    for (let i = 0; i < 5; i++) {
      await finalize(adapter, [0n], alice.account.address, alice);
      expect(await balanceOf(alice)).toBeLessThanOrEqual(AMOUNT * 2n); // never overpays
    }
    expect(await balanceOf(alice)).toBe(AMOUNT * 2n); // converged to exactly matched
  });

  // A wrapper that lies UPWARD about how much it moved must not overpay or brick the batch.
  //
  // NOTE this does not isolate the `FHE.min` clamp in `_creditedAmount`: without it `claimed` would
  // exceed `matched` and the next `matched - claimed` would wrap near 2^64, but OZ soft-fails that
  // oversized transfer to zero (escrow is nowhere near 2^64), so the balances below look the same
  // either way. The clamp is there to keep `claimed <= matched` structurally true — which is what
  // `claimedAmount` reports and what an exact-or-revert wrapper would otherwise revert on forever.
  // What this test does pin is the user-visible guarantee: a lying wrapper cannot extract more than
  // the matched sum, and the batch stays usable afterwards.
  it("does not overpay or brick the batch when the wrapper over-reports", async () => {
    const { alice } = H.wallets;
    const adapter = await deployAdapter(2n);
    await fundAndApprove(adapter, alice, 2n);
    await initWrap(adapter, alice, alice.account.address);
    await initWrap(adapter, alice, alice.account.address); // matched = 200

    // Moves the honest 200 but claims it moved 250.
    await setMode(OVER_REPORT, 50n);
    await finalize(adapter, [0n], alice.account.address, alice);
    expect(await balanceOf(alice)).toBe(AMOUNT * 2n); // paid exactly matched, not the inflated figure

    // The batch is still usable and pays nothing further: the lie bought the wrapper no extra escrow.
    await setMode(NORMAL, 0n);
    await finalize(adapter, [0n], alice.account.address, alice);
    expect(await balanceOf(alice)).toBe(AMOUNT * 2n);
  });

  // A replay of a fully-claimed batch is a no-op: it pays an encrypted zero, does not revert, and
  // does not double-pay.
  it("does not double-pay a fully claimed batch on replay", async () => {
    const { alice, bob } = H.wallets;
    const adapter = await deployAdapter(2n);
    await fundAndApprove(adapter, alice, 2n);
    await initWrap(adapter, alice, alice.account.address);
    await initWrap(adapter, alice, alice.account.address);

    await finalize(adapter, [0n], alice.account.address, alice);
    expect(await balanceOf(alice)).toBe(AMOUNT * 2n);

    // A permissionless replay (even by a stranger) delivers nothing more.
    await finalize(adapter, [0n], alice.account.address, bob);
    expect(await balanceOf(alice)).toBe(AMOUNT * 2n);
  });
});
