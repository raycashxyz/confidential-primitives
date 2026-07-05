/**
 * 4-way finalize comparison, plus an analytic HCU tally for the two FHEVM budgets that
 * bound batch size on-chain (the mock meters them via the HCULimit host contract too):
 *   - TOTAL HCU per tx (cap 20M)
 *   - HCU DEPTH per tx (cap 5M — the serial critical path of the FHE dependency graph)
 *
 * Variants (each fills N deposits for one recipient on a fresh chain, finalizes the whole set):
 *   - rewrite        : SimpleAsyncWrapper.finalizeWrap          — zero each matched amount (N SSTORE)
 *   - bitmap/per-slot: BatchedAsyncWrapper.finalizeWrapPerSlot  — per-slot bitmap ops, 1 SSTORE
 *   - bitmap/batched : BatchedAsyncWrapper.finalizeWrap         — bitwise nullifier hoisted to bulk
 *   - v2             : BatchedAsyncWrapperV2.finalizeWrap       — cleartext nullifier + TREE-reduced sum
 *
 * DEPTH is why the serial designs top out near ~28 deposits: their `sum = add(sum, ...)`
 * chain is N adds deep (~162k HCU each), crossing the 5M cap right past 28. The bulk bitmap
 * path crosses FIRST — its outer per-batch add plus the mint's balance update ride on top of
 * the scan chain, so it already REVERTs at 28 while rewrite/per-slot squeeze under. v2's
 * pairwise tree cuts the critical path to ceil(log2 N) adds, moving its binding limit to the
 * 20M TOTAL budget (~60 analytic; its cap is 48 with headroom).
 *
 * NOTE: FHE calls carry an explicit gas limit (fheTxOpts), so viem skips simulation and a
 * REVERTED finalize still yields a receipt — its gasUsed is gas-to-revert-point, not a
 * measurement. Rows are recorded only from receipts with status "success".
 */
import {
  describe, it, expect
} from "vitest";
import type { Address, Hex } from "viem";

import { createTestEnvironment } from "./setup/environment";
import { encryptRecipient } from "./setup/fhe";
import { txOpts, fheTxOpts } from "./setup/tx";
import { getOrDeployMockUSDC } from "../src/deployers/MockUSDC";
import { getOrDeploySimpleAsyncWrapper } from "../src/deployers/SimpleAsyncWrapper";
import { getOrDeployBatchedAsyncWrapper } from "../src/deployers/BatchedAsyncWrapper";
import { getOrDeployBatchedAsyncWrapperV2 } from "../src/deployers/BatchedAsyncWrapperV2";

// The apples-to-apples race. All four variants fit under the 5M HCU depth cap up to 16;
// at 28 the bulk bitmap already reverts (its outer add + mint update tip it over the cap).
const SHARED_SIZES = [
  4,
  8,
  16,
  28
];
// Past the depth cliff (~29): the serial-sum variants revert on HCU depth; only v2's
// tree-reduced finalize survives. 48 is v2's contract cap.
const EXTENDED_SIZES = [
  32,
  48
];
const AMOUNT = 100n;

// ---------------------------------------------------------------------------
// Analytic HCU model — op costs from the HCULimit host contract (Uint64/Uint160
// branches; fhevm-tevm-mocks ships @fhevm/host-contracts with the same table).
// ---------------------------------------------------------------------------
const OP = {
  EQ_ADDR_SCALAR: 117_000, // eq(eaddress, address)
  EQ_ADDR_CIPHER: 137_000, // eq(eaddress, eaddress)
  SELECT_U64: 55_000, // FHE.select on euint64
  ADD_U64: 162_000, // add(euint64, euint64)
  NE_U64: 84_000, // ne(euint64, scalar)
  AND_U64: 34_000, // and(euint64, _)
  OR_U64: 34_000, // or(euint64, _)
  NOT_U64: 63,
  TRIVIAL: 32 // asEuint64/asEaddress(constant)
};
const DEPTH_CAP = 5_000_000;
const TOTAL_CAP = 20_000_000;

const ceilLog2 = (n: number): number => {
  let depth = 0;
  let v = 1;
  while (v < n) {
    v *= 2;
    depth += 1;
  }
  return depth;
};

// Total HCU per finalize (sum over every op emitted).
const hcuTotal = {
  rewrite: (n: number) => OP.TRIVIAL + n * (OP.EQ_ADDR_CIPHER + 2 * OP.SELECT_U64 + OP.ADD_U64),
  bitmapPerSlot: (n: number) =>
    n * (OP.EQ_ADDR_SCALAR + OP.AND_U64 + OP.NE_U64 + 3 * OP.SELECT_U64 + OP.OR_U64 + OP.ADD_U64) + OP.OR_U64,
  bitmapBatched: (n: number) =>
    n * (OP.EQ_ADDR_SCALAR + OP.OR_U64 + 2 * OP.SELECT_U64 + OP.ADD_U64) +
    (OP.NOT_U64 + OP.AND_U64 + OP.NE_U64 + OP.SELECT_U64 + OP.OR_U64 + OP.ADD_U64),
  v2: (n: number) => n * (OP.EQ_ADDR_SCALAR + OP.SELECT_U64) + (n - 1) * OP.ADD_U64
};

// Critical-path HCU depth. The first three are dominated by the serial length-N add
// chain; v2's tree is ceil(log2 N) adds deep.
const hcuDepth = {
  rewrite: (n: number) => OP.EQ_ADDR_CIPHER + OP.SELECT_U64 + n * OP.ADD_U64,
  bitmapPerSlot: (n: number) => OP.EQ_ADDR_SCALAR + 2 * OP.SELECT_U64 + n * OP.ADD_U64,
  bitmapBatched: (n: number) => OP.EQ_ADDR_SCALAR + 2 * OP.SELECT_U64 + (n + 1) * OP.ADD_U64,
  v2: (n: number) => OP.EQ_ADDR_SCALAR + OP.SELECT_U64 + ceilLog2(n) * OP.ADD_U64
};

interface Row {
  n: number;
  rewrite: bigint | null;
  bitmapPerSlot: bigint | null;
  bitmapBatched: bigint | null;
  v2: bigint | null;
}

describe("Gas Estimation (rewrite vs bitmap per-slot vs bitmap batched vs v2)", () => {

  it("measures finalize gas + reports analytic HCU across batch sizes", async () => {
    const results: Row[] = [];

    // Boot a fresh env (chain + store) and return bound helpers for one measurement row.
    const bootRow = async () => {
      const {
        publicClient, wallets, store, fhevm
      } = await createTestEnvironment();
      const { deployer, alice } = wallets;

      const send = async (p: Promise<Hex>) => publicClient.waitForTransactionReceipt({ hash: await p });
      const finalizeGas = async (p: Promise<Hex>): Promise<bigint | null> => {
        try {
          const receipt = await send(p);
          // FHE calls carry an explicit gas limit, so viem skips simulation and a reverted
          // finalize (the FHEVM HCU caps at high N) still lands with a receipt — its gasUsed
          // is gas-to-revert-point, NOT a valid measurement. Only status "success" counts.
          return receipt.status === "success" ? receipt.gasUsed : null;
        } catch (err) {
          // Simulated calls (no explicit gas) surface reverts as throws instead.
          const msg = err instanceof Error ? err.message : String(err);
          if (/revert|HCU|depth|out of gas|gas required|exceeds/i.test(msg)) return null;
          throw err;
        }
      };
      const encR = (wrapperAddr: Address) =>
        encryptRecipient(fhevm.instance, wrapperAddr, alice.account.address, alice.account.address);

      const { contract: underlying } = await getOrDeployMockUSDC({
        walletClient: deployer,
        publicClient,
        store,
        args: [6]
      });

      const fund = async (times: bigint) =>
        send(underlying.write.transfer([alice.account.address, AMOUNT * times], txOpts(deployer.account)));

      // Fills use explicit gas too, so assert every deposit landed (a silently reverted
      // deposit would corrupt the row's measurement).
      const sendOk = async (p: Promise<Hex>, what: string) => {
        const receipt = await send(p);
        if (receipt.status !== "success") throw new Error(`${what} reverted`);
        return receipt;
      };

      // Approve then run n deposits; the caller supplies the wrapper-specific initWrap
      // call so the generated viem tuple types stay intact (no structural erasure).
      const approveAndFill = async (
        address: Address,
        n: number,
        depositOne: (handle: Hex, inputProof: Hex, i: number) => Promise<unknown>,
      ) => {
        await send(underlying.write.approve([address, AMOUNT * BigInt(n)], txOpts(alice.account)));
        for (let i = 0; i < n; i++) {
          const { handle, inputProof } = await encR(address);
          await depositOne(handle, inputProof, i);
        }
      };

      const fillSimple = async (n: number) => {
        const { contract } = await getOrDeploySimpleAsyncWrapper({
          walletClient: deployer,
          publicClient,
          store,
          args: [underlying.address, 1n],
        });
        await send(underlying.write.approve([contract.address, AMOUNT * BigInt(n)], txOpts(alice.account)));
        for (let i = 0; i < n; i++) {
          const { handle, inputProof } = await encR(contract.address);
          // SimpleAsyncWrapper.initWrap arg order: (from, eRecipient, proof, amount).
          await sendOk(contract.write.initWrap([
            alice.account.address,
            handle,
            inputProof,
            AMOUNT
          ], fheTxOpts(alice.account)), `simple initWrap #${i}`);
        }
        return contract;
      };

      const fillBatched = async (n: number, name: string, symbol: string) => {
        const { contract } = await getOrDeployBatchedAsyncWrapper({
          walletClient: deployer,
          publicClient,
          store,
          args: [
            BigInt(n),
            underlying.address,
            name,
            symbol
          ],
          force: true, // deployoor dedups by contract name — force distinct instances
        });
        await approveAndFill(contract.address, n, (handle, inputProof, i) =>
          sendOk(contract.write.initWrap([
            alice.account.address,
            AMOUNT,
            handle,
            inputProof
          ], fheTxOpts(alice.account)), `initWrap #${i}`));
        return contract;
      };

      const fillV2 = async (n: number) => {
        const { contract } = await getOrDeployBatchedAsyncWrapperV2({
          walletClient: deployer,
          publicClient,
          store,
          args: [
            BigInt(n),
            1n, // minimal sealDelay — the bench fills every batch to the brim anyway
            underlying.address,
            "BatchedV2",
            "bwV2"
          ],
          force: true,
        });
        await approveAndFill(contract.address, n, (handle, inputProof, i) =>
          sendOk(contract.write.initWrap([
            alice.account.address,
            AMOUNT,
            handle,
            inputProof
          ], fheTxOpts(alice.account)), `v2 initWrap #${i}`));
        return contract;
      };

      return {
        alice, send, finalizeGas, fund, fillSimple, fillBatched, fillV2
      };
    };

    // --- shared sizes: all four variants ---
    for (const n of SHARED_SIZES) {
      const {
        alice, finalizeGas, fund, fillSimple, fillBatched, fillV2
      } = await bootRow();
      await fund(BigInt(n) * 4n);

      const simple = await fillSimple(n);
      const indices = Array.from({ length: n }, (_, i) => BigInt(i));
      const rewrite = await finalizeGas(simple.write.finalizeWrap([indices, alice.account.address], fheTxOpts(alice.account)));

      const perSlot = await fillBatched(n, "BatchedPerSlot", "bwPS");
      const bitmapPerSlot = await finalizeGas(perSlot.write.finalizeWrapPerSlot([0n, alice.account.address], fheTxOpts(alice.account)));

      const bulk = await fillBatched(n, "BatchedBulk", "bwBK");
      const bitmapBatched = await finalizeGas(bulk.write.finalizeWrap([[0n], alice.account.address], fheTxOpts(alice.account)));

      const v2Wrapper = await fillV2(n);
      const v2 = await finalizeGas(v2Wrapper.write.finalizeWrap([[0n], alice.account.address], fheTxOpts(alice.account)));

      results.push({
        n,
        rewrite,
        bitmapPerSlot,
        bitmapBatched,
        v2
      });
    }

    // --- extended sizes: past the depth cliff the bitmap variants REVERT on the HCU
    //     depth cap mid-scan; v2's tree keeps going up to its 48 cap ---
    const extended: Row[] = [];
    for (const n of EXTENDED_SIZES) {
      const {
        alice, finalizeGas, fund, fillBatched, fillV2
      } = await bootRow();
      await fund(BigInt(n) * 2n);

      const bulk = await fillBatched(n, "BatchedBulk", "bwBK");
      const bitmapBatched = await finalizeGas(bulk.write.finalizeWrap([[0n], alice.account.address], fheTxOpts(alice.account)));

      const v2Wrapper = await fillV2(n);
      const v2 = await finalizeGas(v2Wrapper.write.finalizeWrap([[0n], alice.account.address], fheTxOpts(alice.account)));

      extended.push({
        n,
        rewrite: null,
        bitmapPerSlot: null,
        bitmapBatched,
        v2
      });
    }

    // --- print ---
    const g = (v: bigint | null) => (v === null ? "REVERT" : v.toLocaleString()).padStart(13);
    const h = (v: number) => v.toLocaleString().padStart(13);
    const capped = (v: number, cap: number) => (v >= cap ? `${v.toLocaleString()} X` : v.toLocaleString()).padStart(15);
    const na = "—".padStart(13);

    console.log("\n  MEASURED EVM gas — finalize, all N deposits to one recipient");
    console.log("  ┌────────┬───────────────┬───────────────┬───────────────┬───────────────┐");
    console.log("  │ N      │ rewrite       │ bmap per-slot │ bmap batched  │ v2            │");
    console.log("  ├────────┼───────────────┼───────────────┼───────────────┼───────────────┤");
    for (const r of results) {
      console.log(`  │ ${String(r.n).padEnd(6)} │ ${g(r.rewrite)} │ ${g(r.bitmapPerSlot)} │ ${g(r.bitmapBatched)} │ ${g(r.v2)} │`);
    }
    console.log("  ├────────┼───────────────┼───────────────┼───────────────┼───────────────┤");
    for (const r of extended) {
      console.log(`  │ ${String(r.n).padEnd(6)} │ ${na} │ ${na} │ ${g(r.bitmapBatched)} │ ${g(r.v2)} │  <- past the HCU depth cliff`);
    }
    console.log("  └────────┴───────────────┴───────────────┴───────────────┴───────────────┘");

    const analyticSizes = [
      4,
      8,
      16,
      28,
      32,
      48,
      56,
      64
    ];
    console.log("\n  ANALYTIC total HCU (cap 20,000,000/tx) — HCULimit op costs, finalize only");
    console.log("  ┌────────┬───────────────┬───────────────┬───────────────┬───────────────┐");
    console.log("  │ N      │ rewrite       │ bmap per-slot │ bmap batched  │ v2            │");
    console.log("  ├────────┼───────────────┼───────────────┼───────────────┼───────────────┤");
    for (const n of analyticSizes) {
      console.log(`  │ ${String(n).padEnd(6)} │ ${h(hcuTotal.rewrite(n))} │ ${h(hcuTotal.bitmapPerSlot(n))} │ ${h(hcuTotal.bitmapBatched(n))} │ ${h(hcuTotal.v2(n))} │`);
    }
    console.log("  └────────┴───────────────┴───────────────┴───────────────┴───────────────┘");

    console.log("\n  ANALYTIC HCU DEPTH (cap 5,000,000/tx; X = over cap) — critical path");
    console.log("  ┌────────┬─────────────────┬─────────────────┬─────────────────┬─────────────────┐");
    console.log("  │ N      │ rewrite         │ bmap per-slot   │ bmap batched    │ v2              │");
    console.log("  ├────────┼─────────────────┼─────────────────┼─────────────────┼─────────────────┤");
    for (const n of analyticSizes) {
      console.log(`  │ ${String(n).padEnd(6)} │ ${capped(hcuDepth.rewrite(n), DEPTH_CAP)} │ ${capped(hcuDepth.bitmapPerSlot(n), DEPTH_CAP)} │ ${capped(hcuDepth.bitmapBatched(n), DEPTH_CAP)} │ ${capped(hcuDepth.v2(n), DEPTH_CAP)} │`);
    }
    console.log("  └────────┴─────────────────┴─────────────────┴─────────────────┴─────────────────┘");
    console.log("  Depth = the serial `sum = add(sum, ...)` chain (~162k HCU/add): the serial variants");
    console.log("  cross the 5M cap around 28-30 (bulk first — its outer add + the mint's balance");
    console.log("  update ride the same chain, hence its measured REVERT at 28). v2's tree keeps depth");
    console.log("  ~1.1M even at 64; its binding limit is TOTAL HCU instead, crossing 20M at ~60 —");
    console.log("  which is why its maxBatch caps at 48.\n");

    // v2 finalizes everywhere it is allowed to exist, and is the cheapest wherever a
    // competitor also fits.
    for (const r of results) {
      expect(r.v2, `v2 gas @${r.n}`).not.toBeNull();
      expect(r.rewrite, `rewrite gas @${r.n}`).not.toBeNull();
      if (r.v2 !== null) {
        if (r.rewrite !== null) expect(r.v2, `v2 < rewrite @${r.n}`).toBeLessThan(r.rewrite);
        if (r.bitmapPerSlot !== null) expect(r.v2, `v2 < per-slot @${r.n}`).toBeLessThan(r.bitmapPerSlot);
        if (r.bitmapBatched !== null) expect(r.v2, `v2 < bulk @${r.n}`).toBeLessThan(r.bitmapBatched);
      }
    }
    // The bulk bitmap's real ceiling is ~27: at 28 its outer add + the mint's balance
    // update tip the serial chain over the 5M depth cap.
    const row28 = results.find((r) => r.n === 28);
    expect(row28?.bitmapBatched, "bulk bitmap reverts @28 (depth cap incl. mint)").toBeNull();
    // Past the depth cliff the bitmap variant REVERTs on the HCU depth cap; v2 keeps
    // finalizing all the way to its 48 contract cap.
    for (const r of extended) {
      expect(r.bitmapBatched, `bitmap/batched reverts @${r.n} (HCU depth)`).toBeNull();
      expect(r.v2, `v2 finalizes @${r.n}`).not.toBeNull();
    }
    // The analytic model agrees with the measured cliff: serial designs cross the 5M
    // DEPTH cap right past 28; v2's depth stays ~1.1M even at 64, and its binding limit
    // is TOTAL HCU (crosses 20M by ~60 — hence the 48 cap).
    expect(hcuDepth.bitmapPerSlot(28)).toBeLessThan(DEPTH_CAP);
    expect(hcuDepth.bitmapPerSlot(32)).toBeGreaterThan(DEPTH_CAP);
    expect(hcuDepth.rewrite(32)).toBeGreaterThan(DEPTH_CAP);
    expect(hcuDepth.v2(64)).toBeLessThan(DEPTH_CAP);
    expect(hcuTotal.v2(48)).toBeLessThan(TOTAL_CAP);
    expect(hcuTotal.v2(64)).toBeGreaterThan(TOTAL_CAP);
  }, 600_000); // 4 sizes x 4 strategies + cliff + cap rows, FHE mocks — slow on CI runners

});
