/**
 * 3-way finalize gas comparison (fhevm-tevm mock = pure EVM gas):
 *   - rewrite        : SimpleAsyncWrapper.finalizeWrap        — zero each matched amount (N SSTORE + N allowThis)
 *   - bitmap/per-slot: BatchedAsyncWrapper.finalizeWrap       — per-slot bitmap ops, 1 SSTORE
 *   - bitmap/batched : BatchedAsyncWrapper.finalizeWrapBatched — bitwise nullifier hoisted to ONE bulk op
 *
 * Each fills N deposits for one recipient (fresh chain per size) and finalizes the whole set.
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

const BATCH_SIZES = [
  4,
  8,
  16,
  28
];
const AMOUNT = 100n;

interface Row {
  n: number;
  rewrite: bigint | null;
  bitmapPerSlot: bigint | null;
  bitmapBatched: bigint | null;
}

describe("Gas Estimation (rewrite vs bitmap per-slot vs bitmap batched)", () => {

  it("measures finalize gas across batch sizes", async () => {
    const results: Row[] = [];

    for (const n of BATCH_SIZES) {
      const N = BigInt(n);
      // Fresh chain + store per size, so deployoor's name-keyed dedup never collides across sizes.
      const {
        publicClient, wallets, store, fhevm
      } = await createTestEnvironment();
      const { deployer, alice } = wallets;

      const send = async (p: Promise<Hex>) => publicClient.waitForTransactionReceipt({ hash: await p });
      const finalizeGas = async (p: Promise<Hex>): Promise<bigint | null> => {
        try {
          return (await send(p)).gasUsed;
        } catch (err) {
          // A benchmark row that reverts on-chain (e.g. the FHEVM HCU depth limit at high N) is an
          // expected "did not fit" outcome — record it as null. Anything else (network, ABI, setup)
          // is a real failure and must surface, not be silently swallowed.
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
      await send(underlying.write.transfer([alice.account.address, AMOUNT * N * 3n], txOpts(deployer.account)));

      // --- rewrite (Simple.finalizeWrap) ---
      const { contract: simple } = await getOrDeploySimpleAsyncWrapper({
        walletClient: deployer,
        publicClient,
        store,
        args: [underlying.address, 1n],
      });
      await send(underlying.write.approve([simple.address, AMOUNT * N], txOpts(alice.account)));
      for (let i = 0; i < n; i++) {
        const { handle, inputProof } = await encR(simple.address);
        await send(simple.write.initWrap([
          alice.account.address,
          handle,
          inputProof,
          AMOUNT
        ], fheTxOpts(alice.account)));
      }
      const indices = Array.from({ length: n }, (_, i) => BigInt(i));
      const rewrite = await finalizeGas(simple.write.finalizeWrap([indices, alice.account.address], fheTxOpts(alice.account)));

      // Deploy + fill a FRESH Batched wrapper per variant. deployoor dedups by contract name,
      // so `force: true` is required to get two independent BatchedAsyncWrapper instances.
      const fillBatched = async (name: string, symbol: string) => {
        const { contract } = await getOrDeployBatchedAsyncWrapper({
          walletClient: deployer,
          publicClient,
          store,
          args: [
            N,
            underlying.address,
            name,
            symbol
          ],
          force: true,
        });
        await send(underlying.write.approve([contract.address, AMOUNT * N], txOpts(alice.account)));
        for (let i = 0; i < n; i++) {
          const { handle, inputProof } = await encR(contract.address);
          await send(contract.write.initWrap([
            alice.account.address,
            AMOUNT,
            handle,
            inputProof
          ], fheTxOpts(alice.account)));
        }
        return contract;
      };

      const perSlot = await fillBatched("BatchedPerSlot", "bwPS");
      const bitmapPerSlot = await finalizeGas(perSlot.write.finalizeWrapPerSlot([0n, alice.account.address], fheTxOpts(alice.account)));

      const bulk = await fillBatched("BatchedBulk", "bwBK");
      const bitmapBatched = await finalizeGas(bulk.write.finalizeWrap([[0n], alice.account.address], fheTxOpts(alice.account)));

      results.push({
        n,
        rewrite,
        bitmapPerSlot,
        bitmapBatched
      });
    }

    const fmt = (g: bigint | null) => (g === null ? "REVERT" : g.toLocaleString()).padStart(13);
    const delta = (a: bigint | null, b: bigint | null) =>
      a !== null && b !== null ? fmt(a - b) : "—".padStart(13);

    console.log("\n  finalizeWrap gas — rewrite vs bitmap(per-slot) vs bitmap(batched-bitwise)");
    console.log("  ┌────────┬───────────────┬───────────────┬───────────────┬───────────────┐");
    console.log("  │ batch  │ rewrite       │ bmap per-slot │ bmap batched  │ Δ(batched-rew)│");
    console.log("  ├────────┼───────────────┼───────────────┼───────────────┼───────────────┤");
    for (const r of results) {
      console.log(
        `  │ ${String(r.n).padEnd(6)} │ ${fmt(r.rewrite)} │ ${fmt(r.bitmapPerSlot)} │ ${fmt(r.bitmapBatched)} │ ${delta(r.bitmapBatched, r.rewrite)} │`,
      );
    }
    console.log("  └────────┴───────────────┴───────────────┴───────────────┴───────────────┘");

    expect(results.length).toBe(BATCH_SIZES.length);
  });

});
