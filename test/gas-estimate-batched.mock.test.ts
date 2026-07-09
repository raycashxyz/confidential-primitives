/**
 * Gas benchmark for the two async wrapper shapes:
 *   - simple  : arbitrary deposit ids, matched encrypted amounts rewritten to zero
 *   - batched : closed batches + cleartext (batch, recipient) nullifier
 *
 * finalizeWrap transfers confidential balance from async escrow to the recipient.
 */
import {
  describe, it, expect
} from "vitest";
import type { Address, Hex, TransactionReceipt } from "viem";

import { createTestEnvironment } from "./setup/environment";
import { encryptRecipient } from "./setup/fhe";
import { txOpts, fheTxOpts } from "./setup/tx";
import { getOrDeployMockUSDC } from "../src/deployers/MockUSDC";
import { getOrDeployMockERC7984ERC20Wrapper } from "../src/deployers/MockERC7984ERC20Wrapper";
import { getOrDeploySimpleAsyncWrapper } from "../src/deployers/SimpleAsyncWrapper";
import { getOrDeployBatchedAsyncWrapper } from "../src/deployers/BatchedAsyncWrapper";

const SIZES = [
  1,
  2,
  4,
  8,
  16,
  32,
  48
];
const AMOUNT = 100n;

const OP = {
  EQ_ADDR_SCALAR: 117_000,
  EQ_ADDR_CIPHER: 137_000,
  SELECT_U64: 55_000,
  ADD_U64: 162_000,
  TRIVIAL: 32
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

const treeAdds = (n: number) => Math.max(0, n - 1);

const hcuTotal = {
  simple: (n: number) => OP.TRIVIAL + n * (OP.EQ_ADDR_CIPHER + 2 * OP.SELECT_U64) + treeAdds(n) * OP.ADD_U64,
  batched: (n: number) => n * (OP.EQ_ADDR_SCALAR + OP.SELECT_U64) + treeAdds(n) * OP.ADD_U64
};

const hcuDepth = {
  simple: (n: number) => OP.EQ_ADDR_CIPHER + OP.SELECT_U64 + ceilLog2(n) * OP.ADD_U64,
  batched: (n: number) => OP.EQ_ADDR_SCALAR + OP.SELECT_U64 + ceilLog2(n) * OP.ADD_U64
};

interface Row {
  n: number;
  simpleFinalize: bigint | null;
  batchedFinalize: bigint | null;
}

describe("Gas Estimation (simple vs batched async wrappers)", () => {
  it("measures finalize gas and reports analytic finalize HCU", async () => {
    const results: Row[] = [];

    const bootRow = async () => {
      const {
        publicClient, wallets, store, fhevm
      } = await createTestEnvironment();
      const { deployer, alice } = wallets;

      const send = async (p: Promise<Hex>): Promise<TransactionReceipt> =>
        publicClient.waitForTransactionReceipt({ hash: await p });

      const sendOk = async (p: Promise<Hex>, what: string): Promise<TransactionReceipt> => {
        const receipt = await send(p);
        if (receipt.status !== "success") throw new Error(`${what} reverted`);
        return receipt;
      };

      const gasOrNull = async (p: Promise<Hex>): Promise<bigint | null> => {
        try {
          const receipt = await send(p);
          return receipt.status === "success" ? receipt.gasUsed : null;
        } catch (err) {
          const msg = err instanceof Error ? err.message : String(err);
          if (/revert|HCU|depth|out of gas|gas required|exceeds/i.test(msg)) return null;
          throw err;
        }
      };

      const encR = (asyncWrapper: Address) =>
        encryptRecipient(fhevm.instance, asyncWrapper, alice.account.address, alice.account.address);

      const { contract: underlying } = await getOrDeployMockUSDC({
        walletClient: deployer,
        publicClient,
        store,
        args: [6]
      });
      const { contract: confidentialWrapper } = await getOrDeployMockERC7984ERC20Wrapper({
        walletClient: deployer,
        publicClient,
        store,
        args: [
          underlying.address,
          "Confidential USDC",
          "cUSDC"
        ]
      });

      const fund = async (times: bigint) =>
        sendOk(underlying.write.transfer([alice.account.address, AMOUNT * times], txOpts(deployer.account)), "fund");

      const fillSimple = async (n: number) => {
        const { contract } = await getOrDeploySimpleAsyncWrapper({
          walletClient: deployer,
          publicClient,
          store,
          args: [
            confidentialWrapper.address,
            1n
          ],
          force: true,
        });
        await sendOk(underlying.write.approve([contract.address, AMOUNT * BigInt(n)], txOpts(alice.account)), "approve simple");

        for (let i = 0; i < n; i++) {
          const { handle, inputProof } = await encR(contract.address);
          await sendOk(contract.write.initWrap([
            AMOUNT,
            handle,
            inputProof
          ], fheTxOpts(alice.account)), `simple initWrap #${i}`);
        }

        return contract;
      };

      const fillBatched = async (n: number) => {
        const { contract } = await getOrDeployBatchedAsyncWrapper({
          walletClient: deployer,
          publicClient,
          store,
          args: [
            BigInt(n),
            1n,
            confidentialWrapper.address
          ],
          force: true,
        });
        await sendOk(underlying.write.approve([contract.address, AMOUNT * BigInt(n)], txOpts(alice.account)), "approve batched");

        for (let i = 0; i < n; i++) {
          const { handle, inputProof } = await encR(contract.address);
          await sendOk(contract.write.initWrap([
            AMOUNT,
            handle,
            inputProof
          ], fheTxOpts(alice.account)), `batched initWrap #${i}`);
        }

        return contract;
      };

      return {
        alice, gasOrNull, fund, fillSimple, fillBatched
      };
    };

    for (const n of SIZES) {
      const {
        alice, gasOrNull, fund, fillSimple, fillBatched
      } = await bootRow();
      await fund(BigInt(n) * 2n);

      const simple = await fillSimple(n);
      const indices = Array.from({ length: n }, (_, i) => BigInt(i));
      const simpleFinalize = await gasOrNull(
        simple.write.finalizeWrap([indices, alice.account.address], fheTxOpts(alice.account)),
      );

      const batched = await fillBatched(n);
      const batchedFinalize = await gasOrNull(
        batched.write.finalizeWrap([[0n], alice.account.address], fheTxOpts(alice.account)),
      );

      results.push({
        n,
        simpleFinalize,
        batchedFinalize,
      });
    }

    const g = (v: bigint | null) => (v === null ? "REVERT" : v.toLocaleString()).padStart(13);
    const h = (v: number) => v.toLocaleString().padStart(13);
    const capped = (v: number, cap: number) => (v >= cap ? `${v.toLocaleString()} X` : v.toLocaleString()).padStart(15);

    console.log("\n  MEASURED EVM gas — finalize all N deposits to one recipient");
    console.log("  ┌────────┬───────────────┬───────────────┐");
    console.log("  │ N      │ simple        │ batched       │");
    console.log("  ├────────┼───────────────┼───────────────┤");
    for (const r of results) {
      console.log(`  │ ${String(r.n).padEnd(6)} │ ${g(r.simpleFinalize)} │ ${g(r.batchedFinalize)} │`);
    }
    console.log("  └────────┴───────────────┴───────────────┘");

    console.log("\n  ANALYTIC total HCU (cap 20,000,000/tx) — finalize only, HCULimit op costs");
    console.log("  ┌────────┬───────────────┬───────────────┐");
    console.log("  │ N      │ simple        │ batched       │");
    console.log("  ├────────┼───────────────┼───────────────┤");
    for (const n of SIZES) {
      console.log(`  │ ${String(n).padEnd(6)} │ ${h(hcuTotal.simple(n))} │ ${h(hcuTotal.batched(n))} │`);
    }
    console.log("  └────────┴───────────────┴───────────────┘");

    console.log("\n  ANALYTIC HCU DEPTH (cap 5,000,000/tx; X = over cap) — finalize critical path");
    console.log("  ┌────────┬─────────────────┬─────────────────┐");
    console.log("  │ N      │ simple          │ batched         │");
    console.log("  ├────────┼─────────────────┼─────────────────┤");
    for (const n of SIZES) {
      console.log(`  │ ${String(n).padEnd(6)} │ ${capped(hcuDepth.simple(n), DEPTH_CAP)} │ ${capped(hcuDepth.batched(n), DEPTH_CAP)} │`);
    }
    console.log("  └────────┴─────────────────┴─────────────────┘\n");

    for (const r of results) {
      if (r.n <= 32) {
        expect(r.simpleFinalize, `simple finalize gas @${r.n}`).not.toBeNull();
      }
      expect(r.batchedFinalize, `batched finalize gas @${r.n}`).not.toBeNull();
    }
    expect(hcuDepth.simple(48)).toBeLessThan(DEPTH_CAP);
    expect(hcuDepth.batched(48)).toBeLessThan(DEPTH_CAP);
    expect(hcuTotal.simple(48)).toBeLessThan(TOTAL_CAP);
    expect(hcuTotal.batched(48)).toBeLessThan(TOTAL_CAP);
  }, 900_000);
});
