/**
 * Gas benchmark for RecurringAllowance.transferFrom as the number of active
 * permissions on the (user, token, spender) key grows.
 *
 * Also verifies the obliviousness claim in gas: a denied spend (over-limit) runs the
 * exact same FHE op sequence as a permitted one, so their gas is identical on a real
 * FHEVM (on-chain execution is symbolic; gas depends only on the derivation shape).
 * Each variant is measured in its own freshly booted environment at the same tx
 * position. NOTE the tevm mock adds run-to-run bookkeeping variance of up to
 * ~2.8k gas per permission (its content-addressed ciphertext DB warms/colds a few
 * ACL and depth-tracker writes depending on the random ciphertext values), so the
 * assertion uses a 2% tolerance; matched runs come out exactly equal (+-12 gas).
 *
 * Analytic HCU uses the per-op costs from @fhevm/host-contracts HCULimit.sol
 * (euint64, cipher-cipher): le 149k, sub/add 162k, and(ebool) 25k, select 55k.
 * The OZ token's confidentialTransferFrom adds its own roughly constant ~583k
 * (tryDecrease ge+sub+select, transferred select, recipient add).
 */
import {
  describe, expect, it
} from "vitest";
import type { Hex, TransactionReceipt } from "viem";

import { createTestEnvironment } from "./setup/environment";
import { encryptValues } from "./setup/fhe";
import { fheTxOpts } from "./setup/tx";
import { getOrDeployMockConfidentialToken } from "../src/deployers/MockConfidentialToken";
import { getOrDeployRecurringAllowance } from "../src/deployers/RecurringAllowance";

const SIZES = [
  1,
  2,
  4,
  8
];
const WEEK = 7n * 86_400n;
const LIMIT = 1000n;

const OP = {
  LE_U64: 149_000,
  SUB_U64: 162_000,
  ADD_U64: 162_000,
  AND_EBOOL: 25_000,
  SELECT_U64: 55_000,
  TOKEN_TRANSFER: 583_000 // OZ _update: ge + sub + 2x select + add
};
const DEPTH_CAP = 5_000_000;
const TOTAL_CAP = 20_000_000;

// Per permission: check (le + sub + le + and, plus a chain-and after the first) + record add.
const hcuTotal = (n: number) =>
  n * (2 * OP.LE_U64 + OP.SUB_U64 + OP.AND_EBOOL + OP.ADD_U64) +
  (n - 1) * OP.AND_EBOOL +
  OP.SELECT_U64 +
  OP.TOKEN_TRANSFER;

// Critical path: one fits computation, then the serial AND chain, select, token, record add.
const hcuDepth = (n: number) =>
  (OP.SUB_U64 + OP.LE_U64 + OP.AND_EBOOL) +
  (n - 1) * OP.AND_EBOOL +
  OP.SELECT_U64 +
  OP.TOKEN_TRANSFER +
  OP.ADD_U64;

interface Row {
  n: number;
  permitted: bigint | null;
  denied: bigint | null;
}

describe("Gas Estimation (RecurringAllowance.transferFrom vs active permission count)", () => {
  it("measures permitted and denied spends and reports analytic HCU", async () => {
    /**
     * Boot a fresh env, set up `n` permissions, run one permitted warm-up spend, then
     * measure the gas of a single spend of `amount` — always the second spend, so the
     * permitted and denied variants are position-identical.
     */
    const measureSpend = async (n: number, amount: bigint): Promise<bigint | null> => {
      const {
        publicClient, wallets, store, fhevm
      } = await createTestEnvironment();
      const {
        deployer, alice, bob, carol
      } = wallets;

      const send = async (p: Promise<Hex>): Promise<TransactionReceipt> =>
        publicClient.waitForTransactionReceipt({ hash: await p });
      const sendOk = async (p: Promise<Hex>, what: string): Promise<TransactionReceipt> => {
        const receipt = await send(p);
        if (receipt.status !== "success") throw new Error(`${what} reverted`);
        return receipt;
      };

      const { contract: token } = await getOrDeployMockConfidentialToken({
        walletClient: deployer,
        publicClient,
        store,
        args: []
      });
      const { contract: allowance } = await getOrDeployRecurringAllowance({
        walletClient: deployer,
        publicClient,
        store,
        args: []
      });

      const enc = async (user: Hex, target: Hex, value: bigint) => {
        const [handle, inputProof] = await encryptValues(
          fhevm.instance,
          [{
            type: "add64",
            value
          }],
          target,
          user,
        );
        return {
          handle,
          inputProof
        };
      };

      // Fund alice and make the allowance contract her operator.
      {
        const { handle, inputProof } = await enc(alice.account.address, token.address, 1_000_000n);
        await sendOk(token.write.mint([
          alice.account.address,
          handle,
          inputProof
        ], fheTxOpts(alice.account)), "mint");
        const { timestamp } = await publicClient.getBlock({ blockTag: "latest" });
        await sendOk(
          token.write.setOperator([allowance.address, timestamp + 3_153_600_000n], fheTxOpts(alice.account)),
          "setOperator",
        );
      }

      // n identical weekly permissions -> all active on every spend, no period resets.
      for (let i = 0; i < n; i++) {
        const { handle, inputProof } = await enc(alice.account.address, allowance.address, LIMIT);
        await sendOk(allowance.write.setPermission([
          token.address,
          bob.account.address,
          handle,
          inputProof,
          WEEK,
          0n,
          0n
        ], fheTxOpts(alice.account)), `setPermission #${i}`);
      }

      const spendGas = async (value: bigint): Promise<bigint | null> => {
        const { handle, inputProof } = await enc(bob.account.address, allowance.address, value);
        try {
          const receipt = await send(allowance.write.transferFrom([
            alice.account.address,
            carol.account.address,
            handle,
            inputProof,
            token.address
          ], fheTxOpts(bob.account)));
          return receipt.status === "success" ? receipt.gasUsed : null;
        } catch (err) {
          const msg = err instanceof Error ? err.message : String(err);
          if (/revert|HCU|depth|out of gas|gas required|exceeds/i.test(msg)) return null;
          throw err;
        }
      };

      await spendGas(10n); // warm-up: every spent slot now holds a computed (non-shared) handle
      return spendGas(amount);
    };

    const results: Row[] = [];
    for (const n of SIZES) {
      results.push({
        n,
        permitted: await measureSpend(n, 50n), // 60 total, within every limit
        denied: await measureSpend(n, 5000n) // over every limit -> oblivious zero-transfer
      });
    }

    const g = (v: bigint | null) => (v === null ? "REVERT" : v.toLocaleString()).padStart(13);
    const h = (v: number) => v.toLocaleString().padStart(13);

    console.log("\n  MEASURED EVM gas — transferFrom with N active permissions on the key");
    console.log("  ┌────────┬───────────────┬───────────────┐");
    console.log("  │ N      │ permitted     │ denied        │");
    console.log("  ├────────┼───────────────┼───────────────┤");
    for (const r of results) {
      console.log(`  │ ${String(r.n).padEnd(6)} │ ${g(r.permitted)} │ ${g(r.denied)} │`);
    }
    console.log("  └────────┴───────────────┴───────────────┘");

    console.log("\n  ANALYTIC HCU — total (cap 20,000,000/tx) and depth (cap 5,000,000/tx)");
    console.log("  ┌────────┬───────────────┬───────────────┐");
    console.log("  │ N      │ total         │ depth         │");
    console.log("  ├────────┼───────────────┼───────────────┤");
    for (const n of SIZES) {
      console.log(`  │ ${String(n).padEnd(6)} │ ${h(hcuTotal(n))} │ ${h(hcuDepth(n))} │`);
    }
    console.log("  └────────┴───────────────┴───────────────┘\n");

    for (const r of results) {
      expect(r.permitted, `permitted spend gas @${r.n}`).not.toBeNull();
      expect(r.denied, `denied spend gas @${r.n}`).not.toBeNull();
      // Obliviousness in gas: identical op sequence either way. The tolerance absorbs
      // the mock's run-to-run bookkeeping variance (see the header note) — matched
      // runs measure exactly equal.
      const drift = Number((r.permitted! > r.denied! ? r.permitted! - r.denied! : r.denied! - r.permitted!)) /
        Number(r.permitted!);
      expect(drift, `permitted/denied gas drift @${r.n}`).toBeLessThan(0.02);
    }
    // The MAX_PERMISSIONS = 8 cap must sit well inside both HCU budgets.
    expect(hcuTotal(8)).toBeLessThan(TOTAL_CAP);
    expect(hcuDepth(8)).toBeLessThan(DEPTH_CAP);
  }, 900_000);
});
