/**
 * Snapshot harness — the fast path for the tevm + FHEVM mock suite.
 *
 * Booting a fresh EVM and re-installing the whole FHEVM host-contract stack
 * (`createFhevmTevmRuntime`, ~0.9s) plus a MockUSDC deploy (~0.5s) costs ~1.4s. Paying that
 * per test (there are dozens) dominated the old runtime. Instead:
 *
 *   - `createHarness` boots the environment ONCE per test file (vitest's forks pool already
 *     runs each file in its own process, so this is naturally per-file isolated), lets the
 *     file deploy its shared baseline (e.g. MockUSDC), then snapshots EVM state.
 *   - `reset()` (call in `beforeEach`) restores that snapshot in ~a few ms instead of
 *     rebuilding — the coprocessor's ciphertext DB is content-addressed, so it needs no reset.
 *
 * Per-test contracts (wrappers, auctions) must still be deployed inside each test with
 * `force: true`: `loadState` rolls the chain back, but deployoor's in-memory store does not,
 * so a non-forced getOrDeploy would hand back a record pointing at a rolled-back address.
 */
import { createTestEnvironment } from "./environment";
import type { TestEnvironment } from "./environment";

export interface Harness extends TestEnvironment {
  /** Restore the post-baseline snapshot (call in `beforeEach`). Cheap (~ms). */
  reset: () => Promise<void>;
}

/**
 * Boot one environment, run `deployBaseline` against it (deploy anything every test in the
 * file shares — e.g. MockUSDC), then snapshot. The returned `reset()` restores that snapshot.
 */
export async function createHarness (
  deployBaseline?: (env: TestEnvironment) => Promise<void>,
): Promise<Harness> {
  const env = await createTestEnvironment();
  if (deployBaseline) await deployBaseline(env);

  const snapshot = await env.cheatcodes.dumpState();

  const reset = async (): Promise<void> => {
    await env.cheatcodes.loadState(snapshot);
    // tevm (1.0.0-next.149) quirk: loadState rolls back the *queryable* nonce
    // (eth_getTransactionCount) but not the tx-validator's, so the next tx would be rejected
    // NonceTooLow. Re-sync every prefunded account's nonce to the restored value; setAccount
    // writes through to the state manager the validator reads.
    for (const w of env.allWallets) {
      const nonce = await env.publicClient.getTransactionCount({ address: w.account.address });
      await env.cheatcodes.setAccount({ address: w.account.address, nonce: BigInt(nonce) });
    }
  };

  return {
    ...env,
    reset
  };
}
