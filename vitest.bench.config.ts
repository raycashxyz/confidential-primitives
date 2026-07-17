import { defineConfig } from "vitest/config";

// On-demand run for the gas benchmarks (excluded from the default `pnpm test`).
// They boot several environments and run hundreds of FHE txs, so they need a long timeout.
export default defineConfig({
  test: {
    include: ["test/gas-estimate-*.mock.test.ts"],
    testTimeout: 600_000,
    hookTimeout: 600_000,
  },
});
