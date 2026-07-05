import { defineConfig } from "vitest/config";

// On-demand run for the finalize gas benchmark (excluded from the default `pnpm test`).
// It boots several environments and runs hundreds of FHE txs, so it needs a long timeout.
export default defineConfig({
  test: {
    include: ["test/gas-estimate-batched.mock.test.ts"],
    testTimeout: 600_000,
    hookTimeout: 600_000,
  },
});
