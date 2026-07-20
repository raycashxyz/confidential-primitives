import { configDefaults, defineConfig } from "vitest/config";

export default defineConfig({
  test: {
    // Every *.mock.test.ts runs on the tevm harness (test/setup/*).
    include: ["test/**/*.mock.test.ts"],
    // The gas benchmarks boot several environments and run hundreds of FHE txs (~minutes).
    // They're benchmarks, not correctness gates — keep them out of `pnpm test` and run
    // them on demand via `pnpm test:bench`. Extend (don't replace) vitest's default
    // excludes so node_modules/dist/cache globs stay ignored.
    exclude: [...configDefaults.exclude, "test/gas-estimate-*.mock.test.ts"],
    testTimeout: 120_000,
    hookTimeout: 120_000,
    // Run test files in parallel across worker processes (default pool: forks). Each file
    // installs its own FHEVM runtime once (see test/setup/harness.ts), so wall-clock is
    // bounded by the slowest file — keep files balanced in size for best core utilization.
    fileParallelism: true,
    // vitest defaults the worker count to (cores - 1), which throttles a 2-core CI runner to
    // a SINGLE worker — every file then runs serially and re-pays its FHEVM install. Our tests
    // are ~50% idle-wait (a tx spends most of its wall-time in tevm's async path, not on CPU),
    // so a 2-core box comfortably hosts several concurrent workers. Override the default on CI
    // to actually parallelize the files there; locally the (cores - 1) default is plenty.
    // Tune this to the CI runner's core count if you move to a larger runner.
    maxWorkers: process.env.CI ? 4 : undefined,
    minWorkers: process.env.CI ? 4 : undefined,
  },
});
