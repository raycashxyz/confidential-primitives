import { defineConfig } from "vitest/config";

export default defineConfig({
  test: {
    // Every *.mock.test.ts runs on the tevm harness (test/setup/*).
    include: ["test/**/*.mock.test.ts"],
    testTimeout: 120_000,
    hookTimeout: 120_000,
  },
});
