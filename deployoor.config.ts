import { defineConfig } from "deployoor";

export default defineConfig({
  // Typed deployers are generated here (gitignored; consumed by tests).
  out: "./src/deployers",
  deploymentsPath: "./deployments",
  // Only the deployable, non-abstract contracts (the base + interface can't be deployed).
  include: /^(MockUSDC|SimpleAsyncWrapper|BatchedAsyncWrapper|BatchedAsyncWrapperV2)$/,
  plugins: [],
});
