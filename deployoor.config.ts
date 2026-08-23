import { defineConfig } from "deployoor";

export default defineConfig({
  // Typed deployers are generated here (gitignored; consumed by tests).
  out: "./src/deployers",
  deploymentsPath: "./deployments",
  // Only the deployable, non-abstract contracts (the base + interface can't be deployed).
  include: /^(MockUSDC|MockERC7984ERC20Wrapper|MockConfidentialToken|MockHandleStealingToken|Mock1271Wallet|MockBatchedStealthWrapAdapterExtension|MockTransientAmountAdapter|MockCapStealingSpender|MockFHEUtilsHarness|MockReusableHandleAdapter|MockRecipientStealingDepositor|MockSoftFailingWrapper|MockWrapperShape|ContinuousStealthWrapAdapter|BatchedStealthWrapAdapter|RecurringAllowance)$/,
  plugins: [],
});
