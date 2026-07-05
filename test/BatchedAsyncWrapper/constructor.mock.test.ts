/**
 * BatchedAsyncWrapper — constructor + initWrap.
 * (finalizeWrapBatched lives in the sibling *.finalize file so vitest runs it on its own
 * worker; both share the harness in setup/suite.)
 */
import {
  describe, it, expect
} from "vitest";

import { useBatchedSuite, AMOUNT } from "./setup/suite";
import { assertRevertsWith } from "../setup/asserts";

const boot = useBatchedSuite();

describe("BatchedAsyncWrapper", () => {

  describe("constructor", () => {
    it("reverts on zero batch size", async () => {
      const { deployWrapper } = await boot();
      await assertRevertsWith(deployWrapper(0n), "InvalidBatchSize");
    });

    it("reverts on batch size above the 64-bit bitmap limit", async () => {
      const { deployWrapper } = await boot();
      await assertRevertsWith(deployWrapper(65n), "InvalidBatchSize");
    });

    it("accepts batch size at the limit (64)", async () => {
      const { deployWrapper } = await boot();
      const { contract: wrapper } = await deployWrapper(64n);
      expect(await wrapper.read.maxBatchDeposits()).toBe(64n);
    });
  });

  describe("initWrap", () => {
    it("pulls underlying and records the deposit", async () => {
      const {
        wallets, underlying, deployWrapper, fundAndApprove, initWrap
      } = await boot();
      const { contract: wrapper } = await deployWrapper(4n);

      await fundAndApprove(wrapper, wallets.alice, 1n);
      await initWrap(wrapper, wallets.alice, wallets.alice.account.address);

      expect(await underlying.read.balanceOf([wrapper.address])).toBe(AMOUNT);
      expect(await wrapper.read.totalDeposits()).toBe(1n);
      const deposit = await wrapper.read.deposits([0n]);
      expect(deposit[0]).toBe(wallets.alice.account.address); // depositor
      expect(deposit[1]).toBe(AMOUNT); // cleartext amount
    });
  });

});
