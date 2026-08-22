/**
 * FHEUtils, tested directly rather than through the contracts that use it.
 *
 * The ACL containment rests on the BEHAVIOUR of `FHEVMExecutor.verifyInput`, namely that it grants access
 * to its own `msg.sender` and to nobody else, not on its signature, so a dependency bump could
 * break it silently, with no compiler error. These assertions are the guard. If they fail after an
 * `@fhevm/solidity` upgrade, the import no longer contains the grant and every consumer is affected.
 */
import {
  describe, it, expect, beforeAll, beforeEach
} from "vitest";
import { parseEventLogs, toHex } from "viem";

import { createHarness } from "./setup/harness";
import type { Harness } from "./setup/harness";
import { encryptValues, encryptRecipient, decryptEuint } from "./setup/fhe";
import { txOpts, fheTxOpts } from "./setup/tx";
import { assertRevertsWith } from "./setup/asserts";
import { getOrDeployMockFHEUtilsHarness } from "../src/deployers/MockFHEUtilsHarness";

describe("FHEUtils", () => {
  let H: Harness;

  beforeAll(async () => {
    H = await createHarness();
  });
  beforeEach(() => H.reset());

  const boot = async () => {
    const {
      publicClient, wallets, store, fhevm
    } = H;
    const { deployer, alice } = wallets;
    const send = async (p: Promise<`0x${string}`>) => {
      const receipt = await publicClient.waitForTransactionReceipt({ hash: await p });
      if (receipt.status !== "success") throw new Error(`tx reverted: ${receipt.transactionHash}`);
      return receipt;
    };
    const { contract } = await getOrDeployMockFHEUtilsHarness({
      walletClient: deployer,
      publicClient,
      store,
      args: [],
      force: true,
    });
    return {
      contract, send, alice, fhevm
    };
  };

  describe("fromExternal", () => {
    it("grants the importing contract access and the submitter none (euint64)", async () => {
      const {
        contract, send, alice, fhevm
      } = await boot();
      const [handle, inputProof] = await encryptValues(
        fhevm.instance, [{
          type: "add64",
          value: 42n
        }], contract.address, alice.account.address,
      );
      const receipt = await send(contract.write.importAndReportAccess([handle, inputProof], fheTxOpts(alice.account)));
      const [access] = parseEventLogs({
        abi: contract.abi,
        logs: receipt.logs,
        eventName: "ImportAccess"
      });
      if (!access) throw new Error("no ImportAccess event");
      expect(access.args.importer).toBe(true);
      expect(access.args.submitter).toBe(false);
    });

    it("grants the importing contract access and the submitter none (eaddress)", async () => {
      const {
        contract, send, alice, fhevm
      } = await boot();
      const { handle, inputProof } = await encryptRecipient(
        fhevm.instance, contract.address, alice.account.address, alice.account.address,
      );
      const receipt = await send(contract.write.importAddressAndReportAccess([handle, inputProof], fheTxOpts(alice.account)));
      const [access] = parseEventLogs({
        abi: contract.abi,
        logs: receipt.logs,
        eventName: "ImportAccess"
      });
      if (!access) throw new Error("no ImportAccess event");
      expect(access.args.importer).toBe(true);
      expect(access.args.submitter).toBe(false);
    });

    // The expected type is passed to the coprocessor rather than inferred from the overload, so a
    // wrong-typed handle cannot reach a typed slot. That is what makes `FHE.fromExternal`'s
    // empty-proof branch unreachable rather than only gated.
    it("rejects a handle whose type does not match the overload", async () => {
      const { contract, alice, fhevm } = await boot();
      const { handle, inputProof } = await encryptRecipient(
        fhevm.instance, contract.address, alice.account.address, alice.account.address,
      );
      await assertRevertsWith(
        contract.write.importAddressAsAmount([handle, inputProof], txOpts(alice.account)),
        "InvalidType",
      );
    });

    // The library rejects an empty proof itself, before the coprocessor is called, so every
    // consumer gets the same error without a gate of its own.
    it("rejects an empty proof before reaching the coprocessor", async () => {
      const { contract, alice, fhevm } = await boot();
      const [handle] = await encryptValues(
        fhevm.instance, [{
          type: "add64",
          value: 42n
        }], contract.address, alice.account.address,
      );
      await assertRevertsWith(
        contract.write.importAndReportAccess([handle, "0x"], txOpts(alice.account)),
        "MissingInputProof",
      );
    });
  });

  describe("isAuthorizedOn", () => {
    // The laundering shape is a handle some OTHER contract is authorized on, returned by a callee that
    // is not. The check must separate the two even though both handles are real, initialized and
    // allowed to somebody.
    it("is true for a handle the contract computed, false for one only another contract holds", async () => {
      const {
        contract, send, alice, fhevm
      } = await boot();
      const { publicClient, wallets, store } = H;
      const { contract: other } = await getOrDeployMockFHEUtilsHarness({
        walletClient: wallets.deployer,
        publicClient,
        store,
        args: [],
        force: true,
      });

      await send(contract.write.produce([7n], fheTxOpts(alice.account)));
      const own = await contract.read.lastResult();
      expect(await contract.read.authorizedHere([own])).toBe(true);

      // A handle the OTHER harness produced and is allowed on. This one never touched it.
      await send(other.write.produce([9n], fheTxOpts(alice.account)));
      const theirs = await other.read.lastResult();
      expect(await other.read.authorizedHere([theirs])).toBe(true);
      expect(await contract.read.authorizedHere([theirs])).toBe(false);

      // And a handle nobody on-chain is allowed on, a client-side encryption never imported.
      const [foreign] = await encryptValues(
        fhevm.instance, [{
          type: "add64",
          value: 7n
        }], alice.account.address, alice.account.address,
      );
      expect(await contract.read.authorizedHere([foreign])).toBe(false);
    });
  });

  describe("HandleSet", () => {
    // Explicit gas: tevm's estimate under-shoots the second, same-value write and OOG-reverts it.
    it("reports a handle fresh until marked, and marking reports whether it was fresh", async () => {
      const { contract, send, alice } = await boot();
      const handle = toHex(1n, { size: 32 });
      const markedFresh = (receipt: Awaited<ReturnType<typeof send>>) => {
        const [marked] = parseEventLogs({
          abi: contract.abi,
          logs: receipt.logs,
          eventName: "HandleMarked"
        });
        if (!marked) throw new Error("no HandleMarked event");
        return marked.args.wasFresh;
      };

      expect(await contract.read.isFresh([handle])).toBe(true);
      expect(markedFresh(await send(contract.write.markUsed([handle], fheTxOpts(alice.account))))).toBe(true);
      expect(await contract.read.isFresh([handle])).toBe(false);
      expect(markedFresh(await send(contract.write.markUsed([handle], fheTxOpts(alice.account))))).toBe(false);
    });
  });

  describe("sum", () => {
    it("tree-reduces an odd-length input to the correct total", async () => {
      const {
        contract, send, alice, fhevm
      } = await boot();
      // Odd length exercises the carry branch (`r < n ? add : xs[l]`) at more than one level.
      const values = [
        1n, 2n, 3n, 4n, 5n, 6n, 7n
      ];
      await send(contract.write.sumOf([values], fheTxOpts(alice.account)));
      const total = await contract.read.lastResult();
      expect(await decryptEuint(fhevm.instance, total, contract.address, alice)).toBe(28n);
    });

    it("sums an empty input to zero", async () => {
      const { contract, send, alice, fhevm } = await boot();
      await send(contract.write.sumOf([[]], fheTxOpts(alice.account)));
      const total = await contract.read.lastResult();
      expect(await decryptEuint(fhevm.instance, total, contract.address, alice)).toBe(0n);
    });
  });
});
