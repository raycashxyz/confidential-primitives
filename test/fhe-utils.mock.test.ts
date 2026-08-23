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
import { parseEventLogs } from "viem";
import type { Hex } from "viem";

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

  describe("fromExternalForThis", () => {
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

    it("grants the importing contract access and the submitter none for every other supported type", async () => {
      const {
        contract, send, alice, fhevm
      } = await boot();
      const opts = fheTxOpts(alice.account);
      const cases: Array<{
        type: "add8" | "add16" | "add32" | "add128" | "add256";
        value: bigint;
        call: (h: Hex, p: Hex) => Promise<Hex>;
      }> = [
        {
          type: "add8",
          value: 8n,
          call: (h, p) => contract.write.importUint8AndReportAccess([h, p], opts)
        },
        {
          type: "add16",
          value: 16n,
          call: (h, p) => contract.write.importUint16AndReportAccess([h, p], opts)
        },
        {
          type: "add32",
          value: 32n,
          call: (h, p) => contract.write.importUint32AndReportAccess([h, p], opts)
        },
        {
          type: "add128",
          value: 128n,
          call: (h, p) => contract.write.importUint128AndReportAccess([h, p], opts)
        },
        {
          type: "add256",
          value: 256n,
          call: (h, p) => contract.write.importUint256AndReportAccess([h, p], opts)
        },
      ];
      const reportsContractOnly = (receipt: Awaited<ReturnType<typeof send>>, label: string) => {
        const [access] = parseEventLogs({
          abi: contract.abi,
          logs: receipt.logs,
          eventName: "ImportAccess"
        });
        if (!access) throw new Error(`no ImportAccess event for ${label}`);
        expect(access.args.importer, label).toBe(true);
        expect(access.args.submitter, label).toBe(false);
      };

      for (const c of cases) {
        const [handle, inputProof] = await encryptValues(
          fhevm.instance, [{
            type: c.type,
            value: c.value
          }], contract.address, alice.account.address,
        );
        reportsContractOnly(await send(c.call(handle, inputProof)), c.type);
      }
      const [boolHandle, boolProof] = await encryptValues(
        fhevm.instance, [{
          type: "addBool",
          value: true
        }], contract.address, alice.account.address,
      );
      reportsContractOnly(await send(contract.write.importBoolAndReportAccess([boolHandle, boolProof], opts)), "addBool");
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
