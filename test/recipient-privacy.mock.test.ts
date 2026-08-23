/**
 * Recipient privacy against the DEPOSITOR (issue #36), for both shipped adapters.
 *
 * The recipient handshake hides the recipient from chain observers. It must also hide it from the
 * depositor, including a CONTRACT depositor, which unlike an EOA can act again in the same
 * transaction. The leak the fix closes is that `FHE.fromExternal` grants the depositor (msg.sender)
 * transient ACL access to the verified recipient ciphertext, and a contract can promote that grant
 * to a persistent `FHE.allow` or a public `FHE.makePubliclyDecryptable` before the transaction ends,
 * then decrypt the recipient off-chain.
 *
 * {StealthWrapAdapter._verifyRecipient} imports the ciphertext through `FHEUtils.fromExternalForThis`,
 * which calls the coprocessor's `verifyInput` directly, so the only ACL grant goes to the adapter, never to the depositor. These
 * tests drive the exact attack from a malicious contract depositor and assert it gets nothing:
 *   - the depositor is NOT allowed on the recipient handle right after depositing, and
 *   - both escalation calls revert `SenderNotAllowed` at the ACL,
 * while a normal deposit by that same contract still succeeds. The depositor-bound proof of #9 is
 * unchanged, so a contract can deposit, it just cannot read the recipient.
 */
import {
  beforeAll, beforeEach, describe, expect, it
} from "vitest";
import { parseEventLogs } from "viem";
import type { Hex } from "viem";

import { createHarness } from "./setup/harness";
import { assertRevertsWithSelector, SENDER_NOT_ALLOWED } from "./setup/asserts";
import type { Harness } from "./setup/harness";
import { encryptRecipient } from "./setup/fhe";
import { txOpts, fheTxOpts } from "./setup/tx";
import { getOrDeployMockUSDC } from "../src/deployers/MockUSDC";
import { getOrDeployMockERC7984ERC20Wrapper } from "../src/deployers/MockERC7984ERC20Wrapper";
import { getOrDeployContinuousStealthWrapAdapter } from "../src/deployers/ContinuousStealthWrapAdapter";
import { getOrDeployBatchedStealthWrapAdapter } from "../src/deployers/BatchedStealthWrapAdapter";
import { getOrDeployMockRecipientStealingDepositor } from "../src/deployers/MockRecipientStealingDepositor";

const AMOUNT = 100n;
const SEAL_DELAY = 3600n;

type USDC = Awaited<ReturnType<typeof getOrDeployMockUSDC>>["contract"];
type Wrapper = Awaited<ReturnType<typeof getOrDeployMockERC7984ERC20Wrapper>>["contract"];
type Attacker = Awaited<ReturnType<typeof getOrDeployMockRecipientStealingDepositor>>["contract"];

describe("recipient privacy against the depositor (#36)", () => {
  let H: Harness;
  let underlying: USDC;
  let confidentialWrapper: Wrapper;

  beforeAll(async () => {
    H = await createHarness(async (env) => {
      const { contract: token } = await getOrDeployMockUSDC({
        walletClient: env.wallets.deployer,
        publicClient: env.publicClient,
        store: env.store,
        args: [6]
      });
      underlying = token;

      const { contract: wrapperToken } = await getOrDeployMockERC7984ERC20Wrapper({
        walletClient: env.wallets.deployer,
        publicClient: env.publicClient,
        store: env.store,
        args: [
          underlying.address,
          "Confidential USDC",
          "cUSDC"
        ]
      });
      confidentialWrapper = wrapperToken;
    });
  });

  beforeEach(() => H.reset());

  const send = async (p: Promise<Hex>) => {
    const receipt = await H.publicClient.waitForTransactionReceipt({ hash: await p });
    if (receipt.status !== "success") throw new Error(`tx reverted: ${receipt.transactionHash}`);
    return receipt;
  };

  const deployContinuous = async () => {
    const { contract } = await getOrDeployContinuousStealthWrapAdapter({
      walletClient: H.wallets.deployer,
      publicClient: H.publicClient,
      store: H.store,
      args: [
        confidentialWrapper.address,
        2n
      ],
      force: true,
    });
    return contract.address;
  };

  const deployBatched = async () => {
    const { contract } = await getOrDeployBatchedStealthWrapAdapter({
      walletClient: H.wallets.deployer,
      publicClient: H.publicClient,
      store: H.store,
      args: [
        4n,
        SEAL_DELAY,
        confidentialWrapper.address
      ],
      force: true,
    });
    return contract.address;
  };

  // Deploy an attacker contract pointed at `adapterAddress`, fund it with underlying, and encrypt a
  // recipient bound to (adapter, attacker), since the attacker is the depositor, so it is `userAddress`.
  const setupAttack = async (adapterAddress: Hex, recipient: Hex) => {
    const { contract: attacker } = await getOrDeployMockRecipientStealingDepositor({
      walletClient: H.wallets.deployer,
      publicClient: H.publicClient,
      store: H.store,
      args: [
        adapterAddress,
        underlying.address
      ],
      force: true,
    });
    await send(underlying.write.transfer([attacker.address, AMOUNT], txOpts(H.wallets.deployer.account)));
    const { handle, inputProof } = await encryptRecipient(
      H.fhevm.instance,
      adapterAddress,
      attacker.address,
      recipient,
    );
    return {
      attacker,
      handle,
      inputProof
    };
  };

  const selfAccessAfterDeposit = async (attacker: Attacker, handle: Hex, inputProof: Hex): Promise<boolean> => {
    const receipt = await send(
      attacker.write.depositAndReportSelfAccess([AMOUNT, handle, inputProof], fheTxOpts(H.wallets.deployer.account)),
    );
    const [event] = parseEventLogs({
      abi: attacker.abi,
      logs: receipt.logs,
      eventName: "DepositorSelfAccess"
    });
    if (!event) throw new Error("DepositorSelfAccess not emitted");
    return event.args.depositorAllowedOnRecipient;
  };

  describe.each([
    {
      name: "ContinuousStealthWrapAdapter",
      deploy: () => deployContinuous()
    },
    {
      name: "BatchedStealthWrapAdapter",
      deploy: () => deployBatched()
    },
  ])("$name", ({ deploy }) => {
    it("grants the depositor NO ACL access to the recipient it deposited for", async () => {
      const recipient = H.wallets.bob.account.address;
      const adapterAddress = await deploy();
      const { attacker, handle, inputProof } = await setupAttack(adapterAddress, recipient);

      // The deposit succeeds, since a contract depositor's proof still works, but the depositor holds no
      // ACL access to the stored recipient handle, nothing it could escalate or decrypt.
      expect(await selfAccessAfterDeposit(attacker, handle, inputProof)).toBe(false);
    });

    it("reverts a same-tx attempt to make the recipient publicly decryptable", async () => {
      const recipient = H.wallets.bob.account.address;
      const adapterAddress = await deploy();
      const { attacker, handle, inputProof } = await setupAttack(adapterAddress, recipient);

      await assertRevertsWithSelector(
        attacker.write.depositThenPublish([AMOUNT, handle, inputProof], txOpts(H.wallets.deployer.account)),
        SENDER_NOT_ALLOWED,
      );
    });

    it("reverts a same-tx attempt to persist the recipient handle to the depositor", async () => {
      const recipient = H.wallets.bob.account.address;
      const adapterAddress = await deploy();
      const { attacker, handle, inputProof } = await setupAttack(adapterAddress, recipient);

      await assertRevertsWithSelector(
        attacker.write.depositThenPersist([AMOUNT, handle, inputProof], txOpts(H.wallets.deployer.account)),
        SENDER_NOT_ALLOWED,
      );
    });
  });
});
