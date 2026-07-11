import {
  beforeAll, beforeEach, describe, expect, it
} from "vitest";
import { zeroAddress, zeroHash } from "viem";

import { createHarness } from "../setup/harness";
import type { Harness } from "../setup/harness";
import type { WalletWithAccount } from "../setup/environment";
import { assertRevertsWith } from "../setup/asserts";
import { decryptEuint, encryptRecipient } from "../setup/fhe";
import { txOpts, fheTxOpts } from "../setup/tx";
import { getOrDeployMockUSDC } from "../../src/deployers/MockUSDC";
import { getOrDeployMockERC7984ERC20Wrapper } from "../../src/deployers/MockERC7984ERC20Wrapper";
import { getOrDeploySimpleAsyncWrapper } from "../../src/deployers/SimpleAsyncWrapper";

const AMOUNT = 100n;

type MockUSDCContract = Awaited<ReturnType<typeof getOrDeployMockUSDC>>["contract"];
type ConfidentialWrapperContract = Awaited<ReturnType<typeof getOrDeployMockERC7984ERC20Wrapper>>["contract"];
type SimpleWrapperContract = Awaited<ReturnType<typeof getOrDeploySimpleAsyncWrapper>>["contract"];

describe("SimpleAsyncWrapper", () => {
  let H: Harness;
  let underlying: MockUSDCContract;
  let confidentialWrapper: ConfidentialWrapperContract;

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

  const sendOk = async (p: Promise<`0x${string}`>) => {
    const receipt = await H.publicClient.waitForTransactionReceipt({ hash: await p });
    if (receipt.status !== "success") throw new Error(`tx reverted: ${receipt.transactionHash}`);
    return receipt;
  };

  const deployWrapper = () =>
    getOrDeploySimpleAsyncWrapper({
      walletClient: H.wallets.deployer,
      publicClient: H.publicClient,
      store: H.store,
      args: [
        confidentialWrapper.address,
        2n
      ],
      force: true,
    });

  const fundAndApprove = async (wrapper: SimpleWrapperContract, who: WalletWithAccount, count: bigint) => {
    await sendOk(underlying.write.transfer([who.account.address, AMOUNT * count], txOpts(H.wallets.deployer.account)));
    await sendOk(underlying.write.approve([wrapper.address, AMOUNT * count], txOpts(who.account)));
  };

  const initWrap = async (wrapper: SimpleWrapperContract, depositor: WalletWithAccount, recipient: `0x${string}`) => {
    const { handle, inputProof } = await encryptRecipient(
      H.fhevm.instance,
      wrapper.address,
      depositor.account.address,
      recipient,
    );
    return sendOk(wrapper.write.initWrap([
      AMOUNT,
      handle,
      inputProof
    ], fheTxOpts(depositor.account)));
  };

  const decryptBalance = async (owner: WalletWithAccount): Promise<bigint> => {
    const handle = await confidentialWrapper.read.confidentialBalanceOf([owner.account.address]);
    if (handle === zeroHash) return 0n;
    return decryptEuint(H.fhevm.instance, handle, confidentialWrapper.address, owner);
  };

  it("wraps into confidential escrow and transfers the matched sum on finalize", async () => {
    const { alice } = H.wallets;
    const { contract: wrapper } = await deployWrapper();

    await fundAndApprove(wrapper, alice, 2n);
    await initWrap(wrapper, alice, alice.account.address);
    await initWrap(wrapper, alice, alice.account.address);

    expect(await underlying.read.balanceOf([confidentialWrapper.address])).toBe(AMOUNT * 2n);
    expect(await wrapper.read.getDepositsLength()).toBe(2n);
    expect(await decryptBalance(alice)).toBe(0n);

    await sendOk(wrapper.write.finalizeWrap([[0n, 1n], alice.account.address], fheTxOpts(alice.account)));

    expect(await decryptBalance(alice)).toBe(AMOUNT * 2n);
  });

  it("enforces the configured minimum decoy set", async () => {
    const { alice } = H.wallets;
    const { contract: wrapper } = await deployWrapper();

    await fundAndApprove(wrapper, alice, 1n);
    await initWrap(wrapper, alice, alice.account.address);

    await assertRevertsWith(
      wrapper.write.finalizeWrap([[0n], alice.account.address], txOpts(alice.account)),
      "TooFewDecoys",
    );
  });

  it("reverts on an out-of-range deposit id", async () => {
    const { alice } = H.wallets;
    const { contract: wrapper } = await deployWrapper();

    await fundAndApprove(wrapper, alice, 1n);
    await initWrap(wrapper, alice, alice.account.address); // only id 0 exists

    await assertRevertsWith(
      wrapper.write.finalizeWrap([[1n, 2n], alice.account.address], txOpts(alice.account)),
      "InvalidId",
    );
  });

  it("rejects a zero recipient", async () => {
    const { alice } = H.wallets;
    const { contract: wrapper } = await deployWrapper();

    await fundAndApprove(wrapper, alice, 2n);
    await initWrap(wrapper, alice, alice.account.address);
    await initWrap(wrapper, alice, alice.account.address);

    await assertRevertsWith(
      wrapper.write.finalizeWrap([[0n, 1n], zeroAddress], txOpts(alice.account)),
      "ZeroAddress",
    );
  });

  it("rejects unsorted or duplicate ids (must be strictly ascending)", async () => {
    const { alice } = H.wallets;
    const { contract: wrapper } = await deployWrapper();

    await fundAndApprove(wrapper, alice, 2n);
    await initWrap(wrapper, alice, alice.account.address);
    await initWrap(wrapper, alice, alice.account.address);

    // unsorted-but-unique reverts DuplicateId (the constraint is strictly ascending, not just unique)
    await assertRevertsWith(
      wrapper.write.finalizeWrap([[1n, 0n], alice.account.address], txOpts(alice.account)),
      "DuplicateId",
    );
    // literal duplicate
    await assertRevertsWith(
      wrapper.write.finalizeWrap([[0n, 0n], alice.account.address], txOpts(alice.account)),
      "DuplicateId",
    );
  });

  it("preserves an unmatched decoy deposit for its true recipient", async () => {
    const { alice, bob } = H.wallets;
    const { contract: wrapper } = await deployWrapper();

    await fundAndApprove(wrapper, alice, 1n);
    await fundAndApprove(wrapper, bob, 1n);
    await initWrap(wrapper, alice, alice.account.address); // id 0 -> alice
    await initWrap(wrapper, bob, bob.account.address); // id 1 -> bob

    // Finalize for alice over [0,1]: id 1 (bob's) is a decoy here and must survive untouched.
    await sendOk(wrapper.write.finalizeWrap([[0n, 1n], alice.account.address], fheTxOpts(alice.account)));
    expect(await decryptBalance(alice)).toBe(AMOUNT);
    expect(await decryptBalance(bob)).toBe(0n);

    // Bob's decoy deposit was preserved: he can still claim it in a later finalize over the same
    // ids — and the already-matched id 0 (now zeroed) contributes nothing to him (no double-spend).
    await sendOk(wrapper.write.finalizeWrap([[0n, 1n], bob.account.address], fheTxOpts(bob.account)));
    expect(await decryptBalance(bob)).toBe(AMOUNT);
    expect(await decryptBalance(alice)).toBe(AMOUNT); // unchanged
  });
});
