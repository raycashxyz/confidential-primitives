/**
 * ERC-1271 signature support + the cross-account replay regression (the auditor's HIGH).
 *
 * Two Mock1271Wallet contracts share one signer (alice's EOA). Because the permit digest
 * now binds `owner`, a signature authorizing wallet A cannot be replayed against sibling
 * wallet B even though B validates the same underlying signer. Pre-fix (owner absent from
 * the digest) this moved funds from B.
 */
import { beforeAll, beforeEach, describe, expect, it } from "vitest";
import { encodeFunctionData } from "viem";
import type { Hex } from "viem";

import { createHarness } from "../setup/harness";
import type { Harness } from "../setup/harness";
import type { WalletWithAccount } from "../setup/environment";
import { assertRevertsWith } from "../setup/asserts";
import { decryptEuint, encryptValues } from "../setup/fhe";
import { fheTxOpts, txOpts } from "../setup/tx";
import { getOrDeployMockConfidentialToken } from "../../src/deployers/MockConfidentialToken";
import { getOrDeployMock1271Wallet } from "../../src/deployers/Mock1271Wallet";
import { getOrDeployRecurringAllowance } from "../../src/deployers/RecurringAllowance";

const DAY = 86_400n;

const PERMIT_GRANT_TYPES = {
  PermitGrant: [
    { name: "owner", type: "address" },
    { name: "token", type: "address" },
    { name: "spender", type: "address" },
    { name: "limitHandle", type: "bytes32" },
    { name: "duration", type: "uint64" },
    { name: "startTime", type: "uint64" },
    { name: "endTime", type: "uint64" },
    { name: "nonce", type: "uint256" },
    { name: "epoch", type: "uint256" },
    { name: "sigDeadline", type: "uint256" }
  ]
} as const;

const PERMIT_SPEND_TYPES = {
  PermitSpend: [
    { name: "owner", type: "address" },
    { name: "token", type: "address" },
    { name: "spender", type: "address" },
    { name: "capHandle", type: "bytes32" },
    { name: "to", type: "address" },
    { name: "nonce", type: "uint256" },
    { name: "epoch", type: "uint256" },
    { name: "sigDeadline", type: "uint256" }
  ]
} as const;

describe("RecurringAllowance: ERC-1271 signers and cross-account replay", () => {
  let H: Harness;
  let token: Awaited<ReturnType<typeof getOrDeployMockConfidentialToken>>["contract"];
  let allowance: Awaited<ReturnType<typeof getOrDeployRecurringAllowance>>["contract"];

  beforeAll(async () => {
    H = await createHarness(async (env) => {
      ({ contract: token } = await getOrDeployMockConfidentialToken({
        walletClient: env.wallets.deployer,
        publicClient: env.publicClient,
        store: env.store,
        args: []
      }));
      ({ contract: allowance } = await getOrDeployRecurringAllowance({
        walletClient: env.wallets.deployer,
        publicClient: env.publicClient,
        store: env.store,
        args: []
      }));
    });
  });

  beforeEach(() => H.reset());

  const sendOk = async (p: Promise<Hex>) => {
    const receipt = await H.publicClient.waitForTransactionReceipt({ hash: await p });
    if (receipt.status !== "success") throw new Error(`tx reverted: ${receipt.transactionHash}`);
    return receipt;
  };

  const now = async () => (await H.publicClient.getBlock({ blockTag: "latest" })).timestamp;

  const encAmount = async (contract: Hex, user: Hex, amount: bigint) => {
    const [handle, inputProof] = await encryptValues(
      H.fhevm.instance,
      [{ type: "add64", value: amount }],
      contract,
      user,
    );
    return { handle, inputProof };
  };

  const domain = () => ({
    name: "RecurringAllowance",
    version: "1",
    chainId: 31337,
    verifyingContract: allowance.address
  } as const);

  const deployWallet = (signer: Hex) =>
    getOrDeployMock1271Wallet({
      walletClient: H.wallets.deployer,
      publicClient: H.publicClient,
      store: H.store,
      args: [signer],
      force: true
    });

  type WalletContract = Awaited<ReturnType<typeof deployWallet>>["contract"];

  /** Mint to the wallet and make the allowance its operator (driven through execute). */
  const fundWallet = async (wallet: WalletContract, amount: bigint) => {
    const { alice, deployer } = H.wallets;
    const { handle, inputProof } = await encAmount(token.address, alice.account.address, amount);
    await sendOk(token.write.mint([wallet.address, handle, inputProof], fheTxOpts(alice.account)));

    const until = Number(await now()) + 3_153_600_000; // uint48
    const setOperatorData = encodeFunctionData({
      abi: token.abi,
      functionName: "setOperator",
      args: [allowance.address, until]
    });
    // Anyone may call the mock's execute; it makes the wallet the msg.sender to the token.
    // Explicit gas: tevm under-estimates the nested call through execute.
    await sendOk(wallet.write.execute([token.address, setOperatorData], fheTxOpts(deployer.account)));
  };

  const signGrant = (
    signerWallet: WalletWithAccount,
    message: Record<string, unknown>,
  ) => signerWallet.signTypedData({
    account: signerWallet.account,
    domain: domain(),
    types: PERMIT_GRANT_TYPES,
    primaryType: "PermitGrant",
    message
  } as never);

  const signSpend = (
    signerWallet: WalletWithAccount,
    message: Record<string, unknown>,
  ) => signerWallet.signTypedData({
    account: signerWallet.account,
    domain: domain(),
    types: PERMIT_SPEND_TYPES,
    primaryType: "PermitSpend",
    message
  } as never);

  it("accepts a correctly-targeted 1271 grant and rejects the cross-account replay", async () => {
    const { alice, bob } = H.wallets;
    const { contract: walletA } = await deployWallet(alice.account.address);
    const { contract: walletB } = await deployWallet(alice.account.address);

    const { handle, inputProof } = await encAmount(allowance.address, bob.account.address, 500n);
    const grant = {
      token: token.address,
      spender: bob.account.address,
      limitHandle: handle,
      duration: DAY,
      startTime: 0n,
      endTime: 0n,
      nonce: 0n,
      sigDeadline: (await now()) + 3600n
    };
    // Alice's key signs a grant naming wallet A as owner.
    const signature = await signGrant(alice, {
      owner: walletA.address,
      epoch: 0n,
      ...grant
    });

    // Replay against wallet B (same signer) reverts — the digest binds owner=B now.
    await assertRevertsWith(
      allowance.write.permitSetPermission([walletB.address, grant, inputProof, signature], txOpts(bob.account)),
      "InvalidSigner",
    );
    expect(await allowance.read.getPermissionCount([walletB.address, token.address, bob.account.address])).toBe(0n);

    // The correctly-targeted submission (owner = wallet A) succeeds.
    await sendOk(allowance.write.permitSetPermission([walletA.address, grant, inputProof, signature], fheTxOpts(bob.account)));
    expect(await allowance.read.getPermissionCount([walletA.address, token.address, bob.account.address])).toBe(1n);
  });

  it("cannot cash a 1271 cheque against a sibling wallet; funds move only from the named owner", async () => {
    const { alice, bob, carol } = H.wallets;
    const { contract: walletA } = await deployWallet(alice.account.address);
    const { contract: walletB } = await deployWallet(alice.account.address);

    await fundWallet(walletA, 10_000n);
    await fundWallet(walletB, 10_000n);

    const { handle, inputProof } = await encAmount(allowance.address, bob.account.address, 500n);
    const permit = {
      token: token.address,
      spender: bob.account.address,
      capHandle: handle,
      to: carol.account.address,
      nonce: 0n,
      sigDeadline: (await now()) + 3600n
    };
    const signature = await signSpend(alice, {
      owner: walletA.address,
      epoch: 0n,
      ...permit
    });

    const requested = await encAmount(allowance.address, bob.account.address, 200n);

    // Replay against wallet B reverts before any transfer.
    await assertRevertsWith(
      allowance.write.permitTransferFrom([
        walletB.address,
        permit,
        inputProof,
        requested.handle,
        requested.inputProof,
        carol.account.address,
        signature
      ], txOpts(bob.account)),
      "InvalidSigner",
    );

    // Correctly targeted (owner = wallet A) moves funds to carol (an EOA we can decrypt).
    await sendOk(allowance.write.permitTransferFrom([
      walletA.address,
      permit,
      inputProof,
      requested.handle,
      requested.inputProof,
      carol.account.address,
      signature
    ], fheTxOpts(bob.account)));

    const carolHandle = await token.read.confidentialBalanceOf([carol.account.address]);
    const carolBalance = await decryptEuint(H.fhevm.instance, carolHandle, token.address, carol);
    expect(carolBalance).toBe(200n);
  });
});
