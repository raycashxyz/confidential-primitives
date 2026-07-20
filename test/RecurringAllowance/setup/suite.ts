/**
 * Shared harness + helpers for the RecurringAllowance suites.
 *
 * Same shape as the BatchedStealthWrapAdapter suite: each *.mock.test.ts file calls
 * `useAllowanceSuite()` once at the top level; it registers the per-file
 * `beforeAll`/`beforeEach` (one FHEVM env with MockConfidentialToken + RecurringAllowance
 * deployed and snapshotted, restored each test) and returns the bound helpers.
 */
import { beforeAll, beforeEach } from "vitest";
import { parseEventLogs, zeroHash } from "viem";
import type { Hex } from "viem";

import { createHarness } from "../../setup/harness";
import type { Harness } from "../../setup/harness";
import type { WalletWithAccount } from "../../setup/environment";
import { decryptEuint, encryptValues } from "../../setup/fhe";
import { fheTxOpts, txOpts } from "../../setup/tx";
import { getOrDeployMockConfidentialToken } from "../../../src/deployers/MockConfidentialToken";
import { getOrDeployRecurringAllowance } from "../../../src/deployers/RecurringAllowance";

export const DAY = 86_400n;
export const WEEK = 7n * DAY;
export const MONTH = 30n * DAY;
export const YEAR = 365n * DAY;
export const MAX_UINT64 = 2n ** 64n - 1n;

export type TokenContract = Awaited<ReturnType<typeof getOrDeployMockConfidentialToken>>["contract"];
export type AllowanceContract = Awaited<ReturnType<typeof getOrDeployRecurringAllowance>>["contract"];

export interface SetPermissionParams {
  user: WalletWithAccount;
  spender: Hex;
  limit: bigint;
  /** Defaults to DAY. */
  duration?: bigint;
  /** Defaults to 0 (= block.timestamp). */
  startTime?: bigint;
  /** Defaults to 0 (= no expiry). */
  endTime?: bigint;
  tokenAddr?: Hex;
}

export interface SpendParams {
  spender: WalletWithAccount;
  from: Hex;
  to: Hex;
  amount: bigint;
  tokenAddr?: Hex;
}

export interface PermitGrantMessage {
  owner: Hex;
  token: Hex;
  spender: Hex;
  limitHandle: Hex;
  duration: bigint;
  startTime: bigint;
  endTime: bigint;
  nonce: bigint;
  epoch: bigint;
  sigDeadline: bigint;
}

export interface PermitSpendMessage {
  owner: Hex;
  token: Hex;
  spender: Hex;
  capHandle: Hex;
  to: Hex;
  nonce: bigint;
  epoch: bigint;
  sigDeadline: bigint;
}

/** Register the per-file harness (once per file) and return the bound helpers. */
export function useAllowanceSuite () {
  let H: Harness;
  let token: TokenContract;
  let allowance: AllowanceContract;

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

  const sendOk = async (p: Promise<`0x${string}`>) => {
    const receipt = await H.publicClient.waitForTransactionReceipt({ hash: await p });
    if (receipt.status !== "success") throw new Error(`tx reverted: ${receipt.transactionHash}`);
    return receipt;
  };

  const now = async (): Promise<bigint> => {
    const { timestamp } = await H.publicClient.getBlock({ blockTag: "latest" });
    return timestamp;
  };

  const encAmount = async (contract: Hex, user: Hex, amount: bigint) => {
    const [handle, inputProof] = await encryptValues(
      H.fhevm.instance,
      [{
        type: "add64",
        value: amount
      }],
      contract,
      user,
    );
    return {
      handle,
      inputProof
    };
  };

  const mintTo = async (who: WalletWithAccount, amount: bigint) => {
    const { handle, inputProof } = await encAmount(token.address, who.account.address, amount);
    await sendOk(token.write.mint([
      who.account.address,
      handle,
      inputProof
    ], fheTxOpts(who.account)));
  };

  /** Make the RecurringAllowance contract an ERC-7984 operator for `who` (~100y). */
  const approveOperator = async (who: WalletWithAccount) => {
    const until = await now() + 3_153_600_000n; // fits uint48
    await sendOk(token.write.setOperator([allowance.address, until], txOpts(who.account)));
  };

  /** Mint + operator in one go — the standard per-test user setup. */
  const fundUser = async (who: WalletWithAccount, amount: bigint) => {
    await mintTo(who, amount);
    await approveOperator(who);
  };

  const setPermission = async (p: SetPermissionParams) => {
    const { handle, inputProof } = await encAmount(allowance.address, p.user.account.address, p.limit);
    const receipt = await sendOk(allowance.write.setPermission([
      p.tokenAddr ?? token.address,
      p.spender,
      handle,
      inputProof,
      p.duration ?? DAY,
      p.startTime ?? 0n,
      p.endTime ?? 0n
    ], fheTxOpts(p.user.account)));
    const [event] = parseEventLogs({
      abi: allowance.abi,
      logs: receipt.logs,
      eventName: "PermissionSet"
    });
    if (!event) throw new Error("setPermission: no PermissionSet event");
    return {
      receipt,
      permissionId: event.args.permissionId,
      event: event.args
    };
  };

  /** Spend via transferFrom; resolves to the receipt (reverts throw). */
  const spend = async (p: SpendParams) => {
    const { handle, inputProof } = await encAmount(allowance.address, p.spender.account.address, p.amount);
    return sendOk(allowance.write.transferFrom([
      p.from,
      p.to,
      handle,
      inputProof,
      p.tokenAddr ?? token.address
    ], fheTxOpts(p.spender.account)));
  };

  /** Spend WITHOUT an explicit gas limit — use with assertRevertsWith so viem simulates. */
  const spendExpectingRevert = async (p: SpendParams) => {
    const { handle, inputProof } = await encAmount(allowance.address, p.spender.account.address, p.amount);
    return allowance.write.transferFrom([
      p.from,
      p.to,
      handle,
      inputProof,
      p.tokenAddr ?? token.address
    ], txOpts(p.spender.account));
  };

  const getPermission = (user: Hex, spender: Hex, index: bigint) =>
    allowance.read.getPermission([
      user,
      token.address,
      spender,
      index
    ]);

  const getPermissionCount = (user: Hex, spender: Hex) =>
    allowance.read.getPermissionCount([
      user,
      token.address,
      spender
    ]);

  /** Decrypt a limit/spent handle (ACL context: the allowance contract). */
  const decryptAllowanceHandle = (handle: Hex | bigint, owner: WalletWithAccount) =>
    decryptEuint(H.fhevm.instance, handle as Hex, allowance.address, owner);

  /** Decrypt `owner`'s confidential token balance (0n for the uninitialized handle). */
  const balanceOf = async (owner: WalletWithAccount): Promise<bigint> => {
    const handle = await token.read.confidentialBalanceOf([owner.account.address]);
    if (handle === zeroHash) return 0n;
    return decryptEuint(H.fhevm.instance, handle, token.address, owner);
  };

  const decryptSpent = async (user: WalletWithAccount, spender: Hex, index: bigint, as?: WalletWithAccount) => {
    const permission = await getPermission(user.account.address, spender, index);
    return decryptAllowanceHandle(permission.spent, as ?? user);
  };

  const eip712Domain = () => ({
    name: "RecurringAllowance",
    version: "1",
    chainId: 31337,
    verifyingContract: allowance.address
  } as const);

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

  const signPermitGrant = (owner: WalletWithAccount, message: PermitGrantMessage) =>
    owner.signTypedData({
      account: owner.account,
      domain: eip712Domain(),
      types: PERMIT_GRANT_TYPES,
      primaryType: "PermitGrant",
      message
    });

  const signPermitSpend = (owner: WalletWithAccount, message: PermitSpendMessage) =>
    owner.signTypedData({
      account: owner.account,
      domain: eip712Domain(),
      types: PERMIT_SPEND_TYPES,
      primaryType: "PermitSpend",
      message
    });

  return {
    ctx: () => ({
      H,
      token,
      allowance
    }),
    sendOk,
    now,
    encAmount,
    mintTo,
    approveOperator,
    fundUser,
    setPermission,
    spend,
    spendExpectingRevert,
    getPermission,
    getPermissionCount,
    decryptAllowanceHandle,
    decryptSpent,
    balanceOf,
    signPermitGrant,
    signPermitSpend,
  };
}
