/**
 * Minimal FHEVM encrypt/decrypt helpers over a fhevm-tevm-mocks instance.
 *
 * Standalone replacement for the encrypt/decrypt utilities used by the private harness — no
 * relayer-SDK production path, just the test-instance calls the wrappers need.
 */
import {
  getAddress, isHex, padHex, toHex
} from "viem";
import type { Hex, TypedDataDomain } from "viem";
import type { WalletWithAccount } from "./environment";

interface EncryptedInput {
  addAddress: (value: string) => void;
  add64: (value: bigint | number) => void;
  encrypt: () => Promise<{ handles: (string | Uint8Array)[]; inputProof: string | Uint8Array }>;
}

interface Eip712 {
  domain: TypedDataDomain;
  // readonly: the relayer-sdk (via fhevm-tevm-mocks >= 0.3) returns frozen tuples here.
  types: Record<string, readonly { readonly name: string; readonly type: string }[]>;
  primaryType: string;
  message: Record<string, unknown> & {
    startTimestamp: string | number | bigint;
    durationDays: string | number | bigint;
  };
}

/** The subset of the fhevm-tevm-mocks instance surface these helpers use. */
export interface FhevmInstance {
  createEncryptedInput: (contract: string, user: string) => EncryptedInput;
  generateKeypair: () => { publicKey: string; privateKey: string };
  createEIP712: (publicKey: string, contracts: string[], startTimestamp: number, durationDays: number) => Eip712;
  userDecrypt: (
    handles: { contractAddress: string; handle: string }[],
    privateKey: string,
    publicKey: string,
    signature: string,
    contracts: string[],
    user: string,
    startTimestamp: number,
    durationDays: number,
  ) => Promise<Record<string, bigint | string | boolean>>;
}

type EncValue =
  | { type: "addAddress"; value: string }
  | { type: "add64"; value: bigint | number };

const toHandle = (h: string | Uint8Array): Hex =>
  typeof h === "string" && isHex(h) ? padHex(h, { size: 32 }) : toHex(h, { size: 32 });

const toProof = (p: string | Uint8Array): Hex => (typeof p === "string" && isHex(p) ? p : toHex(p));

/**
 * Encrypt `values` for `contractAddress`/`userAddress`, returning `[...handles, inputProof]` —
 * the shape the wrapper entry points expect.
 */
export async function encryptValues (
  instance: FhevmInstance,
  values: EncValue[],
  contractAddress: Hex,
  userAddress: Hex,
): Promise<Hex[]> {
  const input = instance.createEncryptedInput(getAddress(contractAddress), getAddress(userAddress));
  for (const v of values) {
    if (v.type === "addAddress") input.addAddress(v.value);
    else input.add64(v.value);
  }
  const enc = await input.encrypt();
  return [...enc.handles.map(toHandle), toProof(enc.inputProof)];
}

/** Encrypt a single recipient address. Returns `{ handle, inputProof }`. */
export async function encryptRecipient (
  instance: FhevmInstance,
  contractAddress: Hex,
  userAddress: Hex,
  recipient: Hex,
): Promise<{ handle: Hex; inputProof: Hex }> {
  const [handle, inputProof] = await encryptValues(
    instance,
    [{
      type: "addAddress",
      value: recipient
    }],
    contractAddress,
    userAddress,
  );
  return {
    handle,
    inputProof
  };
}

/**
 * Decrypt an euint handle for `owner` via the full userDecrypt flow (fresh keypair authorized by
 * an EIP-712 signature). The tevm mock relayer verifies that signature strictly.
 */
export async function decryptEuint (
  instance: FhevmInstance,
  handle: Hex | bigint,
  contractAddress: Hex,
  owner: WalletWithAccount,
): Promise<bigint> {
  const startTimestamp = Math.floor(Date.now() / 1000);
  const durationDays = 365;
  const keypair = instance.generateKeypair();
  const eip712 = instance.createEIP712(keypair.publicKey, [contractAddress], startTimestamp, durationDays);
  const { EIP712Domain: _domain, ...types } = eip712.types;

  const signature = await owner.signTypedData({
    account: owner.account,
    domain: eip712.domain,
    types,
    primaryType: eip712.primaryType,
    // The mock encodes the uint256 fields as strings; viem's typed signer wants bigint.
    message: {
      ...eip712.message,
      startTimestamp: BigInt(eip712.message.startTimestamp),
      durationDays: BigInt(eip712.message.durationDays),
    },
  });

  const handleHex = toHex(typeof handle === "bigint" ? handle : BigInt(handle), { size: 32 });
  const contract = getAddress(contractAddress);
  const decrypted = await instance.userDecrypt(
    [{
      contractAddress: contract,
      handle: handleHex
    }],
    keypair.privateKey,
    keypair.publicKey,
    signature,
    [contract],
    getAddress(owner.account.address),
    startTimestamp,
    durationDays,
  );

  const value = decrypted[handleHex];
  if (value === undefined) throw new Error("decryptEuint: no decrypted value for handle");
  return typeof value === "bigint" ? value : BigInt(String(value));
}
