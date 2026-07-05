/**
 * In-memory FHEVM test environment: tevm (via @deployoor/testing) + fhevm-tevm-mocks.
 *
 * This is the single place that knows about the test *runtime*. Everything else (the test
 * files) works off the plain viem clients + named wallets + `fhevm` instance it returns, so the
 * runtime never leaks into test bodies.
 */
import { createTestClients } from "@deployoor/testing";
import { createFhevmTevmRuntime } from "fhevm-tevm-mocks";
import type { FhevmTevmRuntime } from "fhevm-tevm-mocks";
import { createCommon } from "tevm/common";
import { hardhat } from "viem/chains";
import type {
  Account, Chain, PublicClient, WalletClient
} from "viem";

export type WalletWithAccount = WalletClient & { account: Account };

/** Named test wallets. */
export interface NamedWallets {
  deployer: WalletWithAccount;
  alice: WalletWithAccount;
  bob: WalletWithAccount;
  carol: WalletWithAccount;
  signer: WalletWithAccount;
}

type TestClients = Awaited<ReturnType<typeof createTestClients>>;

export interface TestEnvironment {
  publicClient: PublicClient;
  wallets: NamedWallets;
  chain: Chain;
  /** deployoor in-memory store — pass to getOrDeploy so nothing touches disk. */
  store: TestClients["store"];
  /** tevm cheatcodes (mine, setBalance, …). */
  cheatcodes: TestClients["cheatcodes"];
  /** Advance the chain clock by `seconds`. */
  warpTime: (seconds: bigint) => Promise<void>;
  /** Advance the chain clock to (at least) absolute `timestamp`. */
  warpTo: (timestamp: bigint) => Promise<void>;
  /** Prefunded wallet client at `index` (0..4 alias deployer..signer) for suites needing extras. */
  walletAt: (index: number) => WalletWithAccount;
  /** Every prefunded wallet (all tevm accounts) — used by the snapshot harness to resync nonces. */
  allWallets: WalletWithAccount[];
  fhevm: FhevmTevmRuntime["fhevm"];
}

/**
 * Boot a fresh in-memory EVM with the Zama FHEVM mock installed.
 *
 * chainId is viem's `hardhat` chain (31337): the contracts inherit `ZamaEthereumConfig`, which at
 * 31337 selects the local coprocessor config — exactly the host addresses fhevm-tevm-mocks
 * installs. Any other chainId makes the wrapper constructor revert `ZamaProtocolUnsupported`.
 */
export async function createTestEnvironment (): Promise<TestEnvironment> {
  const clients = await createTestClients({ common: createCommon({ ...hardhat }) });
  const runtime = await createFhevmTevmRuntime(clients.tevm);

  const [
    deployer,
    alice,
    bob,
    carol,
    signer
  ] = runtime.accounts;
  if (!bob || !carol || !signer) {
    throw new Error("createTestEnvironment: expected at least 5 prefunded tevm accounts");
  }
  const walletFor = (account: Account) => runtime.walletClientFor(account) as WalletWithAccount;

  const walletAt = (index: number): WalletWithAccount => {
    const account = runtime.accounts[index];
    if (!account) {
      throw new Error(`createTestEnvironment: no prefunded account at index ${index}`);
    }
    return walletFor(account);
  };

  // tevm has no `evm_increaseTime`; mine two blocks `seconds` apart to move the head forward.
  const warpTime = async (seconds: bigint): Promise<void> => {
    await clients.cheatcodes.mine({
      blockCount: 2,
      interval: Number(seconds),
    });
  };

  const warpTo = async (timestamp: bigint): Promise<void> => {
    const { timestamp: current } = await runtime.publicClient.getBlock({ blockTag: "latest" });
    if (timestamp > current) await warpTime(timestamp - current);
  };

  return {
    publicClient: runtime.publicClient,
    wallets: {
      deployer: walletFor(deployer),
      alice: walletFor(alice),
      bob: walletFor(bob),
      carol: walletFor(carol),
      signer: walletFor(signer),
    },
    chain: runtime.chain,
    store: clients.store,
    cheatcodes: clients.cheatcodes,
    warpTime,
    warpTo,
    walletAt,
    allWallets: runtime.accounts.map(walletFor),
    fhevm: runtime.fhevm,
  };
}
