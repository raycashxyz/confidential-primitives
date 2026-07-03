import "@nomicfoundation/hardhat-chai-matchers";
import "@nomicfoundation/hardhat-ethers";
import "@nomicfoundation/hardhat-network-helpers";
// Regenerates deployoor's typed deployers automatically after every `hardhat compile`.
import "@deployoor/hardhat";
import "dotenv/config";
import type { HardhatUserConfig } from "hardhat/config";

/** Test-only mnemonic — MUST NOT be used for any real funds. */
const TEST_MNEMONIC = "test test test test test test test test test test test junk";

const MNEMONIC = process.env.MNEMONIC ?? TEST_MNEMONIC;
const sepoliaRpcUrl = process.env.SEPOLIA_RPC_URL ?? "https://ethereum-sepolia-rpc.publicnode.com";

const config: HardhatUserConfig = {
  defaultNetwork: "hardhat",
  paths: {
    sources: "./contracts",
    tests: "./test",
    cache: "./cache",
    artifacts: "./artifacts",
  },
  // The wrappers are ^0.8.27; MockUSDC (^0.8.20) and the OZ/FHEVM deps compile under it too.
  solidity: {
    version: "0.8.27",
    settings: {
      optimizer: { enabled: true, runs: 200 },
      evmVersion: "cancun",
    },
  },
  networks: {
    hardhat: {
      chainId: 31337,
      accounts: { mnemonic: MNEMONIC },
    },
    sepolia: {
      url: sepoliaRpcUrl,
      chainId: 11155111,
      accounts: { mnemonic: MNEMONIC, path: "m/44'/60'/0'/0/", count: 10 },
    },
  },
};

export default config;
