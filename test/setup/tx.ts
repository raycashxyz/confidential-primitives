import { hardhat as hardhatChain } from "viem/chains";
import type { Account } from "viem";

/**
 * tevm's gas estimate under-shoots FHE state-changing writes (they'd silently OOG-revert), so
 * FHE calls (initWrap / finalizeWrap / wrapper unwrap / …) pass an explicit gas limit via fheTxOpts.
 * Plain reads and ERC-20 transfers use txOpts. Do NOT use fheTxOpts for revert-expected calls —
 * an explicit gas makes viem skip simulation, so the revert wouldn't surface at call time.
 */
export const FHE_GAS = 15_000_000n;

export const txOpts = (account: Account) => ({
  account,
  chain: hardhatChain,
});

export const fheTxOpts = (account: Account) => ({
  ...txOpts(account),
  gas: FHE_GAS,
});
