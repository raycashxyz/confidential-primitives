import { toFunctionSelector } from "viem";

/**
 * Assert a promise (a viem write/simulate or a deployoor deploy) reverts with a specific custom
 * error. Matches either the decoded error name (viem decodes it for contract calls) or its 4-byte
 * selector (deployoor surfaces constructor reverts as the raw selector). Assumes a no-arg error.
 *
 * Pass revert-expected *calls* WITHOUT an explicit gas limit (plain txOpts) so viem simulates and
 * surfaces the revert at call time.
 */
export async function assertRevertsWith (promise: Promise<unknown>, errorName: string): Promise<void> {
  let selector: string | undefined;
  try {
    selector = toFunctionSelector(`${errorName}()`).toLowerCase();
  } catch {
    selector = undefined;
  }

  try {
    await promise;
  } catch (error) {
    const message = (error instanceof Error ? error.message : String(error)).toLowerCase();
    if (message.includes(errorName.toLowerCase())) return;
    if (selector && message.includes(selector)) return;
    throw new Error(`expected revert "${errorName}"${selector ? ` (${selector})` : ""}, got: ${message}`);
  }
  throw new Error(`expected revert "${errorName}" but the call succeeded`);
}

/**
 * The ACL rejects an unauthorized `allow` / `makePubliclyDecryptable` with `SenderNotAllowed(address)`.
 * That error lives in a host contract, not in ours, so viem cannot name it and surfaces the raw
 * 4-byte selector; match on the selector instead.
 */
export const SENDER_NOT_ALLOWED = toFunctionSelector("SenderNotAllowed(address)").toLowerCase();

/** Assert a promise reverts with a specific 4-byte selector, for errors outside our own ABIs. */
export async function assertRevertsWithSelector (promise: Promise<unknown>, selector: string): Promise<void> {
  try {
    await promise;
  } catch (error) {
    const message = (error instanceof Error ? error.message : String(error)).toLowerCase();
    if (message.includes(selector)) return;
    throw new Error(`expected revert selector ${selector}, got: ${message}`);
  }
  throw new Error(`expected revert selector ${selector} but the call succeeded`);
}
