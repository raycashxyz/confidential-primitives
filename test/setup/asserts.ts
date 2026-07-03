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
