import { describe, expect, it } from "vitest";
import { getAddress, parseEventLogs, zeroAddress } from "viem";
import type { Hex } from "viem";

import { assertRevertsWith } from "../setup/asserts";
import { fheTxOpts, txOpts } from "../setup/tx";
import { DAY, useAllowanceSuite } from "./setup/suite";
import type { PermitGrantMessage, PermitSpendMessage } from "./setup/suite";

describe("RecurringAllowance: signature permits (FHEPermit2)", () => {
  const S = useAllowanceSuite();

  /** Owner-side of the gasless-grant handshake: encrypt the limit BOUND TO THE SPENDER. */
  const makeGrant = async (params: {
    owner: "alice";
    spender: Hex;
    limit: bigint;
    duration?: bigint;
    startTime?: bigint;
    endTime?: bigint;
    nonce?: bigint;
    sigDeadline?: bigint;
  }) => {
    const { H, token, allowance } = S.ctx();
    const owner = H.wallets[params.owner];
    // The owner registers the ciphertext with the SPENDER as bound submitter.
    const { handle, inputProof } = await S.encAmount(allowance.address, params.spender, params.limit);
    const message: PermitGrantMessage = {
      token: token.address,
      spender: params.spender,
      limitHandle: handle,
      duration: params.duration ?? DAY,
      startTime: params.startTime ?? 0n,
      endTime: params.endTime ?? 0n,
      nonce: params.nonce ?? 0n,
      sigDeadline: params.sigDeadline ?? (await S.now()) + 3600n
    };
    const signature = await S.signPermitGrant(owner, message);
    return {
      message,
      inputProof,
      signature
    };
  };

  const makeCheque = async (params: {
    owner: "alice";
    spender: Hex;
    cap: bigint;
    to?: Hex;
    nonce?: bigint;
    sigDeadline?: bigint;
  }) => {
    const { H, token, allowance } = S.ctx();
    const owner = H.wallets[params.owner];
    const { handle, inputProof } = await S.encAmount(allowance.address, params.spender, params.cap);
    const message: PermitSpendMessage = {
      token: token.address,
      spender: params.spender,
      capHandle: handle,
      to: params.to ?? zeroAddress,
      nonce: params.nonce ?? 0n,
      sigDeadline: params.sigDeadline ?? (await S.now()) + 3600n
    };
    const signature = await S.signPermitSpend(owner, message);
    return {
      message,
      capProof: inputProof,
      signature
    };
  };

  it("creates a permission gaslessly for the owner: sign off-chain, spender submits", async () => {
    const { H, allowance } = S.ctx();
    const { alice, bob, carol } = H.wallets;

    await S.fundUser(alice, 10_000n);
    const { message, inputProof, signature } = await makeGrant({
      owner: "alice",
      spender: bob.account.address,
      limit: 500n
    });

    // BOB submits — alice signs only.
    const receipt = await S.sendOk(allowance.write.permitSetPermission([
      alice.account.address,
      message,
      inputProof,
      signature
    ], fheTxOpts(bob.account)));

    const [event] = parseEventLogs({
      abi: allowance.abi,
      logs: receipt.logs,
      eventName: "PermissionSet"
    });
    expect(getAddress(event.args.user)).toBe(getAddress(alice.account.address));
    expect(getAddress(event.args.spender)).toBe(getAddress(bob.account.address));

    // The permission is a completely normal one: bob can pull against it,
    // and both parties can decrypt it.
    const permission = await S.getPermission(alice.account.address, bob.account.address, 0n);
    expect(await S.decryptAllowanceHandle(permission.limit, alice)).toBe(500n);
    expect(await S.decryptAllowanceHandle(permission.limit, bob)).toBe(500n);

    await S.spend({
      spender: bob,
      from: alice.account.address,
      to: carol.account.address,
      amount: 300n
    });
    expect(await S.balanceOf(carol)).toBe(300n);
    expect(await S.decryptSpent(alice, bob.account.address, 0n)).toBe(300n);
  });

  it("rejects bad grant submissions: wrong signer, wrong submitter, expired, replayed", async () => {
    const { H, allowance } = S.ctx();
    const { alice, bob, carol } = H.wallets;

    await S.fundUser(alice, 10_000n);
    const { message, inputProof, signature } = await makeGrant({
      owner: "alice",
      spender: bob.account.address,
      limit: 500n
    });

    // Signed by bob, claimed to be from alice -> InvalidSigner.
    const bobSignature = await S.signPermitGrant(bob, message);
    await assertRevertsWith(
      allowance.write.permitSetPermission([
        alice.account.address,
        message,
        inputProof,
        bobSignature
      ], txOpts(bob.account)),
      "InvalidSigner",
    );

    // Submitted by carol (not the named spender) -> SpenderMismatch.
    await assertRevertsWith(
      allowance.write.permitSetPermission([
        alice.account.address,
        message,
        inputProof,
        signature
      ], txOpts(carol.account)),
      "SpenderMismatch",
    );

    // Expired deadline -> SignatureExpired.
    const expired = await makeGrant({
      owner: "alice",
      spender: bob.account.address,
      limit: 500n,
      nonce: 1n,
      sigDeadline: (await S.now()) - 1n
    });
    await assertRevertsWith(
      allowance.write.permitSetPermission([
        alice.account.address,
        expired.message,
        expired.inputProof,
        expired.signature
      ], txOpts(bob.account)),
      "SignatureExpired",
    );

    // Valid submission consumes the nonce; replay -> InvalidNonce.
    await S.sendOk(allowance.write.permitSetPermission([
      alice.account.address,
      message,
      inputProof,
      signature
    ], fheTxOpts(bob.account)));
    await assertRevertsWith(
      allowance.write.permitSetPermission([
        alice.account.address,
        message,
        inputProof,
        signature
      ], txOpts(bob.account)),
      "InvalidNonce",
    );
  });

  it("lets the owner cancel a signed-but-unsubmitted grant by burning its nonce", async () => {
    const { H, allowance } = S.ctx();
    const { alice, bob } = H.wallets;

    await S.fundUser(alice, 10_000n);
    const { message, inputProof, signature } = await makeGrant({
      owner: "alice",
      spender: bob.account.address,
      limit: 500n,
      nonce: 7n
    });

    // Alice burns nonce 7 (word 0, bit 7) before bob submits.
    await S.sendOk(allowance.write.invalidateUnorderedNonces([0n, 1n << 7n], txOpts(alice.account)));

    await assertRevertsWith(
      allowance.write.permitSetPermission([
        alice.account.address,
        message,
        inputProof,
        signature
      ], txOpts(bob.account)),
      "InvalidNonce",
    );
  });

  it("executes a one-shot cheque up to the signed cap, obliviously", async () => {
    const { H, allowance } = S.ctx();
    const { alice, bob, carol } = H.wallets;

    await S.fundUser(alice, 10_000n);
    const cheque = await makeCheque({
      owner: "alice",
      spender: bob.account.address,
      cap: 500n
    });

    // Bob requests 300 (within the cap) to carol.
    const requested = await S.encAmount(S.ctx().allowance.address, bob.account.address, 300n);
    const receipt = await S.sendOk(allowance.write.permitTransferFrom([
      alice.account.address,
      cheque.message,
      cheque.capProof,
      requested.handle,
      requested.inputProof,
      carol.account.address,
      cheque.signature
    ], fheTxOpts(bob.account)));

    const [event] = parseEventLogs({
      abi: allowance.abi,
      logs: receipt.logs,
      eventName: "PermitSpent"
    });
    expect(getAddress(event.args.owner)).toBe(getAddress(alice.account.address));
    expect(event.args.nonce).toBe(0n);

    expect(await S.balanceOf(carol)).toBe(300n);
    expect(await S.balanceOf(alice)).toBe(9700n);

    // No stored permission was involved.
    expect(await allowance.read.getGrantedPairCount([alice.account.address])).toBe(0n);

    // The nonce is one-shot: a replay fails even though the cap wasn't exhausted.
    const requested2 = await S.encAmount(allowance.address, bob.account.address, 100n);
    await assertRevertsWith(
      allowance.write.permitTransferFrom([
        alice.account.address,
        cheque.message,
        cheque.capProof,
        requested2.handle,
        requested2.inputProof,
        carol.account.address,
        cheque.signature
      ], txOpts(bob.account)),
      "InvalidNonce",
    );
  });

  it("moves an encrypted zero when the request exceeds the cap (nonce still burns)", async () => {
    const { H, allowance } = S.ctx();
    const { alice, bob, carol } = H.wallets;

    await S.fundUser(alice, 10_000n);
    const cheque = await makeCheque({
      owner: "alice",
      spender: bob.account.address,
      cap: 500n
    });

    const requested = await S.encAmount(allowance.address, bob.account.address, 900n); // over cap
    await S.sendOk(allowance.write.permitTransferFrom([
      alice.account.address,
      cheque.message,
      cheque.capProof,
      requested.handle,
      requested.inputProof,
      carol.account.address,
      cheque.signature
    ], fheTxOpts(bob.account)));

    expect(await S.balanceOf(carol)).toBe(0n);
    expect(await S.balanceOf(alice)).toBe(10_000n);
    // Documented cheque semantics: consumed on submission regardless of outcome.
    expect(await allowance.read.nonceBitmap([alice.account.address, 0n])).toBe(1n);
  });

  it("enforces a bound recipient", async () => {
    const { H, allowance } = S.ctx();
    const {
      alice, bob, carol, signer: dave
    } = H.wallets;

    await S.fundUser(alice, 10_000n);
    const cheque = await makeCheque({
      owner: "alice",
      spender: bob.account.address,
      cap: 500n,
      to: carol.account.address
    });

    const requested = await S.encAmount(allowance.address, bob.account.address, 200n);

    // Redirecting the cheque to dave fails...
    await assertRevertsWith(
      allowance.write.permitTransferFrom([
        alice.account.address,
        cheque.message,
        cheque.capProof,
        requested.handle,
        requested.inputProof,
        dave.account.address,
        cheque.signature
      ], txOpts(bob.account)),
      "RecipientMismatch",
    );

    // ...cashing it to carol works.
    await S.sendOk(allowance.write.permitTransferFrom([
      alice.account.address,
      cheque.message,
      cheque.capProof,
      requested.handle,
      requested.inputProof,
      carol.account.address,
      cheque.signature
    ], fheTxOpts(bob.account)));
    expect(await S.balanceOf(carol)).toBe(200n);
  });

  it("rejects a tampered grant (signature covers every field, including the handle)", async () => {
    const { H, allowance } = S.ctx();
    const { alice, bob } = H.wallets;

    await S.fundUser(alice, 10_000n);
    const { message, inputProof, signature } = await makeGrant({
      owner: "alice",
      spender: bob.account.address,
      limit: 100n
    });

    // Bob substitutes his own (bigger) encrypted limit under alice's signature.
    const forged = await S.encAmount(allowance.address, bob.account.address, 10_000n);
    await assertRevertsWith(
      allowance.write.permitSetPermission([
        alice.account.address,
        {
          ...message,
          limitHandle: forged.handle
        },
        forged.inputProof,
        signature
      ], txOpts(bob.account)),
      "InvalidSigner",
    );

    // Tampering a cleartext field breaks it the same way.
    await assertRevertsWith(
      allowance.write.permitSetPermission([
        alice.account.address,
        {
          ...message,
          duration: DAY * 30n
        },
        inputProof,
        signature
      ], txOpts(bob.account)),
      "InvalidSigner",
    );
  });
});
