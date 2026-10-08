import { describe, expect, it } from "vitest";
import { getAddress, parseEventLogs, zeroAddress } from "viem";
import type { Hex } from "viem";

import { assertRevertsWith, assertRevertsWithSelector, SENDER_NOT_ALLOWED } from "../setup/asserts";
import { fheTxOpts, txOpts } from "../setup/tx";
import { DAY, useAllowanceSuite } from "./setup/suite";
import type { PermitGrantMessage, PermitSpendMessage } from "./setup/suite";
import { getOrDeployMockHandleStealingToken } from "../../src/deployers/MockHandleStealingToken";
import { getOrDeployMockCapStealingSpender } from "../../src/deployers/MockCapStealingSpender";

describe("RecurringAllowance: signature permits (FHEPermit2)", () => {
  const S = useAllowanceSuite();

  // The struct passed to the contract call. Owner and epoch are bound at
  // verification from the function arg and on-chain storage, not the calldata struct.
  type GrantStruct = Omit<PermitGrantMessage, "owner" | "epoch">;
  type SpendStruct = Omit<PermitSpendMessage, "owner" | "epoch">;

  /** Owner-side of the gasless-grant handshake. Encrypt the limit BOUND TO THE SPENDER. */
  const makeGrant = async (params: {
    owner: "alice";
    spender: Hex;
    limit: bigint;
    duration?: bigint;
    startTime?: bigint;
    endTime?: bigint;
    nonce?: bigint;
    epoch?: bigint;
    sigDeadline?: bigint;
  }) => {
    const { H, token, allowance } = S.ctx();
    const owner = H.wallets[params.owner];
    const { handle, inputProof } = await S.encAmount(allowance.address, params.spender, params.limit);
    const grant: GrantStruct = {
      token: token.address,
      spender: params.spender,
      limitHandle: handle,
      duration: params.duration ?? DAY,
      startTime: params.startTime ?? 0n,
      endTime: params.endTime ?? 0n,
      nonce: params.nonce ?? 0n,
      sigDeadline: params.sigDeadline ?? (await S.now()) + 3600n
    };
    const epoch = params.epoch ?? (await allowance.read.permitEpoch([owner.account.address]));
    const signature = await S.signPermitGrant(owner, {
      owner: owner.account.address,
      epoch,
      ...grant
    });
    return {
      grant,
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
    epoch?: bigint;
    sigDeadline?: bigint;
    tokenAddr?: Hex;
  }) => {
    const { H, token, allowance } = S.ctx();
    const owner = H.wallets[params.owner];
    const { handle, inputProof } = await S.encAmount(allowance.address, params.spender, params.cap);
    const permit: SpendStruct = {
      token: params.tokenAddr ?? token.address,
      spender: params.spender,
      capHandle: handle,
      to: params.to ?? zeroAddress,
      nonce: params.nonce ?? 0n,
      sigDeadline: params.sigDeadline ?? (await S.now()) + 3600n
    };
    const epoch = params.epoch ?? (await allowance.read.permitEpoch([owner.account.address]));
    const signature = await S.signPermitSpend(owner, {
      owner: owner.account.address,
      epoch,
      ...permit
    });
    return {
      permit,
      capProof: inputProof,
      signature
    };
  };

  // The cheque path is the most direct version of the stolen-return-handle attack. It hands the
  // token's return value straight to `msg.sender` via allowTransient, so a contract spender can
  // persist it with FHE.allow in the same transaction, with no laundering through `spent` and no
  // arithmetic inference needed, unlike the transferFrom paths. Same provenance check guards it.
  it("rejects a token-returned handle the token is not authorized on, through the cheque path", async () => {
    const { H, allowance } = S.ctx();
    const { deployer, alice, bob, carol } = H.wallets;

    // The victim: carol's encrypted limit, public via getPermission and never the evil token's.
    await S.setPermission({
      user: carol,
      spender: alice.account.address,
      limit: 4321n
    });
    const victim = await S.getPermission(carol.account.address, alice.account.address, 0n);

    // A hostile token the cheque owner holds balance in, with the allowance as its operator.
    const { contract: evil } = await getOrDeployMockHandleStealingToken({
      walletClient: deployer,
      publicClient: H.publicClient,
      store: H.store,
      args: [],
      force: true,
    });
    const minted = await S.encAmount(evil.address, alice.account.address, 10_000n);
    await S.sendOk(evil.write.mint([
      alice.account.address,
      minted.handle,
      minted.inputProof
    ], fheTxOpts(alice.account)));
    const until = Number(await S.now()) + 3_153_600_000;
    await S.sendOk(evil.write.setOperator([allowance.address, until], txOpts(alice.account)));

    // Still honest here, so the revert below is the substitution rather than a broken fixture.
    const honest = await makeCheque({
      owner: "alice",
      spender: bob.account.address,
      cap: 500n,
      tokenAddr: evil.address
    });
    const firstRequest = await S.encAmount(allowance.address, bob.account.address, 100n);
    await S.sendOk(allowance.write.permitTransferFrom([
      alice.account.address,
      honest.permit,
      honest.capProof,
      firstRequest.handle,
      firstRequest.inputProof,
      carol.account.address,
      honest.signature
    ], fheTxOpts(bob.account)));

    await S.sendOk(evil.write.setStolenHandle([victim.limit], txOpts(bob.account)));

    const armed = await makeCheque({
      owner: "alice",
      spender: bob.account.address,
      cap: 500n,
      nonce: 1n,
      tokenAddr: evil.address
    });
    const request = await S.encAmount(allowance.address, bob.account.address, 100n);
    await assertRevertsWith(
      allowance.write.permitTransferFrom([
        alice.account.address,
        armed.permit,
        armed.capProof,
        request.handle,
        request.inputProof,
        carol.account.address,
        armed.signature
      ], txOpts(bob.account)),
      "InvalidReturnedHandle",
    );

    // Carol's limit stayed hers. Bob never received a handle he could decrypt.
    await expect(S.decryptAllowanceHandle(victim.limit, bob)).rejects.toThrow();
  });

  // The cap is the owner's private ceiling for one cheque. It is never granted onward, so the spender
  // learns only whether their request fit. FHE.fromExternal would have handed the submitter a
  // transient grant on it, which a CONTRACT spender can persist and decrypt inside the same
  // transaction. FHEUtils keeps the grant on the allowance contract alone.
  it("does not let a contract spender read the cheque cap", async () => {
    const { H, token, allowance } = S.ctx();
    const { deployer, alice, carol } = H.wallets;

    const { contract: thief } = await getOrDeployMockCapStealingSpender({
      walletClient: deployer,
      publicClient: H.publicClient,
      store: H.store,
      args: [allowance.address],
      force: true,
    });

    await S.fundUser(alice, 10_000n);

    // Owner signs a cheque naming the CONTRACT as spender. Cap and request bind to it, not to an EOA.
    const cheque = await makeCheque({
      owner: "alice",
      spender: thief.address,
      cap: 500n
    });
    const requested = await S.encAmount(allowance.address, thief.address, 300n);
    const call = [
      alice.account.address,
      cheque.permit,
      cheque.capProof,
      requested.handle,
      requested.inputProof,
      carol.account.address,
      cheque.signature
    ] as const;

    const receipt = await S.sendOk(thief.write.spendAndReportSelfAccess(call, fheTxOpts(deployer.account)));
    const [access] = parseEventLogs({
      abi: thief.abi,
      logs: receipt.logs,
      eventName: "SpenderSelfAccess"
    });
    if (!access) throw new Error("no SpenderSelfAccess event");
    expect(access.args.spenderAllowedOnCap).toBe(false);

    // The cheque did execute. The spend is not a silent no-op.
    expect(await S.balanceOf(carol)).toBe(300n);

    // And escalating that access reverts at the ACL. Fresh nonce, since the first cheque burned nonce 0.
    const second = await makeCheque({
      owner: "alice",
      spender: thief.address,
      cap: 500n,
      nonce: 1n
    });
    const requested2 = await S.encAmount(allowance.address, thief.address, 100n);
    await assertRevertsWithSelector(
      thief.write.spendThenPersistCap([
        alice.account.address,
        second.permit,
        second.capProof,
        requested2.handle,
        requested2.inputProof,
        carol.account.address,
        second.signature
      ], txOpts(deployer.account)),
      SENDER_NOT_ALLOWED,
    );
  });

  it("creates a permission gaslessly for the owner: sign off-chain, spender submits", async () => {
    const { H, allowance } = S.ctx();
    const { alice, bob, carol } = H.wallets;

    await S.fundUser(alice, 10_000n);
    const { grant, inputProof, signature } = await makeGrant({
      owner: "alice",
      spender: bob.account.address,
      limit: 500n
    });

    // BOB submits. Alice signs only.
    const receipt = await S.sendOk(allowance.write.permitSetPermission([
      alice.account.address,
      grant,
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

    // The permission is a completely normal one. Bob can pull against it,
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

  // Same gate as setPermission. The gasless path must not become a way to store an unverified,
  // untyped handle as a permission limit.
  it("rejects a grant submitted with an empty inputProof", async () => {
    const { H, allowance } = S.ctx();
    const { alice, bob } = H.wallets;

    const { grant, signature } = await makeGrant({
      owner: "alice",
      spender: bob.account.address,
      limit: 500n
    });

    await assertRevertsWith(
      allowance.write.permitSetPermission([
        alice.account.address,
        grant,
        "0x",
        signature
      ], txOpts(bob.account)),
      "MissingInputProof",
    );
  });

  it("rejects bad grant submissions: wrong signer, wrong submitter, expired, replayed", async () => {
    const { H, allowance } = S.ctx();
    const { alice, bob, carol } = H.wallets;

    await S.fundUser(alice, 10_000n);
    const { grant, inputProof, signature } = await makeGrant({
      owner: "alice",
      spender: bob.account.address,
      limit: 500n
    });

    // Signed by bob but claimed from alice -> InvalidSigner, since bob signs the same message.
    const bobSignature = await S.signPermitGrant(bob, {
      owner: alice.account.address,
      epoch: 0n,
      ...grant
    });
    await assertRevertsWith(
      allowance.write.permitSetPermission([
        alice.account.address,
        grant,
        inputProof,
        bobSignature
      ], txOpts(bob.account)),
      "InvalidSigner",
    );

    // Submitted by carol (not the named spender) -> SpenderMismatch.
    await assertRevertsWith(
      allowance.write.permitSetPermission([
        alice.account.address,
        grant,
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
        expired.grant,
        expired.inputProof,
        expired.signature
      ], txOpts(bob.account)),
      "SignatureExpired",
    );

    // Valid submission consumes the nonce. Replay -> InvalidNonce.
    await S.sendOk(allowance.write.permitSetPermission([
      alice.account.address,
      grant,
      inputProof,
      signature
    ], fheTxOpts(bob.account)));
    await assertRevertsWith(
      allowance.write.permitSetPermission([
        alice.account.address,
        grant,
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
    const { grant, inputProof, signature } = await makeGrant({
      owner: "alice",
      spender: bob.account.address,
      limit: 500n,
      nonce: 7n
    });

    // Alice burns nonce 7 (word 0, bit 7) before bob submits.
    const receipt = await S.sendOk(allowance.write.invalidateUnorderedNonces([0n, 1n << 7n], txOpts(alice.account)));
    const [burned] = parseEventLogs({
      abi: allowance.abi,
      logs: receipt.logs,
      eventName: "UnorderedNonceInvalidation"
    });
    if (!burned) throw new Error("no UnorderedNonceInvalidation event");
    expect(burned.args.owner).toBe(getAddress(alice.account.address));
    expect(burned.args.word).toBe(0n);
    expect(burned.args.mask).toBe(1n << 7n);

    await assertRevertsWith(
      allowance.write.permitSetPermission([
        alice.account.address,
        grant,
        inputProof,
        signature
      ], txOpts(bob.account)),
      "InvalidNonce",
    );
  });

  it("honors unordered nonces across a word boundary (nonce >= 256)", async () => {
    const { H, allowance } = S.ctx();
    const { alice, bob, carol } = H.wallets;

    await S.fundUser(alice, 10_000n);
    // nonce 300 = word 1, bit 44.
    const { grant, inputProof, signature } = await makeGrant({
      owner: "alice",
      spender: bob.account.address,
      limit: 500n,
      nonce: 300n
    });

    await S.sendOk(allowance.write.permitSetPermission([
      alice.account.address,
      grant,
      inputProof,
      signature
    ], fheTxOpts(bob.account)));
    expect(await S.getPermissionCount(alice.account.address, bob.account.address)).toBe(1n);

    // Word 1 now has bit 44 set. A fresh nonce in the same word still works.
    const second = await makeGrant({
      owner: "alice",
      spender: bob.account.address,
      limit: 200n,
      nonce: 301n
    });
    await S.sendOk(allowance.write.permitSetPermission([
      alice.account.address,
      second.grant,
      second.inputProof,
      second.signature
    ], fheTxOpts(bob.account)));
    expect(await S.getPermissionCount(alice.account.address, bob.account.address)).toBe(2n);
  });

  it("invalidateAllPermits cancels every outstanding grant and cheque at once", async () => {
    const { H, allowance } = S.ctx();
    const { alice, bob, carol } = H.wallets;

    await S.fundUser(alice, 10_000n);
    // Two independent signatures at the current epoch (0).
    const grant = await makeGrant({
      owner: "alice",
      spender: bob.account.address,
      limit: 500n,
      nonce: 1n
    });
    const cheque = await makeCheque({
      owner: "alice",
      spender: bob.account.address,
      cap: 500n,
      nonce: 2n
    });

    // Alice bumps her permit epoch.
    const receipt = await S.sendOk(allowance.write.invalidateAllPermits(txOpts(alice.account)));
    const [event] = parseEventLogs({
      abi: allowance.abi,
      logs: receipt.logs,
      eventName: "PermitEpochIncremented"
    });
    expect(event.args.newEpoch).toBe(1n);
    expect(await allowance.read.permitEpoch([alice.account.address])).toBe(1n);

    // Both epoch-0 signatures now fail verification, since the digest binds the current epoch.
    await assertRevertsWith(
      allowance.write.permitSetPermission([
        alice.account.address,
        grant.grant,
        grant.inputProof,
        grant.signature
      ], txOpts(bob.account)),
      "InvalidSigner",
    );
    const requested = await S.encAmount(allowance.address, bob.account.address, 100n);
    await assertRevertsWith(
      allowance.write.permitTransferFrom([
        alice.account.address,
        cheque.permit,
        cheque.capProof,
        requested.handle,
        requested.inputProof,
        carol.account.address,
        cheque.signature
      ], txOpts(bob.account)),
      "InvalidSigner",
    );

    // A freshly signed permit at the new epoch works again.
    const fresh = await makeGrant({
      owner: "alice",
      spender: bob.account.address,
      limit: 500n,
      nonce: 3n
    });
    await S.sendOk(allowance.write.permitSetPermission([
      alice.account.address,
      fresh.grant,
      fresh.inputProof,
      fresh.signature
    ], fheTxOpts(bob.account)));
    expect(await S.getPermissionCount(alice.account.address, bob.account.address)).toBe(1n);
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
    const requested = await S.encAmount(allowance.address, bob.account.address, 300n);
    const receipt = await S.sendOk(allowance.write.permitTransferFrom([
      alice.account.address,
      cheque.permit,
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

    // The nonce is one-shot. A replay fails even though the cap wasn't exhausted.
    const requested2 = await S.encAmount(allowance.address, bob.account.address, 100n);
    await assertRevertsWith(
      allowance.write.permitTransferFrom([
        alice.account.address,
        cheque.permit,
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
      cheque.permit,
      cheque.capProof,
      requested.handle,
      requested.inputProof,
      carol.account.address,
      cheque.signature
    ], fheTxOpts(bob.account)));

    expect(await S.balanceOf(carol)).toBe(0n);
    expect(await S.balanceOf(alice)).toBe(10_000n);
    // Documented cheque semantics, consumed on submission regardless of outcome.
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
        cheque.permit,
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
      cheque.permit,
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
    const { grant, inputProof, signature } = await makeGrant({
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
          ...grant,
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
          ...grant,
          duration: DAY * 30n
        },
        inputProof,
        signature
      ], txOpts(bob.account)),
      "InvalidSigner",
    );
  });
});
