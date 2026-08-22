// SPDX-License-Identifier: MIT
pragma solidity ^0.8.27;

import {FHE, euint64, eaddress, externalEaddress} from "@fhevm/solidity/lib/FHE.sol";
import {ZamaEthereumConfig} from "@fhevm/solidity/config/ZamaConfig.sol";
import {IERC20} from "@openzeppelin/contracts/interfaces/IERC20.sol";
import {SafeERC20} from "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import {ReentrancyGuard} from "@openzeppelin/contracts/utils/ReentrancyGuard.sol";
import {IERC7984ERC20Wrapper} from "@openzeppelin/confidential-contracts/interfaces/IERC7984ERC20Wrapper.sol";
import {IStealthWrapAdapter} from "../../interfaces/IStealthWrapAdapter.sol";
import {FHEUtils} from "../../fhe/FHEUtils.sol";

/**
 * @title StealthWrapAdapter
 * @author Valerio Leo (@valeriohq)
 * @author Pavlos Polianidis (@ppoliani)
 * @notice Abstract base for stealth wrap adapters over an existing ERC7984ERC20Wrapper.
 *
 *         This contract does not implement an ERC7984 token. It escrows confidential
 *         balances of `CONFIDENTIAL_WRAPPER`: initWrap pulls clear ERC20 from the
 *         depositor, wraps it into confidential balance owned by this contract, and
 *         records an encrypted recipient. finalizeWrap variants homomorphically select
 *         matching deposits and transfer the resulting confidential balance to the
 *         cleartext recipient.
 *
 *         DEPOSITOR TRUST — THE RECIPIENT IS HIDDEN FROM THE CHAIN AND FROM THE DEPOSITOR.
 *         The obvious way to import the recipient, `FHE.fromExternal`, would only hide it from the
 *         chain. It expands to `Impl.verify`, which after the coprocessor proof check runs
 *         `IACL.allowTransient(result, msg.sender)` — and inside {initWrap} that `msg.sender` is the
 *         depositor. An EOA depositor gains nothing from that transient grant (it dies with the
 *         transaction), but a CONTRACT depositor could, still inside the same transaction, promote
 *         it with `FHE.allow` or publish it with `FHE.makePubliclyDecryptable` and read the recipient
 *         address the handshake conceals.
 *
 *         So {_verifyRecipient} imports the ciphertext through {FHEUtils-fromExternal}, which calls
 *         the coprocessor's `verifyInput` and stops there. The proof check and the binding are the
 *         same (`contractAddress` is this adapter, `userAddress` is the depositor), and the only ACL
 *         grant made is the executor's own, to this adapter. The adapter persists that access with
 *         `FHE.allowThis`; the depositor is named inside the proof and receives nothing to escalate.
 *         The proof stays bound to the depositor, so no third party can submit it (the property
 *         {_consumeRecipientHandle} depends on), and the recipient is concealed from a contract
 *         depositor as well as from observers.
 *
 *         That is the narrower guarantee that submitting a well-formed deposit does not leak the
 *         recipient to whoever submitted it, contract or not. Whether the depositor can TRUST the
 *         recipient is a separate question; see the next note.
 *
 *         THE DEPOSITOR CANNOT VERIFY THE ENCRYPTED RECIPIENT. Importing the handle proves the
 *         ciphertext is well-formed and correctly bound; it says nothing about the ADDRESS inside.
 *         The depositor pays before knowing what they paid for, so the handshake requires trusting
 *         whoever produced the handle. A recipient who supplies an encryption of someone else's
 *         address redirects the payment; one who supplies an encryption of the zero address destroys
 *         it outright, because {finalizeWrap} rejects `address(0)` in cleartext, so no permitted
 *         recipient can ever match that deposit and the funds stay in escrow forever.
 *
 *         Client-side validation does not close this: the party doing the encrypting is exactly the
 *         party being trusted, and the depositor cannot decrypt the handle to check. Treat a
 *         payment request as an authenticated message from the payee and verify it out of band.
 *
 *         EXACT EXITS FORFEIT UNLINKABILITY. Deposit amounts are public and rounded to the
 *         wrapper's `rate()`, and the finalize event names the scanned set. The payout itself stays
 *         encrypted here — but the recipient holds it, and unwrapping it publicly reveals its clear
 *         value. Anyone can then search the scanned amounts for a subset summing to it; when only
 *         one subset matches, that subset is the recipient's deposits. This happens after delivery,
 *         under the recipient's own key, so no on-chain control can prevent it — recipients must
 *         avoid exiting the exact amount they were paid.
 *
 *         SUPPORTED WRAPPERS — SOFT-FAIL EXPOSURE DIFFERS BY PATH. ERC-7984 does not require `wrap`
 *         and `confidentialTransfer` to move exactly what was asked: an operation may SOFT-FAIL,
 *         returning an encrypted zero (or less than requested) while the transaction succeeds
 *         (OpenZeppelin's own transfer is exact-or-zero via `FHESafeMath`, not exact-or-revert). How
 *         much that matters depends on the path:
 *
 *         - deposit (BOTH adapters — still needs exact-or-revert). {_wrapIntoEscrow} pulls the
 *           depositor's underlying, then wraps. OpenZeppelin's wrapper moves the underlying BEFORE
 *           `_mint`, so on an `ERC7984Hooked` wrapper a rejecting mint hook can substitute an
 *           encrypted zero instead of reverting. The adapter records a zero-valued deposit while the
 *           wrapper has kept the underlying, and there is no refund path — the shortfall is a
 *           cleartext underlying amount that cannot be un-pulled on an encrypted result.
 *         - finalize (differs). The batched adapter is RETRY-SAFE: it pays `matched - claimed` and
 *           credits back only what actually moved, so a soft-failed or partial transfer leaves the
 *           remainder claimable (see {BatchedStealthWrapAdapter-finalizeWrap}). The continuous
 *           adapter is NOT: it consumes deposits by zeroing them before the transfer, and a flat pool
 *           cannot attribute a partial back to individual deposits, so a soft-fail there destroys the
 *           claim. It keeps the exact-or-revert (at least all-or-nothing) finalize requirement; see
 *           its docs.
 *
 *         So the deployment constraint is: any wrapper this points at must be exact-or-revert on
 *         `wrap`, and additionally on `confidentialTransfer` unless the adapter's finalize path is
 *         retry-safe. A bare OZ `ERC7984ERC20Wrapper` over a sufficient escrow balance qualifies (it
 *         only soft-fails to zero on an insufficient balance, which finalize never hits); a hooked
 *         one is only as safe as the modules its admin can install.
 *
 *         REENTRANCY: both helpers make external calls, but on OPPOSITE sides of the state they
 *         guard, so implementations must reason about them separately. Either way the public
 *         {initWrap} and {finalizeWrap} MUST be `nonReentrant`, as the bundled adapters are.
 *
 *         - {_wrapIntoEscrow} calls out (safeTransferFrom / wrap) BEFORE the caller records its
 *           deposit entry, so a re-entrant call would see escrow that no deposit yet accounts for.
 *         - {_transferWrapped} is the other way round: the external `confidentialTransfer` sits next
 *           to the claim commit, and the ordering differs by adapter. The continuous adapter zeroes
 *           matched amounts BEFORE the transfer (optimistic: a revert unwinds it atomically). The
 *           batched adapter credits its encrypted `claimed` ledger AFTER the transfer, because the
 *           credit is the returned amount — so it relies purely on `nonReentrant` to stop a
 *           re-entrant finalize from reading the stale ledger and double-paying. Either ordering is
 *           safe ONLY under the guard. A derived finalizer that drops `nonReentrant` exposes a
 *           double-claim on either ordering.
 */
abstract contract StealthWrapAdapter is IStealthWrapAdapter, ZamaEthereumConfig, ReentrancyGuard {
    using SafeERC20 for IERC20;

    IERC7984ERC20Wrapper public immutable CONFIDENTIAL_WRAPPER;
    euint64 public immutable E_ZERO;

    /// @dev Encrypted-recipient handles already spent on a deposit — see {_verifyRecipient}.
    mapping(bytes32 handle => bool) private _usedRecipientHandles;

    constructor(IERC7984ERC20Wrapper confidentialWrapper_) {
        if (address(confidentialWrapper_) == address(0)) revert ZeroAddress();

        address underlying_ = confidentialWrapper_.underlying();
        if (underlying_ == address(0)) revert ZeroAddress();

        // rate() is the wrap divisor used in _wrapIntoEscrow (`amount % rate`); a zero rate
        // would panic on every deposit. A valid OZ ERC7984ERC20Wrapper never returns 0.
        if (confidentialWrapper_.rate() == 0) revert InvalidRate();

        CONFIDENTIAL_WRAPPER = confidentialWrapper_;

        E_ZERO = FHE.asEuint64(0);
        FHE.allowThis(E_ZERO);
    }

    function confidentialWrapper() external view returns (address) {
        return address(CONFIDENTIAL_WRAPPER);
    }

    /**
     * @dev Import a depositor-submitted encrypted recipient. Implementations MUST route every
     *      `externalEaddress` through here rather than importing it themselves.
     *
     *      Two things happen, in order:
     *
     *        1. An EMPTY `inputProof` is rejected up front. Every legitimate deposit carries a real
     *           proof (the recipient encrypts their address bound to `(this, depositor)`), so this
     *           rejects nothing valid, and it gives the adapter's own `MissingInputProof` revert
     *           before any external call.
     *        2. The ciphertext is imported through {_importRecipient}, i.e. {FHEUtils-fromExternal}.
     *           That grants ACL access to this adapter only (the DEPOSITOR TRUST note has the why)
     *           and passes the expected `Uint160` type to the coprocessor, which reverts `InvalidType`
     *           for anything else.
     *
     *      That mandatory `Uint160` check is what keeps a hostile handle out of the pipeline. Three
     *      attacks follow from a wrong-typed handle reaching the `eaddress` slot, and the typed import
     *      closes all of them at the coprocessor:
     *
     *        - a `Bool` handle. Scalar `FHE.eq(eaddress, address)` skips the operand type check, and
     *          an encrypted `true` then compares equal to EVERY non-zero recipient — one poisoned
     *          slot pays out once per attacker-chosen address, draining the pooled escrow.
     *        - a `euint64` handle carrying the previous slot's own future payout. Handles are
     *          content-addressed with no `msg.sender` in the preimage, so an attacker can weld each
     *          slot's comparison onto the one before it. finalize then recomputes that chain
     *          serially and trips the FHEVM 5M per-tx DEPTH budget (a counter distinct from the 20M
     *          total), freezing a chosen recipient's escrow for good.
     *        - any other wrong type. The continuous adapter's non-scalar `FHE.eq` type-checks both
     *          operands and reverts `IncompatibleTypes` for every id set naming the slot, which
     *          bricks those deposits permanently.
     *
     *      Handle freshness is delegated to {_consumeRecipientHandle}, which is where the single-use
     *      policy and the grounds for overriding it are documented. Note the split: neither the
     *      empty-proof gate nor the direct-`verifyInput` import is part of that hook, and neither is
     *      overridable — a derived adapter can relax freshness without being handed a way to relax the
     *      type check or to reintroduce the depositor-ACL leak.
     *
     *      THE CALLER MUST PERSIST ACCESS TO THE RETURNED HANDLE. What the import grants is the
     *      adapter's TRANSIENT access, which expires with the transaction, so an adapter that stores
     *      the handle without `FHE.allowThis` leaves a deposit finalize can never match again. This
     *      is not done here because a handle that is imported and discarded needs no grant: the grant
     *      belongs where the handle is stored. {BatchedStealthWrapAdapter-_recordBatchedDeposit} is
     *      the worked example — it persists both ciphertexts it records.
     */
    function _verifyRecipient(externalEaddress eRecipient, bytes calldata inputProof) internal returns (eaddress) {
        if (inputProof.length == 0) revert MissingInputProof();

        eaddress verifiedRecipient = _importRecipient(eRecipient, inputProof);
        _consumeRecipientHandle(FHE.toBytes32(verifiedRecipient));

        return verifiedRecipient;
    }

    /**
     * @dev Verify `eRecipient` against `inputProof` and return the `eaddress`, granting ACL access to
     *      THIS adapter and to no one else. That containment is the whole of the recipient-privacy
     *      fix, so this is `private`: it must not be bypassable or overridable.
     *
     *      The mechanism, and why `FHE.fromExternal` cannot be used here, are documented on
     *      {FHEUtils}. In short: `fromExternal` adds a second ACL grant naming the DEPOSITOR, which a
     *      contract depositor can promote to permanent access before the transaction ends. The
     *      proof binding is unchanged either way — it still names the depositor, which is what stops
     *      a third party submitting the handle — so only the leak goes away.
     *
     *      The caller then persists the adapter's access with `FHE.allowThis`.
     */
    function _importRecipient(externalEaddress eRecipient, bytes calldata inputProof) private returns (eaddress) {
        return FHEUtils.fromExternal(eRecipient, inputProof, msg.sender);
    }

    /**
     * @dev Freshness policy for an imported recipient handle, applied to every deposit that routes
     *      through {_verifyRecipient}.
     *
     *      DEFAULT: SINGLE-USE. The handle is emitted in the deposit event so the recipient can spot
     *      their own payment, which makes it a public tag: submit the same one twice and observers
     *      can cluster those deposits as "same unknown recipient" without breaking any encryption.
     *      Once one member of the cluster is tied to a clear address — by a finalize, by timing, by
     *      off-chain context — the rest follow. Batch boundaries and decoy choice do not remove a tag
     *      that travels with the deposit itself. Enforcing freshness here rather than leaving it to
     *      wallets costs one storage slot per deposit and cannot be forgotten. For the bundled
     *      adapters it rejects nothing legitimate — every payment request is supposed to carry its
     *      own encryption, and a fresh encryption of the SAME address yields a different handle, so a
     *      recipient can still be paid any number of times — and it cannot be griefed, because the
     *      input proof binds a handle to its depositor, so no one else can spend it.
     *
     *      WHEN TO OVERRIDE: when the deposit path ALREADY publishes the grouping this protects. The
     *      motivating case is a CREATE2 deposit-address flow that derives the address from the handle
     *      (`salt == handle`), because that derivation is the only thing binding the address to a
     *      recipient the payer cannot inspect — decouple them and whoever drives the recovery path
     *      picks the recipient after the money has arrived. Deposits there are already clustered by
     *      the payer's clear ERC-20 transfer TO that public address, which lands before `initWrap`
     *      runs, so single-use buys nothing while its failure mode is severe: the address cannot
     *      rotate its handle, so a second (often accidental) transfer to a live deposit address
     *      cannot be wrapped at all, leaving only a cleartext sweep — which doxxes the FIRST deposit.
     *
     *      The apparent middle ground does not exist. Re-wrapping under a fresh handle cannot be
     *      authenticated: the deposit address cannot identify its own recipient, so its recovery
     *      entrypoint must be permissionless, and a bystander can route a handle encrypting THEIR
     *      address through it. Proving the replacement matches means either publicly decrypting
     *      `FHE.eq(old, new)` — which reveals exactly the linkage single-use was protecting — or
     *      `FHE.select`-ing to an unclaimable recipient on mismatch, which lets any bystander burn
     *      the funds for the price of gas. Ranked by damage, reuse (linked, funds recoverable) beats
     *      both. So permitting reuse there is the correct policy, not a concession.
     *
     *      Overrides should call {_recordRecipientHandle} so {recipientHandleUsed} stays truthful. No
     *      extra event is needed: each adapter already emits the handle in its deposit event, so a
     *      repeat is visible to any indexer. And state it in the adapter's own docs — deposits made
     *      through it are publicly linkable by recipient, so it must not be presented as offering the
     *      unlinkability the bundled adapters do.
     */
    function _consumeRecipientHandle(bytes32 handle) internal virtual {
        if (_usedRecipientHandles[handle]) revert RecipientHandleAlreadyUsed();
        _recordRecipientHandle(handle);
    }

    /// @dev Mark a handle as spent WITHOUT rejecting a repeat. Exists so an override of
    ///      {_consumeRecipientHandle} that permits reuse can still keep {recipientHandleUsed}
    ///      answering truthfully; the mapping itself stays private.
    function _recordRecipientHandle(bytes32 handle) internal {
        _usedRecipientHandles[handle] = true;
    }

    /// @notice Whether an encrypted-recipient handle has already funded a deposit here.
    /// @dev Records history, not policy: an adapter that overrides {_consumeRecipientHandle} to
    ///      permit reuse still reports `true` here for a handle it will happily accept again.
    function recipientHandleUsed(bytes32 handle) external view returns (bool) {
        return _usedRecipientHandles[handle];
    }

    function underlying() public view returns (address) {
        return CONFIDENTIAL_WRAPPER.underlying();
    }

    function rate() public view returns (uint256) {
        return CONFIDENTIAL_WRAPPER.rate();
    }

    /**
     * @dev External calls (safeTransferFrom / wrap) run before the caller records its deposit,
     *      so callers MUST be `nonReentrant` (see the contract-level REENTRANCY note).
     *
     *      NOTE FOR WRAPPERS WITH TRANSFER RESTRICTIONS: the adapter, not the depositor, is the
     *      wrapper's counterparty. It pulls the underlying itself and then calls
     *      `wrap(address(this), amount)`, so a wrapper that gates on `msg.sender` or the wrap
     *      recipient — a deny-list, an allow-list, a compliance module — sees only this adapter and
     *      passes. A depositor whom the wrapper would have blocked on a direct `wrap` can therefore
     *      still originate one through here, as long as the plain ERC-20 transfer succeeds. That is
     *      inherent to interposing a contract, not something the adapter can detect; a wrapper
     *      operator who wants those checks enforced must apply them to the adapter's own deposit
     *      path or decline to have an adapter pointed at it.
     */
    function _wrapIntoEscrow(address depositor, uint256 amount) internal returns (uint256 wrappedUnderlying, euint64 wrappedAmount) {
        if (amount == 0) revert ZeroAmount();

        uint256 rate_ = CONFIDENTIAL_WRAPPER.rate();
        wrappedUnderlying = amount - (amount % rate_);
        if (wrappedUnderlying == 0) revert ZeroAmount();

        IERC20 token = IERC20(CONFIDENTIAL_WRAPPER.underlying());
        token.safeTransferFrom(depositor, address(this), wrappedUnderlying);
        token.forceApprove(address(CONFIDENTIAL_WRAPPER), wrappedUnderlying);

        wrappedAmount = CONFIDENTIAL_WRAPPER.wrap(address(this), wrappedUnderlying);
        FHE.allowThis(wrappedAmount);
    }

    /// @dev Makes an external `confidentialTransfer`, so callers MUST be `nonReentrant`. Where the
    ///      claim state is committed relative to this call differs by adapter — the continuous one
    ///      zeroes matched amounts BEFORE it, the batched one credits its encrypted `claimed` ledger
    ///      AFTER it because the credit is this function's return value. Neither is safe without the
    ///      guard; see the contract-level REENTRANCY note.
    function _transferWrapped(address recipient, euint64 amount) internal returns (euint64 transferred) {
        FHE.allowThis(amount);
        FHE.allow(amount, address(CONFIDENTIAL_WRAPPER));
        transferred = CONFIDENTIAL_WRAPPER.confidentialTransfer(recipient, amount);
        FHE.allowThis(transferred);
    }

    /// @dev Tree-reduce `xs` to a single encrypted sum — see {FHEUtils-sum} for why the shape
    ///      matters. `virtual` so a derived adapter can substitute its own reduction; overrides must
    ///      keep the FHE dependency depth sub-linear or finalize will hit the per-transaction depth
    ///      budget as the scan grows.
    function _sumTree(euint64[] memory xs) internal virtual returns (euint64) {
        return FHEUtils.sum(xs);
    }

    function finalizeWrap(uint256[] calldata ids, address recipient) external virtual;
}
