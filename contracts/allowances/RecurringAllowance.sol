// SPDX-License-Identifier: MIT
pragma solidity ^0.8.27;

import {FHE, euint64, ebool, externalEuint64} from "@fhevm/solidity/lib/FHE.sol";
import {ZamaEthereumConfig} from "@fhevm/solidity/config/ZamaConfig.sol";
import {ReentrancyGuard} from "@openzeppelin/contracts/utils/ReentrancyGuard.sol";
import {EIP712} from "@openzeppelin/contracts/utils/cryptography/EIP712.sol";
import {SignatureChecker} from "@openzeppelin/contracts/utils/cryptography/SignatureChecker.sol";
import {IERC7984} from "@openzeppelin/confidential-contracts/interfaces/IERC7984.sol";
import {IRecurringAllowance} from "../interfaces/IRecurringAllowance.sol";
import {FHESafe} from "../fhe/FHESafe.sol";
import {UnorderedNonces} from "./base/UnorderedNonces.sol";

/**
 * @title RecurringAllowance
 * @author Michalis Ghiumiusliu (@MichalisG)
 * @author Pavlos Polianidis (@ppoliani)
 * @author Valerio Leo (@valeriohq)
 * @notice Encrypted, period-based spending permissions for ERC-7984 confidential
 *         tokens: "let this spender pull up to X per day", with X encrypted.
 *
 *         ERC-7984's native delegation is `setOperator`, which is all-or-nothing: an
 *         operator can move ANY amount. This contract turns that into scoped delegation.
 *         The user makes RecurringAllowance an operator once, then grants per-spender
 *         permissions here; a spender can only move funds through {transferFrom}, which
 *         enforces the encrypted budgets. Note the limits bind only this contract —
 *         any OTHER operator the user approves on the token bypasses them entirely.
 *
 *         CONJUNCTIVE SEMANTICS: all active permissions for a (user, token, spender)
 *         key must allow a spend (AND logic), so "100/day AND 500/week" works out of
 *         the box. The flip side: adding a permission only ever TIGHTENS the allowance
 *         (a zero-limit permission blocks the key entirely). To raise a limit, update
 *         the existing permission instead of adding one.
 *
 *         OBLIVIOUS SPENDING: a denied spend does not revert — it transfers an
 *         encrypted zero. Storage writes, FHE ops and events are identical either way,
 *         so an on-chain observer cannot distinguish a denied attempt from a permitted
 *         one; only holders of the relevant decryption rights can. `spent` is
 *         credited with the amount the token reports as ACTUALLY moved, so a spend
 *         that fails on the user's balance does not consume allowance.
 *
 *         PERIOD GRID: periods are fixed windows anchored at `startTime` (period n is
 *         `[startTime + n*duration, startTime + (n+1)*duration)`), not a sliding
 *         window. `spent` resets lazily on the first spend attempt in a new period.
 *         Worst case a spender can move 2x the limit in a `duration`-long span that
 *         straddles a boundary (end of one period + start of the next) — inherent to
 *         fixed-window budgets; size limits accordingly.
 *
 *         DECRYPTION RIGHTS (who can see what): `limit` and `spent` are decryptable by
 *         the user AND the spender — the spender must be able to see their own budget,
 *         and an active spender could infer it anyway by probing. Third parties see
 *         only the cleartext shape: that a permission exists, its period, its window,
 *         and when spends were attempted. Amounts stay encrypted end to end.
 *
 *         SIGNATURE PERMITS (the Permit2 analog): because amounts are encrypted, a permit
 *         signs the CIPHERTEXT HANDLE — the owner encrypts the amount off-chain with the
 *         input proof bound to `(this, spender)` and signs EIP-712 over the struct
 *         including that handle, so only the named spender can submit it and no other
 *         ciphertext can be substituted. {permitSetPermission} creates a permission
 *         gaslessly for the owner (the spender submits and pays); {permitTransferFrom}
 *         executes a one-shot transfer up to a signed encrypted cap, optionally bound to
 *         a recipient (a "confidential cheque"). Nonces are Permit2-style unordered
 *         bitmaps; signatures verify via ECDSA or ERC-1271. NOTE a cheque that submits
 *         SUCCESSFULLY burns its nonce regardless of the encrypted outcome (the outcome is
 *         unknowable in cleartext), but a token that reverts rolls the nonce back and leaves the
 *         cheque live — see {permitTransferFrom}. How long an input proof remains submittable
 *         after signing is an operational property of the FHEVM gateway — size `sigDeadline`
 *         accordingly.
 *
 *         REENTRANCY: {transferFrom}, {tryTransferFrom} and {permitTransferFrom} call the
 *         caller-supplied `token` address, so all are `nonReentrant`. All other state is
 *         keyed by `msg.sender`, which inside such a call is the token itself — it can
 *         only touch its own keys.
 */
contract RecurringAllowance is IRecurringAllowance, ZamaEthereumConfig, ReentrancyGuard, EIP712, UnorderedNonces {
    // `owner` is signed (not just a call argument) so an ERC-1271 wallet sharing a signer
    // with another account cannot have its signature replayed against that sibling — the
    // digest is account-specific. `epoch` lets an owner invalidate every outstanding
    // signature at once (see {invalidateAllPermits}); the contract mixes in the CURRENT
    // on-chain epoch, so a bump makes prior signatures fail verification.
    bytes32 public constant PERMIT_GRANT_TYPEHASH = keccak256(
        "PermitGrant(address owner,address token,address spender,bytes32 limitHandle,uint64 duration,uint64 startTime,uint64 endTime,uint256 nonce,uint256 epoch,uint256 sigDeadline)"
    );
    bytes32 public constant PERMIT_SPEND_TYPEHASH = keccak256(
        "PermitSpend(address owner,address token,address spender,bytes32 capHandle,address to,uint256 nonce,uint256 epoch,uint256 sigDeadline)"
    );
    /// @notice Hard cap on live permissions per (user, token, spender) key.
    /// @dev Every active permission adds ~6 FHE ops to each {transferFrom} for the key,
    ///      and the FHEVM HCU-per-tx budget bounds how many fit: the batched stealth
    ///      adapter measured ~170 ops/tx before reverting, so 8 permissions (~50 ops)
    ///      leaves wide headroom. Realistic use is 2-4 tiers (daily/weekly/monthly);
    ///      without a cap a user could grow the array until every spend for the key
    ///      exceeds the budget, bricking the allowance until {lockdown}.
    uint256 public constant MAX_PERMISSIONS = 8;

    /// @dev Shared encrypted zero (trivial encryption of 0 — publicly known, so sharing
    ///      one handle across users leaks nothing). Fresh `spent` values point here.
    euint64 private immutable E_ZERO;

    mapping(address user => mapping(address token => mapping(address spender => Permission[]))) private _permissions;

    /// @dev Enumeration of a user's granted (token, spender) pairs, maintained under the
    ///      invariant "pair listed <=> its permissions array is non-empty" so wallets can
    ///      render (and revoke) every grant without an indexer.
    mapping(address user => TokenSpenderPair[]) private _grantedPairs;
    /// @dev pairKey (keccak(token, spender)) => index in {_grantedPairs} PLUS ONE (0 = absent).
    mapping(address user => mapping(bytes32 pairKey => uint256 indexPlusOne)) private _grantedPairIndex;

    /// @dev Ids start at 1 so 0 never names a permission.
    uint256 private _nextPermissionId = 1;

    /// @notice Per-owner permit epoch, mixed into every permit digest. Bumping it (via
    ///         {invalidateAllPermits}) invalidates all of the owner's outstanding
    ///         signatures at once. Starts at 0.
    mapping(address owner => uint256) public permitEpoch;

    constructor() EIP712("RecurringAllowance", "1") {
        E_ZERO = FHE.asEuint64(0);
        FHE.allowThis(E_ZERO);
    }

    /**
     * @notice Grant `spender` a recurring, encrypted spending budget on `token`.
     * @dev The user must (separately) make this contract an operator on `token` via
     *      `setOperator` — and keep that operator window at least as long as the
     *      permission's, or spends revert at the token.
     * @param token The ERC-7984 token the permission applies to
     * @param spender The account allowed to call {transferFrom} against this budget
     * @param limit Encrypted per-period limit (input proof bound to `(this, msg.sender)`)
     * @param inputProof Proof for `limit`
     * @param duration Period length in seconds; 0 means `type(uint64).max` (never resets)
     * @param startTime Grid anchor and activation time; 0 means `block.timestamp`.
     *        May be in the past (elapsed periods simply count from there).
     * @param endTime Inclusive expiry; 0 means `type(uint64).max` (no expiry).
     *        Must not be in the past, and must be after `startTime`. Expiry is INCLUSIVE, so
     *        `endTime == block.timestamp` is accepted and leaves the permission active for the
     *        rest of the current second.
     * @return permissionId Stable id of the new permission
     */
    function setPermission(
        address token,
        address spender,
        externalEuint64 limit,
        bytes calldata inputProof,
        uint64 duration,
        uint64 startTime,
        uint64 endTime
    ) external returns (uint256 permissionId) {
        // Cleartext validation BEFORE fromExternal so an invalid window / 9th permission
        // reverts without paying for encrypted-input proof verification.
        bool firstPermission;
        (duration, startTime, endTime, firstPermission) =
            _validateNewPermission(msg.sender, token, spender, duration, startTime, endTime);
        euint64 eLimit = _verifyLimit(limit, inputProof);
        permissionId = _finalizeCreate(msg.sender, token, spender, eLimit, duration, startTime, endTime, firstPermission);
    }

    /**
     * @notice Create a permission from an owner's signed {PermitGrant} — the gasless
     *         grant flow. The owner signs off-chain; the named spender submits (and
     *         pays gas). The resulting permission is indistinguishable from one the
     *         owner created via {setPermission}.
     * @dev The grant's `limitHandle` must come with an input proof the owner created
     *      bound to `(this, grant.spender)` — which is also why only the named spender
     *      can submit: for anyone else the coprocessor rejects the proof. The
     *      explicit {SpenderMismatch} check just fails faster and cleaner.
     *      Zero-valued time fields resolve AT SUBMISSION (startTime 0 = "when the
     *      spender activates it"), bounded by `sigDeadline`.
     * @param owner The user granting the permission (the signer)
     * @param grant The signed grant parameters
     * @param inputProof Proof for `grant.limitHandle`
     * @param signature EIP-712 signature by `owner` (ECDSA or ERC-1271)
     * @return permissionId Stable id of the new permission
     */
    function permitSetPermission(
        address owner,
        PermitGrant calldata grant,
        bytes calldata inputProof,
        bytes calldata signature
    ) external returns (uint256 permissionId) {
        if (msg.sender != grant.spender) revert SpenderMismatch();
        if (block.timestamp > grant.sigDeadline) revert SignatureExpired(grant.sigDeadline);
        _useUnorderedNonce(owner, grant.nonce);
        _verifyPermitGrant(owner, grant, signature);

        bool firstPermission;
        uint64 duration;
        uint64 startTime;
        uint64 endTime;
        (duration, startTime, endTime, firstPermission) =
            _validateNewPermission(owner, grant.token, grant.spender, grant.duration, grant.startTime, grant.endTime);
        euint64 eLimit = _verifyLimit(externalEuint64.wrap(grant.limitHandle), inputProof);
        permissionId = _finalizeCreate(owner, grant.token, grant.spender, eLimit, duration, startTime, endTime, firstPermission);
    }

    /**
     * @dev Import a permission's encrypted limit. Both creation paths route through here.
     *
     *      {FHESafe-fromExternal} passes the expected `Uint64` to the coprocessor, so a handle of any
     *      other type reverts `InvalidType` before it can become `Permission.limit`. That matters
     *      because a non-`Uint64` limit makes every later `FHE.le` against it revert inside
     *      `_evaluatePermissions`, which runs BEFORE the try/catch in {_trySpend}: one poisoned payer
     *      would abort an entire {tryTransferFrom} batch rather than being skipped.
     *
     *      The empty-proof rejection is kept as an explicit first line — creation always supplies a
     *      limit, and failing here is cheaper and names this contract's own error. Only
     *      {updatePermission} reads an empty proof as a sentinel ("leave the limit unchanged"),
     *      behind its own `length > 0` gate.
     */
    function _verifyLimit(externalEuint64 limit, bytes calldata inputProof) private returns (euint64) {
        if (inputProof.length == 0) revert MissingInputProof();
        return FHESafe.fromExternal(limit, inputProof, msg.sender);
    }

    /// @dev Cleartext half of permission creation, shared by {setPermission} and
    ///      {permitSetPermission}. Resolves the zero-sentinels, validates the window and
    ///      the per-key cap, prunes expired entries, and reports whether this will be the
    ///      first live permission under the key. Runs BEFORE any ciphertext import so a
    ///      cleartext revert never pays for proof verification.
    function _validateNewPermission(
        address user,
        address token,
        address spender,
        uint64 duration,
        uint64 startTime,
        uint64 endTime
    ) private returns (uint64, uint64, uint64, bool firstPermission) {
        if (token == address(0)) revert InvalidTokenAddress();
        if (spender == address(0)) revert InvalidSpenderAddress();

        if (duration == 0) duration = type(uint64).max;
        if (startTime == 0) startTime = uint64(block.timestamp);
        if (endTime == 0) endTime = type(uint64).max;
        _checkWindow(startTime, endTime);

        Permission[] storage permissions = _permissions[user][token][spender];
        _pruneExpired(permissions);
        if (permissions.length >= MAX_PERMISSIONS) revert TooManyPermissions();
        firstPermission = permissions.length == 0;

        return (duration, startTime, endTime, firstPermission);
    }

    /// @dev Encrypted half of permission creation: grant ACL, append, emit. The E_ZERO
    ///      grants and the pair-tracking are only needed once per key — E_ZERO is a single
    ///      shared handle and ACL grants are permanent, so re-granting on a 2nd/3rd tier is
    ///      pure redundant external work.
    function _finalizeCreate(
        address user,
        address token,
        address spender,
        euint64 eLimit,
        uint64 duration,
        uint64 startTime,
        uint64 endTime,
        bool firstPermission
    ) private returns (uint256 permissionId) {
        FHE.allowThis(eLimit);
        FHE.allow(eLimit, user);
        FHE.allow(eLimit, spender);
        if (firstPermission) {
            // Let both parties decrypt the initial (and any reset) spent value.
            FHE.allow(E_ZERO, user);
            FHE.allow(E_ZERO, spender);
            _trackPair(user, token, spender);
        }

        permissionId = _nextPermissionId++;
        _permissions[user][token][spender].push(
            Permission({
                id: permissionId,
                limit: eLimit,
                spent: E_ZERO,
                lastUpdated: startTime,
                startTime: startTime,
                endTime: endTime,
                duration: duration
            })
        );

        emit PermissionSet(user, token, spender, permissionId, eLimit, duration, startTime, endTime);
    }

    /**
     * @notice Modify an existing permission. Zero-valued parameters mean "leave unchanged"
     *         (to actually set a field to its "unlimited" value, pass `type(uint64).max`;
     *         to skip the limit, pass an empty `inputProof`).
     * @dev Changing `duration` or `startTime` to a DIFFERENT value re-anchors the period
     *      grid, so `spent` resets — otherwise the old grid's spend history would be
     *      measured against the new grid (and a future `startTime` would make the reset
     *      math underflow). Re-submitting the SAME value is a no-op and does NOT reset,
     *      so a wallet echoing back a full record can't silently refresh the budget.
     *
     *      TREAT A GRID CHANGE AS ISSUING A FRESH BUDGET, NOT AS AN EDIT. Because it zeroes
     *      `spent`, a live spender who sees the pending update can frontrun it to drain whatever
     *      room is left on the old grid, let the update reset the counter, then backrun and spend
     *      up to the limit again — about 2x one period's limit around a single transaction. This is
     *      distinct from, and stacks with, the ~2x the contract-level PERIOD GRID note already
     *      describes for a natural rollover.
     *
     *      To TIGHTEN a live permission safely, prefer {invalidatePermission} (or {lockdown}) and
     *      re-grant, or lower only the `limit` — a limit-only update keeps the current period's
     *      `spent`, so it blocks further spending immediately rather than releasing a fresh window.
     *      When a grid change is genuinely needed against a hot spender, submit it through a private
     *      relay.
     *      Changing only `limit` keeps the current period's `spent`: lowering the limit
     *      below what is already spent simply blocks further spending until the next reset.
     *      The permission is addressed by its stable `permissionId` (see {_findPermission}).
     */
    function updatePermission(
        address token,
        address spender,
        uint256 permissionId,
        externalEuint64 limit,
        bytes calldata inputProof,
        uint64 duration,
        uint64 startTime,
        uint64 endTime
    ) external {
        Permission[] storage permissions = _permissions[msg.sender][token][spender];
        Permission storage permission = permissions[_findPermission(permissions, permissionId)];

        // Cleartext first: every reason to reject this call is knowable without touching a
        // ciphertext, while importing one pays for coprocessor proof verification and three
        // ACL grants that a revert would only roll back. {_validateNewPermission} already
        // establishes this order on the creation path.
        bool gridChanged = _applyWindowUpdate(permission, duration, startTime, endTime);

        if (inputProof.length > 0) {
            euint64 eLimit = FHESafe.fromExternal(limit, inputProof, msg.sender);
            permission.limit = eLimit;
            FHE.allowThis(eLimit);
            FHE.allow(eLimit, msg.sender);
            FHE.allow(eLimit, spender);
        }

        if (gridChanged) {
            permission.spent = E_ZERO;
            // Anchor accounting so `spent` is fresh for the CURRENT grid period and does
            // not immediately re-reset: clamp to now for a started grid, or to startTime
            // while future-dated (keeps the startTime <= lastUpdated invariant).
            permission.lastUpdated =
                permission.startTime > uint64(block.timestamp) ? permission.startTime : uint64(block.timestamp);
        }

        emit PermissionUpdated(
            msg.sender,
            token,
            spender,
            permissionId,
            permission.limit,
            permission.duration,
            permission.startTime,
            permission.endTime
        );

        _pruneExpired(permissions);
    }

    /**
     * @notice Revoke a single permission, leaving the key's other permissions intact.
     * @dev Swap-and-pop removal; addressed by its stable `permissionId` like {updatePermission}.
     */
    function invalidatePermission(address token, address spender, uint256 permissionId) external {
        Permission[] storage permissions = _permissions[msg.sender][token][spender];
        uint256 permissionIndex = _findPermission(permissions, permissionId);

        uint256 lastIndex = permissions.length - 1;
        if (permissionIndex != lastIndex) permissions[permissionIndex] = permissions[lastIndex];
        permissions.pop();
        if (permissions.length == 0) _untrackPair(msg.sender, token, spender);

        emit PermissionInvalidated(msg.sender, token, spender, permissionId);
    }

    /**
     * @notice Revoke every STORED permission for each given (token, spender) pair in one call.
     * @dev The panic button — but scoped to stored permissions. It does NOT cancel
     *      signed-but-unsubmitted {PermitGrant}/{PermitSpend} signatures (call
     *      {invalidateAllPermits} for those), cannot revoke the operator status this
     *      contract holds on the token (do that on the token for belt and braces), and
     *      cannot revoke FHE decryption rights already granted on past handles — the
     *      spender keeps being able to read the historical limits it already knew.
     */
    function lockdown(TokenSpenderPair[] calldata pairs) external {
        for (uint256 i = 0; i < pairs.length; i++) {
            delete _permissions[msg.sender][pairs[i].token][pairs[i].spender];
            _untrackPair(msg.sender, pairs[i].token, pairs[i].spender);
            emit Lockdown(msg.sender, pairs[i].token, pairs[i].spender);
        }
    }

    /**
     * @notice Invalidate EVERY outstanding permit signature for `msg.sender` at once by
     *         bumping their {permitEpoch}. Complements {lockdown}: lockdown revokes stored
     *         permissions for specific pairs; this cancels signed-but-unsubmitted
     *         {PermitGrant}/{PermitSpend} signatures (which lockdown cannot see, since a
     *         signature lives off-chain until submitted). To cancel one specific permit
     *         instead, use {invalidateUnorderedNonces}.
     * @return newEpoch The owner's epoch after the bump
     */
    function invalidateAllPermits() external returns (uint256 newEpoch) {
        newEpoch = ++permitEpoch[msg.sender];
        emit PermitEpochIncremented(msg.sender, newEpoch);
    }

    /**
     * @notice Spend from `from`'s allowance: transfer up to the encrypted `amount` of
     *         `token` to `to`, if every active permission for (from, token, msg.sender)
     *         allows it. Denied spends transfer an encrypted zero instead of reverting.
     * @dev Reverts `NoPermissions` only on the cleartext precondition (no active
     *      permission window) — everything amount-dependent is oblivious.
     * @param from The user whose allowance is spent
     * @param to The recipient
     * @param amount Encrypted amount (input proof bound to `(this, msg.sender)`)
     * @param inputProof Proof for `amount`
     * @param token The ERC-7984 token to move
     * @return transferred Encrypted amount actually moved (0 if denied or balance-short).
     *         Transiently ACL-allowed to the caller, so contract spenders can chain
     *         FHE ops on it within the same transaction; `from`/`to` can decrypt it
     *         via the token's own grants.
     */
    function transferFrom(
        address from,
        address to,
        externalEuint64 amount,
        bytes calldata inputProof,
        address token
    ) external nonReentrant returns (euint64 transferred) {
        transferred = _spend(from, to, FHESafe.fromExternal(amount, inputProof, msg.sender), token);
    }

    /**
     * @notice Batch variant of {transferFrom}. Atomic: if any item hits a cleartext
     *         revert (e.g. `NoPermissions` after a user lockdown), the whole batch
     *         reverts — filter recipients off-chain first, or use {tryTransferFrom}.
     * @dev Batch size is bounded by the FHEVM per-transaction budget, not by this contract. Items
     *      share no FHE work, so cost is the sum over items and depends on each payer's active
     *      tiers — see {activePermissionCount}, which exists to size this off-chain.
     */
    function transferFrom(TransferDetails[] calldata transfers) external nonReentrant {
        for (uint256 i = 0; i < transfers.length; i++) {
            TransferDetails calldata t = transfers[i];
            _spend(t.from, t.to, FHESafe.fromExternal(t.amount, t.inputProof, msg.sender), t.token);
        }
    }

    /**
     * @notice Lenient batch for payment processors: items that fail a CLEARTEXT
     *         precondition (no active permission window, or the token call reverting —
     *         e.g. an expired operator grant) are skipped with a {TransferSkipped}
     *         event instead of reverting the batch. Encrypted denials are NOT skips:
     *         they execute obliviously and move an encrypted zero, exactly as in
     *         {transferFrom}.
     *
     *         Leniency does NOT extend to a token that returns a handle it is not authorized on.
     *         That reverts `InvalidReturnedHandle` and takes the whole batch with it — see
     *         {_isTokenAuthored} and the note at the call site for why this failure is escalated
     *         rather than skipped.
     * @dev Malformed input proofs still revert the whole call (the import is not
     *      catchable), as does a `token` address with no code (the compiler's
     *      extcodesize check reverts outside try/catch) — both are the caller's own
     *      inputs to get right.
     *
     *      Exhausting the FHEVM per-transaction budget is NOT skipped. Permission evaluation runs
     *      before the `try` opens, so an over-large batch reverts in full — including the items that
     *      would have fit — with `HCULimit`'s `HCUTransactionLimitExceeded` or
     *      `HCUTransactionDepthLimitExceeded` naming the budget that was exceeded. Cost is the sum
     *      over items and depends on each payer's active tiers, so one payer with more tiers than
     *      expected lowers the ceiling for the rest of the batch. Size batches with
     *      {activePermissionCount}.
     * @return executed Per-item flags: true if the item completed and its spend was recorded (the
     *         encrypted outcome may still be zero). False means the item was skipped — see
     *         {TransferSkipped} for which reason. No flag reports a transfer that moved funds: the
     *         one case that could have (an unauthorized return handle) now reverts the call.
     */
    function tryTransferFrom(TransferDetails[] calldata transfers) external nonReentrant returns (bool[] memory executed) {
        executed = new bool[](transfers.length);
        for (uint256 i = 0; i < transfers.length; i++) {
            TransferDetails calldata t = transfers[i];
            executed[i] = _trySpend(t.from, t.to, FHESafe.fromExternal(t.amount, t.inputProof, msg.sender), t.token);
        }
    }

    /**
     * @notice Execute an owner-signed one-shot transfer: move up to the signed encrypted
     *         cap of `permit.token` from `owner` to `to` — the "confidential cheque".
     *         The spender chooses the actual `requested` amount at execution; the cap is enforced
     *         obliviously and all-or-nothing — an over-cap request moves an encrypted zero rather
     *         than being clamped down to the cap.
     * @dev Touches no stored permissions — this is a parallel, stateless rail (plus the
     *      nonce bit). The nonce is consumed on submission REGARDLESS of the encrypted
     *      outcome: a cheque against an insufficient balance is burned unspent (the
     *      outcome cannot be read in cleartext). Like every spend path, requires this
     *      contract to be an ERC-7984 operator for `owner` on the token.
     *
     *      EXCEPTION — the nonce only burns if the call SUCCEEDS. It is written before the token
     *      call, so a token that REVERTS instead of returning an encrypted zero takes the bitmap
     *      write down with it and the cheque stays submittable until `sigDeadline`. The case that
     *      matters in practice is an owner who has never received confidential tokens: some
     *      implementations revert on the uninitialized balance handle rather than treating it as
     *      zero. Such a cheque survives, and the named spender can resubmit it once the owner is
     *      funded. Any retry is still bounded by the signed spender, recipient (when bound),
     *      encrypted cap, epoch and deadline — but an owner who wants a failed cheque gone must
     *      cancel it explicitly with {invalidateUnorderedNonces} or {invalidateAllPermits}.
     * @param owner The signer whose funds move
     * @param permit The signed cheque parameters
     * @param capProof Proof for `permit.capHandle` (bound to `(this, permit.spender)`)
     * @param requested The spender's encrypted requested amount
     * @param requestedProof Proof for `requested` (bound to `(this, msg.sender)`)
     * @param to Recipient; must match `permit.to` when the cheque binds one
     * @param signature EIP-712 signature by `owner` (ECDSA or ERC-1271)
     * @return transferred Encrypted amount actually moved (transiently ACL'd to the caller)
     */
    function permitTransferFrom(
        address owner,
        PermitSpend calldata permit,
        bytes calldata capProof,
        externalEuint64 requested,
        bytes calldata requestedProof,
        address to,
        bytes calldata signature
    ) external nonReentrant returns (euint64 transferred) {
        if (msg.sender != permit.spender) revert SpenderMismatch();
        if (block.timestamp > permit.sigDeadline) revert SignatureExpired(permit.sigDeadline);
        if (permit.to != address(0) && to != permit.to) revert RecipientMismatch();
        _useUnorderedNonce(owner, permit.nonce);
        _verifyPermitSpend(owner, permit, signature);

        euint64 eAmount = _chequeAmount(permit.capHandle, capProof, requested, requestedProof);

        FHE.allowTransient(eAmount, permit.token);
        transferred = IERC7984(permit.token).confidentialTransferFrom(owner, to, eAmount);
        if (!_isTokenAuthored(permit.token, transferred)) revert InvalidReturnedHandle();
        FHE.allowTransient(transferred, msg.sender);

        emit PermitSpent(owner, to, permit.token, msg.sender, permit.nonce, transferred);
    }

    /// @dev All-or-nothing oblivious amount: `requested` when it is at or below the signed cap, an
    ///      encrypted zero otherwise. NOT a clamp — a request of 150 against a cap of 100 moves
    ///      zero, not 100 — and the cheque's nonce is consumed either way, so the signer must issue
    ///      a fresh cheque to retry.
    function _chequeAmount(
        bytes32 capHandle,
        bytes calldata capProof,
        externalEuint64 requested,
        bytes calldata requestedProof
    ) private returns (euint64) {
        // The cap is the OWNER's, encrypted bound to the spender and submitted by them, and it is
        // never granted onward — only `transferred` is. Importing through FHESafe keeps it that way:
        // `FHE.fromExternal` would hand the spender transient access to the cap, which a CONTRACT
        // spender can persist and decrypt, revealing how much room the cheque has left.
        euint64 eCap = FHESafe.fromExternal(externalEuint64.wrap(capHandle), capProof, msg.sender);
        euint64 eRequested = FHESafe.fromExternal(requested, requestedProof, msg.sender);
        return FHE.select(FHE.le(eRequested, eCap), eRequested, E_ZERO);
    }

    /// @notice Permission at `permissionIndex` for the key. Indices are NOT stable
    ///         across writes (swap-and-pop); use the returned `id` to re-address it.
    function getPermission(
        address user,
        address token,
        address spender,
        uint256 permissionIndex
    ) external view returns (Permission memory) {
        Permission[] storage permissions = _permissions[user][token][spender];
        if (permissionIndex >= permissions.length) revert PermissionIndexOutOfRange(permissionIndex);
        return permissions[permissionIndex];
    }

    /// @notice Permission with id `permissionId` for the key (linear scan, view-only).
    function getPermissionById(
        address user,
        address token,
        address spender,
        uint256 permissionId
    ) external view returns (Permission memory) {
        Permission[] storage permissions = _permissions[user][token][spender];
        uint256 len = permissions.length;
        for (uint256 i = 0; i < len; ) {
            if (permissions[i].id == permissionId) return permissions[i];
            unchecked { ++i; }
        }
        revert PermissionNotFound(permissionId);
    }

    function getPermissionCount(address user, address token, address spender) external view returns (uint256) {
        return _permissions[user][token][spender].length;
    }

    /**
     * @notice How many permissions a spend against this key would evaluate right now — the count
     *         that drives its FHE cost. Excludes expired and not-yet-started entries, exactly as
     *         {_evaluatePermissions} does; {getPermissionCount} counts stored entries instead.
     * @dev Size batches with this. Each item in {transferFrom} and {tryTransferFrom} evaluates its
     *      OWN payer's permission set and shares nothing with the others, so a batch's FHE cost is
     *      the sum over its items and one payer's tiers move the ceiling for everyone else in the
     *      call. From this repo's benchmark, a single transfer costs ~1,957,000 HCU at 2 active
     *      permissions, ~3,301,000 at 4 and ~5,989,000 at 8, against a 20,000,000 per-transaction
     *      budget — so roughly 10, 6 and 3 items respectively, and a mixed batch is bounded by its
     *      total. Ten two-tier payments settle; let one payer reach eight tiers and the same batch
     *      exceeds the budget and reverts.
     *
     *      Treat those figures as a floor and this as a planning view, not an on-chain guard: the
     *      same budget also pays for the token's own `confidentialTransferFrom`, which this contract
     *      cannot measure and whose cost can change under it (a hooked token gaining modules). An
     *      over-budget batch reverts in full rather than skipping the items that did not fit.
     *
     *      The count applies the spend path's own active test, so a client filtering on
     *      `startTime`/`endTime` itself cannot disagree with it — note `endTime` expiry is INCLUSIVE.
     *
     *      The separate 5,000,000 DEPTH budget can also bind, though it usually does not: within an
     *      item the checks are ANDed serially, and across items `spent` chains one `FHE.add` per
     *      repeat of the SAME (user, token, spender) key. Batches that hit one payer many times
     *      should account for that as well.
     */
    function activePermissionCount(
        address user,
        address token,
        address spender
    ) external view returns (uint256 count) {
        Permission[] storage permissions = _permissions[user][token][spender];
        uint64 nowTs = uint64(block.timestamp);
        uint256 len = permissions.length;
        for (uint256 i = 0; i < len; ) {
            Permission storage permission = permissions[i];
            if (nowTs <= permission.endTime && nowTs >= permission.startTime) count++;
            unchecked { ++i; }
        }
    }

    function getGrantedPairCount(address user) external view returns (uint256) {
        return _grantedPairs[user].length;
    }

    function getGrantedPairAt(address user, uint256 index) external view returns (TokenSpenderPair memory) {
        if (index >= _grantedPairs[user].length) revert GrantedPairIndexOutOfRange(index);
        return _grantedPairs[user][index];
    }

    function getGrantedPairs(address user) external view returns (TokenSpenderPair[] memory) {
        return _grantedPairs[user];
    }

    // -----------------------------------------------------------------------
    // Spend path
    // -----------------------------------------------------------------------

    /**
     * @dev Check-all, transfer, then record what actually moved.
     *
     *      The permission check gates on the REQUESTED amount; `spent` is credited with
     *      the token's reported ACTUAL transfer. OZ's ERC7984 moves all-or-nothing
     *      (`FHESafeMath.tryDecrease`), so the credit is `amount` or 0 and the
     *      `spent <= limit` invariant is preserved. The external token call sits between
     *      check and record — safe because both entry points are `nonReentrant` and a
     *      malicious `token` can only ever corrupt permission keys naming itself.
     */
    function _spend(address from, address to, euint64 amount, address token) private returns (euint64 transferred) {
        (ebool permitted, bool anyActive) = _evaluatePermissions(from, token, msg.sender, amount);
        if (!anyActive) revert NoPermissions();

        euint64 eTransferAmount = FHE.select(permitted, amount, E_ZERO);
        // The token computes over the handle during this call only.
        FHE.allowTransient(eTransferAmount, token);
        transferred = IERC7984(token).confidentialTransferFrom(from, to, eTransferAmount);
        // Reject a handle the token is not authorized on before it reaches `_recordSpend` — see
        // {_isTokenAuthored} for why an unauthorized handle is a confidentiality leak, not a nuisance.
        if (!_isTokenAuthored(token, transferred)) revert InvalidReturnedHandle();

        _recordSpend(from, token, msg.sender, transferred);

        // OZ's confidentialTransferFrom grants us transient access to `transferred`;
        // pass it on so a contract spender can keep computing with the result.
        FHE.allowTransient(transferred, msg.sender);

        emit AllowanceTransfer(from, to, token, msg.sender, transferred);
    }

    /**
     * @dev Lenient sibling of {_spend} for {tryTransferFrom}: cleartext failures skip
     *      instead of reverting. The try/catch is safe against a malicious token — a
     *      reverting call rolls back its own effects, and reentrancy is blocked at the
     *      entry point.
     *
     *      NOT everything rolls back on a skip, though. Only SPEND ACCOUNTING is conditional on the
     *      token call succeeding: {_evaluatePermissions} has already run, and its permission
     *      maintenance persists even when the catch branch fires — expired entries stay pruned
     *      (swap-and-pop, so surviving entries may have moved), a crossed period boundary stays
     *      reset with `lastUpdated` restamped and {PermissionReset} emitted, and an emptied key
     *      stays unlisted from {getGrantedPairs}. On the strict paths a revert unwinds all of it;
     *      here it commits. None of it is harmful — the same maintenance would happen on the next
     *      successful spend — but it does mean a spender can drive it without moving funds, which
     *      is why owner-facing writes address permissions by id (see {_findPermission}).
     */
    function _trySpend(address from, address to, euint64 amount, address token) private returns (bool) {
        (ebool permitted, bool anyActive) = _evaluatePermissions(from, token, msg.sender, amount);
        if (!anyActive) {
            emit TransferSkipped(from, to, token, msg.sender, SkipReason.NO_PERMISSIONS);
            return false;
        }

        euint64 eTransferAmount = FHE.select(permitted, amount, E_ZERO);
        FHE.allowTransient(eTransferAmount, token);
        try IERC7984(token).confidentialTransferFrom(from, to, eTransferAmount) returns (euint64 transferred) {
            // ESCALATION, NOT A SKIP — the one item-level failure that takes the whole batch down.
            // Every other skip reason is a cleartext precondition the caller can fix: no permission
            // window, no operator grant. A handle the token is not authorized on is different in
            // kind. No conforming ERC-7984 can produce one — OZ's `_update` ends with
            // `FHE.allowThis(transferred)` — so it is positive evidence that the counterparty is
            // hostile rather than merely unusable.
            //
            // `token` is caller-supplied per item, so skipping would mean settling unrelated payers
            // in the same transaction as a contract already caught lying about its return value, on
            // the assumption that lying is the only thing it does. We do not make that assumption:
            // the unknown behaviour of a proven-malicious callee is exactly the class of risk that
            // is obvious only after someone exploits it. Reverting also unwinds the transfer this
            // call just made, which a skip cannot.
            //
            // The cost is real and one-sided: a single hostile token kills the honest items beside
            // it. Screen tokens before batching, or submit suspect ones in their own call.
            if (!_isTokenAuthored(token, transferred)) revert InvalidReturnedHandle();
            _recordSpend(from, token, msg.sender, transferred);
            FHE.allowTransient(transferred, msg.sender);
            emit AllowanceTransfer(from, to, token, msg.sender, transferred);
            return true;
        } catch {
            emit TransferSkipped(from, to, token, msg.sender, SkipReason.TOKEN_CALL_FAILED);
            return false;
        }
    }

    /**
     * @dev First pass: prune expired permissions, lazily reset elapsed periods, and
     *      AND together every active permission's "does the requested amount fit".
     *      Never reverts on "nothing active" — callers decide (strict paths revert
     *      `NoPermissions`, {_trySpend} skips). When `anyActive` is false, `permitted`
     *      is uninitialized and MUST NOT be used.
     *
     *      The fit check must not underflow: FHE arithmetic WRAPS, so the naive
     *      `amount <= limit - spent` turns `spent > limit` (possible after a limit
     *      decrease) into an almost-unlimited budget. Instead:
     *      `amount <= limit && spent <= limit - amount`, which is equivalent to
     *      `spent + amount <= limit` and never wraps in a way that matters — when
     *      `amount > limit` the second operand's wrap is discarded by the AND.
     */
    function _evaluatePermissions(
        address user,
        address token,
        address spender,
        euint64 amount
    ) private returns (ebool permitted, bool anyActive) {
        Permission[] storage permissions = _permissions[user][token][spender];

        uint64 nowTs = uint64(block.timestamp);
        uint256 count = permissions.length;
        uint256 i = 0;
        while (i < count) {
            Permission storage permission = permissions[i];
            if (nowTs > permission.endTime) {
                uint256 lastIndex = count - 1;
                if (i != lastIndex) permissions[i] = permissions[lastIndex];
                permissions.pop();
                count--; // the swapped-in element now sits at i — re-examine it
            } else if (nowTs < permission.startTime) {
                i++; // not started: excluded from the check AND from _recordSpend
            } else {
                anyActive = true;
                _resetIfNewPeriod(user, token, spender, permission);

                ebool fits = FHE.and(
                    FHE.le(amount, permission.limit),
                    FHE.le(permission.spent, FHE.sub(permission.limit, amount))
                );
                permitted = FHE.isInitialized(permitted) ? FHE.and(permitted, fits) : fits;
                i++;
            }
        }

        // Keep the enumeration invariant if the prune emptied the array. On strict
        // paths a NoPermissions revert rolls this back together with the prune; on
        // the lenient path both persist.
        if (permissions.length == 0) _untrackPair(user, token, spender);
    }

    /**
     * @dev Second pass: credit `transferredAmount` to every active permission and stamp
     *      `lastUpdated`. Runs after the token call; the array cannot have changed in
     *      between (nonReentrant, and other writers are keyed by msg.sender). Writes are
     *      identical for permitted and denied spends (adding an encrypted zero), which
     *      is what keeps denied attempts indistinguishable on-chain.
     */
    function _recordSpend(address user, address token, address spender, euint64 transferredAmount) private {
        Permission[] storage permissions = _permissions[user][token][spender];
        uint64 nowTs = uint64(block.timestamp);
        uint256 len = permissions.length; // stable here: no prune/pop on this path
        for (uint256 i = 0; i < len; ) {
            Permission storage permission = permissions[i];
            // Mirror _evaluatePermissions' active set: expired ones were pruned there,
            // not-yet-started ones were excluded from the check so must not be touched.
            if (nowTs >= permission.startTime) {
                euint64 newSpent = FHE.add(permission.spent, transferredAmount);
                permission.spent = newSpent;
                permission.lastUpdated = nowTs;
                FHE.allowThis(newSpent);
                FHE.allow(newSpent, user);
                FHE.allow(newSpent, spender);
            }
            unchecked { ++i; }
        }
    }

    /**
     * @dev Reset `spent` if `block.timestamp` sits in a later period than `lastUpdated`.
     *      Only called with `startTime <= block.timestamp`, and every write keeps
     *      `lastUpdated >= startTime`, so neither subtraction can underflow.
     */
    function _resetIfNewPeriod(address user, address token, address spender, Permission storage permission) private {
        uint256 duration = permission.duration;
        uint256 startTime = permission.startTime;
        uint256 currentPeriod = (block.timestamp - startTime) / duration;
        uint256 lastUpdatePeriod = (uint256(permission.lastUpdated) - startTime) / duration;
        if (currentPeriod == lastUpdatePeriod) return;

        permission.spent = E_ZERO; // user + spender were allowed on E_ZERO at setPermission
        permission.lastUpdated = uint64(block.timestamp);

        emit PermissionReset(user, token, spender, permission.id, block.timestamp);
    }

    // -----------------------------------------------------------------------
    // Shared helpers
    // -----------------------------------------------------------------------

    /**
     * @dev Could `token` have computed `handle`? Ciphertext handles are global, not namespaced per
     *      token, and `token` is a caller-supplied address — so without this check a malicious token
     *      can return ANY handle in place of a transfer result.
     *
     *      That is not a theoretical substitution. This contract calls `FHE.allowThis` on every
     *      user's `limit` and `spent`, so it is permanently authorized on all of them, and those
     *      handles are public (returned by {getPermission}, emitted in {PermissionSet}). An attacker
     *      registers a permission on a token they wrote, has it return a victim's `limit` handle,
     *      and {_recordSpend} computes `FHE.add(ownSpent, victimLimit)` — which passes, because WE
     *      are allowed on both — then grants the sum to the attacker, who knows their own `spent`
     *      and subtracts it. {permitTransferFrom} is more direct still: it forwards the returned
     *      handle straight to `msg.sender` via `allowTransient`, which a contract caller persists.
     *
     *      An honestly-computed result is always authorized to its own token: OZ's `ERC7984._update`
     *      ends with `FHE.allowThis(transferred)`. A third party's ciphertext is not. (OZ applies the
     *      mirror image of this check to amounts callers hand IN — `ERC7984UnauthorizedUseOfEncryptedAmount`.)
     *
     *      Uninitialized is rejected too: an uninitialized handle would revert inside `_recordSpend`'s
     *      `FHE.add` anyway, and that revert sits in the lenient path's success branch where it would
     *      take the whole batch down instead of skipping one item.
     */
    function _isTokenAuthored(address token, euint64 handle) private view returns (bool) {
        return FHE.isInitialized(handle) && FHE.isAllowed(handle, token);
    }

    /// @dev EIP-712 verification for {PermitGrant} (ECDSA or ERC-1271). Binds `owner` and
    ///      the current {permitEpoch} into the digest (see the type-hash note).
    function _verifyPermitGrant(address owner, PermitGrant calldata grant, bytes calldata signature) private view {
        bytes32 structHash = keccak256(
            abi.encode(
                PERMIT_GRANT_TYPEHASH,
                owner,
                grant.token,
                grant.spender,
                grant.limitHandle,
                grant.duration,
                grant.startTime,
                grant.endTime,
                grant.nonce,
                permitEpoch[owner],
                grant.sigDeadline
            )
        );
        if (!SignatureChecker.isValidSignatureNowCalldata(owner, _hashTypedDataV4(structHash), signature)) {
            revert InvalidSigner();
        }
    }

    /// @dev EIP-712 verification for {PermitSpend} (ECDSA or ERC-1271). Binds `owner` and
    ///      the current {permitEpoch} into the digest (see the type-hash note).
    function _verifyPermitSpend(address owner, PermitSpend calldata permit, bytes calldata signature) private view {
        bytes32 structHash = keccak256(
            abi.encode(
                PERMIT_SPEND_TYPEHASH,
                owner,
                permit.token,
                permit.spender,
                permit.capHandle,
                permit.to,
                permit.nonce,
                permitEpoch[owner],
                permit.sigDeadline
            )
        );
        if (!SignatureChecker.isValidSignatureNowCalldata(owner, _hashTypedDataV4(structHash), signature)) {
            revert InvalidSigner();
        }
    }

    /**
     * @dev Cleartext half of {updatePermission}: resolve the zero-sentinels against the stored
     *      record, validate the resulting window, commit the time fields, and report whether the
     *      period grid moved.
     *
     *      Split out so the whole cleartext decision — including the {InvalidEndTime} revert —
     *      happens before any ciphertext import, and because holding the three resolved values
     *      inline alongside the rest of `updatePermission` overflows the stack.
     *
     *      A permission must come out of an update live or future-dated; expiring one is
     *      {invalidatePermission}'s job. Re-submitting the SAME value is not a change, so a wallet
     *      echoing back a full record cannot silently refresh the budget.
     */
    function _applyWindowUpdate(
        Permission storage permission,
        uint64 duration,
        uint64 startTime,
        uint64 endTime
    ) private returns (bool gridChanged) {
        uint64 newDuration = duration == 0 ? permission.duration : duration;
        uint64 newStartTime = startTime == 0 ? permission.startTime : startTime;
        uint64 newEndTime = endTime == 0 ? permission.endTime : endTime;
        _checkWindow(newStartTime, newEndTime);

        gridChanged = newDuration != permission.duration || newStartTime != permission.startTime;

        permission.duration = newDuration;
        permission.startTime = newStartTime;
        permission.endTime = newEndTime;
    }

    /**
     * @dev Resolve a permission by its stable id. Owner-facing writes address permissions this way
     *      because an ARRAY INDEX is not something the owner controls: any spender can move it.
     *
     *      `_evaluatePermissions` swap-and-pops expired entries, and a spender reaches that prune
     *      with a `tryTransferFrom` carrying an encrypted zero — no funds move, and it does not even
     *      need an active permission, because the prune runs before `anyActive` is decided and the
     *      lenient path returns instead of reverting, so the reorder commits. A spender watching the
     *      mempool could therefore front-run the owner's revocation and make it revert on a stale
     *      index. The payoff is narrow but real: a spender sitting at `spent == limit` with a period
     *      boundary approaching survives to the next `_resetIfNewPeriod` and buys a further full
     *      limit. Each expired entry is consumable once, but a hoarded short-`endTime` `PermitGrant`
     *      reloads the magazine.
     *
     *      Ids travel with the permission through the swap, so they are immune. `MAX_PERMISSIONS`
     *      is 8, so the linear scan costs little.
     */
    function _findPermission(
        Permission[] storage permissions,
        uint256 permissionId
    ) private view returns (uint256) {
        uint256 len = permissions.length;
        for (uint256 i = 0; i < len; ) {
            if (permissions[i].id == permissionId) return i;
            unchecked { ++i; }
        }
        revert PermissionNotFound(permissionId);
    }

    /// @dev Add (token, spender) to `user`'s granted-pair enumeration if absent.
    function _trackPair(address user, address token, address spender) private {
        bytes32 pairKey = keccak256(abi.encodePacked(token, spender));
        if (_grantedPairIndex[user][pairKey] != 0) return;
        _grantedPairs[user].push(TokenSpenderPair({token: token, spender: spender}));
        _grantedPairIndex[user][pairKey] = _grantedPairs[user].length; // index + 1
    }

    /// @dev Swap-and-pop (token, spender) out of `user`'s enumeration; no-op if absent.
    function _untrackPair(address user, address token, address spender) private {
        bytes32 pairKey = keccak256(abi.encodePacked(token, spender));
        uint256 indexPlusOne = _grantedPairIndex[user][pairKey];
        if (indexPlusOne == 0) return;

        TokenSpenderPair[] storage pairs = _grantedPairs[user];
        uint256 lastIndex = pairs.length - 1;
        if (indexPlusOne - 1 != lastIndex) {
            TokenSpenderPair memory last = pairs[lastIndex];
            pairs[indexPlusOne - 1] = last;
            _grantedPairIndex[user][keccak256(abi.encodePacked(last.token, last.spender))] = indexPlusOne;
        }
        pairs.pop();
        delete _grantedPairIndex[user][pairKey];
    }

    /// @dev A window is valid if it does not end in the past and ends after it starts. `endTime` is
    ///      an INCLUSIVE expiry (active while `block.timestamp <= endTime`), so `endTime` equal to
    ///      now is accepted.
    function _checkWindow(uint64 startTime, uint64 endTime) private view {
        if (endTime < uint64(block.timestamp)) revert InvalidEndTime();
        if (endTime <= startTime) revert InvalidEndTime();
    }

    /// @dev Swap-and-pop every expired permission (endTime is inclusive).
    function _pruneExpired(Permission[] storage permissions) private {
        uint64 nowTs = uint64(block.timestamp);
        uint256 count = permissions.length;
        uint256 i = 0;
        while (i < count) {
            if (nowTs > permissions[i].endTime) {
                uint256 lastIndex = count - 1;
                if (i != lastIndex) permissions[i] = permissions[lastIndex];
                permissions.pop();
                count--; // re-examine the element swapped into slot i
            } else {
                unchecked { ++i; }
            }
        }
    }
}
