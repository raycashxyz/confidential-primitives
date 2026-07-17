// SPDX-License-Identifier: MIT
pragma solidity ^0.8.27;

import {FHE, euint64, ebool, externalEuint64} from "@fhevm/solidity/lib/FHE.sol";
import {ZamaEthereumConfig} from "@fhevm/solidity/config/ZamaConfig.sol";
import {ReentrancyGuard} from "@openzeppelin/contracts/utils/ReentrancyGuard.sol";
import {IERC7984} from "@openzeppelin/confidential-contracts/interfaces/IERC7984.sol";
import {IRecurringAllowance} from "../interfaces/IRecurringAllowance.sol";

/**
 * @title RecurringAllowance
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
 *         REENTRANCY: {transferFrom} calls the caller-supplied `token` address, so both
 *         overloads are `nonReentrant`. All other state is keyed by `msg.sender`, which
 *         inside such a call is the token itself — it can only touch its own keys.
 */
contract RecurringAllowance is IRecurringAllowance, ZamaEthereumConfig, ReentrancyGuard {
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

    /// @dev Ids start at 1 so 0 never names a permission.
    uint256 private _nextPermissionId = 1;

    constructor() {
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
     *        Must be in the future and after `startTime`.
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
        if (token == address(0)) revert InvalidTokenAddress();
        if (spender == address(0)) revert InvalidSpenderAddress();

        if (duration == 0) duration = type(uint64).max;
        if (startTime == 0) startTime = uint64(block.timestamp);
        if (endTime == 0) endTime = type(uint64).max;
        _checkWindow(startTime, endTime);

        Permission[] storage permissions = _permissions[msg.sender][token][spender];
        _pruneExpired(permissions);
        if (permissions.length >= MAX_PERMISSIONS) revert TooManyPermissions();

        euint64 eLimit = FHE.fromExternal(limit, inputProof);
        FHE.allowThis(eLimit);
        FHE.allow(eLimit, msg.sender);
        FHE.allow(eLimit, spender);
        // Let both parties decrypt the initial (and any reset) spent value.
        FHE.allow(E_ZERO, msg.sender);
        FHE.allow(E_ZERO, spender);

        permissionId = _nextPermissionId++;
        permissions.push(
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

        emit PermissionSet(msg.sender, token, spender, permissionId, eLimit, duration, startTime, endTime);
    }

    /**
     * @notice Modify an existing permission. Zero-valued parameters mean "leave unchanged"
     *         (to actually set a field to its "unlimited" value, pass `type(uint64).max`;
     *         to skip the limit, pass an empty `inputProof`).
     * @dev Changing `duration` or `startTime` re-anchors the period grid, so `spent`
     *      resets and a fresh period starts — otherwise the old grid's spend history
     *      would be measured against the new grid (and a future `startTime` would make
     *      the reset math underflow). Changing only `limit` keeps the current period's
     *      `spent`: lowering the limit below what is already spent simply blocks further
     *      spending until the next reset.
     *      The permission is addressed by (index, id): indices move under swap-and-pop,
     *      so the id guard makes a stale index revert instead of hitting a neighbour.
     */
    function updatePermission(
        address token,
        address spender,
        uint256 permissionIndex,
        uint256 permissionId,
        externalEuint64 limit,
        bytes calldata inputProof,
        uint64 duration,
        uint64 startTime,
        uint64 endTime
    ) external {
        Permission[] storage permissions = _permissions[msg.sender][token][spender];
        if (permissionIndex >= permissions.length) revert PermissionNotFound(permissionIndex);
        Permission storage permission = permissions[permissionIndex];
        if (permission.id != permissionId) revert PermissionMismatch(permissionId);

        if (inputProof.length > 0) {
            euint64 eLimit = FHE.fromExternal(limit, inputProof);
            permission.limit = eLimit;
            FHE.allowThis(eLimit);
            FHE.allow(eLimit, msg.sender);
            FHE.allow(eLimit, spender);
        }

        bool gridChanged;
        if (duration != 0) {
            permission.duration = duration;
            gridChanged = true;
        }
        if (startTime != 0) {
            permission.startTime = startTime;
            gridChanged = true;
        }
        if (endTime != 0) {
            permission.endTime = endTime;
        }
        // The permission must come out of an update live or future-dated; expiring one
        // is invalidatePermission's job.
        _checkWindow(permission.startTime, permission.endTime);

        if (gridChanged) {
            permission.spent = E_ZERO;
            permission.lastUpdated = permission.startTime;
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
     * @dev Swap-and-pop removal; addressed by (index, id) like {updatePermission}.
     */
    function invalidatePermission(
        address token,
        address spender,
        uint256 permissionIndex,
        uint256 permissionId
    ) external {
        Permission[] storage permissions = _permissions[msg.sender][token][spender];
        if (permissionIndex >= permissions.length) revert PermissionNotFound(permissionIndex);
        if (permissions[permissionIndex].id != permissionId) revert PermissionMismatch(permissionId);

        permissions[permissionIndex] = permissions[permissions.length - 1];
        permissions.pop();

        emit PermissionInvalidated(msg.sender, token, spender, permissionId);
    }

    /**
     * @notice Revoke every permission for each given (token, spender) pair in one call.
     * @dev The panic button. Note it cannot revoke the operator status this contract
     *      holds on the token (do that on the token if you want belt and braces), and
     *      FHE decryption rights already granted on past handles are not revocable —
     *      the spender keeps being able to read the historical limits it already knew.
     */
    function lockdown(TokenSpenderPair[] calldata pairs) external {
        for (uint256 i = 0; i < pairs.length; i++) {
            delete _permissions[msg.sender][pairs[i].token][pairs[i].spender];
            emit Lockdown(msg.sender, pairs[i].token, pairs[i].spender);
        }
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
        transferred = _spend(from, to, FHE.fromExternal(amount, inputProof), token);
    }

    /**
     * @notice Batch variant of {transferFrom}. Atomic: if any item hits a cleartext
     *         revert (e.g. `NoPermissions` after a user lockdown), the whole batch
     *         reverts — filter recipients off-chain first.
     */
    function transferFrom(TransferDetails[] calldata transfers) external nonReentrant {
        for (uint256 i = 0; i < transfers.length; i++) {
            TransferDetails calldata t = transfers[i];
            _spend(t.from, t.to, FHE.fromExternal(t.amount, t.inputProof), t.token);
        }
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
        if (permissionIndex >= permissions.length) revert PermissionNotFound(permissionIndex);
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
        for (uint256 i = 0; i < permissions.length; i++) {
            if (permissions[i].id == permissionId) return permissions[i];
        }
        revert PermissionNotFound(permissionId);
    }

    function getPermissionCount(address user, address token, address spender) external view returns (uint256) {
        return _permissions[user][token][spender].length;
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
        ebool permitted = _checkPermissions(from, token, msg.sender, amount);

        euint64 eTransferAmount = FHE.select(permitted, amount, E_ZERO);
        // The token computes over the handle during this call only.
        FHE.allowTransient(eTransferAmount, token);
        transferred = IERC7984(token).confidentialTransferFrom(from, to, eTransferAmount);

        _recordSpend(from, token, msg.sender, transferred);

        // OZ's confidentialTransferFrom grants us transient access to `transferred`;
        // pass it on so a contract spender can keep computing with the result.
        FHE.allowTransient(transferred, msg.sender);

        emit AllowanceTransfer(from, to, token, msg.sender, transferred);
    }

    /**
     * @dev First pass: prune expired permissions, lazily reset elapsed periods, and
     *      AND together every active permission's "does the requested amount fit".
     *
     *      The fit check must not underflow: FHE arithmetic WRAPS, so the naive
     *      `amount <= limit - spent` turns `spent > limit` (possible after a limit
     *      decrease) into an almost-unlimited budget. Instead:
     *      `amount <= limit && spent <= limit - amount`, which is equivalent to
     *      `spent + amount <= limit` and never wraps in a way that matters — when
     *      `amount > limit` the second operand's wrap is discarded by the AND.
     */
    function _checkPermissions(
        address user,
        address token,
        address spender,
        euint64 amount
    ) private returns (ebool permitted) {
        Permission[] storage permissions = _permissions[user][token][spender];
        if (permissions.length == 0) revert NoPermissions();

        uint64 nowTs = uint64(block.timestamp);
        bool anyActive = false;
        uint256 count = permissions.length;
        uint256 i = 0;
        while (i < count) {
            Permission storage permission = permissions[i];
            if (nowTs > permission.endTime) {
                permissions[i] = permissions[count - 1];
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

        if (!anyActive) revert NoPermissions();
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
        for (uint256 i = 0; i < permissions.length; i++) {
            Permission storage permission = permissions[i];
            // Mirror _checkPermissions' active set: expired ones were pruned there,
            // not-yet-started ones were excluded from the check so must not be touched.
            if (nowTs < permission.startTime) continue;

            euint64 newSpent = FHE.add(permission.spent, transferredAmount);
            permission.spent = newSpent;
            permission.lastUpdated = nowTs;
            FHE.allowThis(newSpent);
            FHE.allow(newSpent, user);
            FHE.allow(newSpent, spender);
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

    /// @dev A window is valid if it ends in the future and after it starts.
    function _checkWindow(uint64 startTime, uint64 endTime) private view {
        if (endTime < uint64(block.timestamp)) revert InvalidEndTime();
        if (endTime <= startTime) revert InvalidEndTime();
    }

    /// @dev Swap-and-pop every expired permission (endTime is inclusive).
    function _pruneExpired(Permission[] storage permissions) private {
        uint64 nowTs = uint64(block.timestamp);
        uint256 i = 0;
        while (i < permissions.length) {
            if (nowTs > permissions[i].endTime) {
                permissions[i] = permissions[permissions.length - 1];
                permissions.pop();
            } else {
                i++;
            }
        }
    }
}
