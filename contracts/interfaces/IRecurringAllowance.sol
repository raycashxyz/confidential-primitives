// SPDX-License-Identifier: MIT
pragma solidity ^0.8.27;

import {euint64, externalEuint64} from "@fhevm/solidity/lib/FHE.sol";

/**
 * @title IRecurringAllowance
 * @author Valerio Leo (@valeriohq)
 * @notice Interface for {RecurringAllowance}: encrypted, period-based spending
 *         permissions over any ERC-7984 confidential token.
 */
interface IRecurringAllowance {
    /**
     * @dev One spending permission. Amounts are encrypted (`euint64`); the time
     *      fields are cleartext, so the *shape* of a permission (its period and
     *      window) is public while its size stays private.
     *
     *      The period grid is anchored at `startTime`: period `n` covers
     *      `[startTime + n*duration, startTime + (n+1)*duration)`. `spent` counts
     *      the current period only and is reset (lazily, on the next spend) when a
     *      period boundary is crossed.
     */
    struct Permission {
        /// @dev Stable identifier, unique across all users. Indices shift (swap-and-pop),
        ///      ids never do — state-changing calls that take an index also take the id.
        uint256 id;
        /// @dev Encrypted per-period spending limit.
        euint64 limit;
        /// @dev Encrypted amount spent in the current period.
        euint64 spent;
        /// @dev Last time `spent` was written (spend attempt or period reset).
        ///      Invariant: `startTime <= lastUpdated`. Once the permission has started it
        ///      also holds `lastUpdated <= block.timestamp`; while still future-dated it
        ///      equals `startTime` (which is itself in the future).
        uint64 lastUpdated;
        /// @dev Unix timestamp the permission (and its period grid) starts at.
        uint64 startTime;
        /// @dev Unix timestamp the permission expires at, INCLUSIVE: the permission
        ///      is active while `block.timestamp <= endTime`.
        uint64 endTime;
        /// @dev Period length in seconds. `type(uint64).max` means the spent amount
        ///      never resets (a one-shot budget for the whole window).
        uint64 duration;
    }

    /// @dev One transfer in a {transferFrom} batch.
    struct TransferDetails {
        address from;
        address to;
        externalEuint64 amount;
        bytes inputProof;
        address token;
    }

    /// @dev A (token, spender) pair for {lockdown} and the granted-pair enumeration.
    struct TokenSpenderPair {
        address token;
        address spender;
    }

    /**
     * @dev Signed authorization to CREATE a permission (the gasless-grant flow).
     *      `limitHandle` is the bytes32 handle of an encrypted limit whose input proof
     *      the owner created bound to `(this contract, spender)` — so only `spender`
     *      can submit it. Signing the handle commits the owner to that exact ciphertext.
     */
    struct PermitGrant {
        address token;
        address spender;
        /// @dev Handle of the encrypted per-period limit (an `externalEuint64`).
        bytes32 limitHandle;
        /// @dev Same sentinel semantics as {setPermission} — 0 means max / "at submission".
        uint64 duration;
        uint64 startTime;
        uint64 endTime;
        /// @dev Unordered nonce (see {UnorderedNonces}).
        uint256 nonce;
        /// @dev Signature expiry — the permit cannot be submitted after this timestamp.
        uint256 sigDeadline;
    }

    /**
     * @dev Signed authorization for a ONE-SHOT transfer up to an encrypted cap (the
     *      "confidential cheque"). Consumed on submission regardless of the encrypted
     *      outcome — a cheque against an insufficient balance still burns its nonce.
     */
    struct PermitSpend {
        address token;
        address spender;
        /// @dev Handle of the encrypted cap (an `externalEuint64`), proof bound to `spender`.
        bytes32 capHandle;
        /// @dev Bound recipient; address(0) lets the spender choose at execution.
        address to;
        uint256 nonce;
        uint256 sigDeadline;
    }

    /// @dev Why {tryTransferFrom} skipped an item.
    enum SkipReason {
        NONE,
        /// @dev No active permission window for (from, token, spender).
        NO_PERMISSIONS,
        /// @dev The token call reverted (e.g. this contract is not an operator for `from`).
        TOKEN_CALL_FAILED
    }

    /// @dev `token` is the zero address.
    error InvalidTokenAddress();
    /// @dev `spender` is the zero address.
    error InvalidSpenderAddress();
    /// @dev The (effective) end time is in the past or not after the start time.
    error InvalidEndTime();
    /// @dev No permission exists at `permissionIndex` for the given key.
    error PermissionNotFound(uint256 permissionIndex);
    /// @dev The permission at the given index does not carry the given id (the array
    ///      was reordered since the caller read it — re-read and retry).
    error PermissionMismatch(uint256 permissionId);
    /// @dev The (user, token, spender) key has no active permission to spend against.
    error NoPermissions();
    /// @dev Adding one more permission would exceed {RecurringAllowance-MAX_PERMISSIONS}.
    error TooManyPermissions();
    /// @dev The permit's `sigDeadline` has passed.
    error SignatureExpired(uint256 sigDeadline);
    /// @dev The signature does not verify for the claimed owner (ECDSA or ERC-1271).
    error InvalidSigner();
    /// @dev A permit must be submitted by the spender it names (its proof binds them anyway).
    error SpenderMismatch();
    /// @dev The permit binds a recipient and `to` differs from it.
    error RecipientMismatch();

    /// @notice A new permission was created.
    event PermissionSet(
        address indexed user,
        address indexed token,
        address indexed spender,
        uint256 permissionId,
        euint64 limit,
        uint64 duration,
        uint64 startTime,
        uint64 endTime
    );

    /// @notice An existing permission was modified by its user.
    event PermissionUpdated(
        address indexed user,
        address indexed token,
        address indexed spender,
        uint256 permissionId,
        euint64 limit,
        uint64 duration,
        uint64 startTime,
        uint64 endTime
    );

    /// @notice A permission's period boundary was crossed and its spent amount reset.
    event PermissionReset(
        address indexed user,
        address indexed token,
        address indexed spender,
        uint256 permissionId,
        uint256 timestamp
    );

    /// @notice A single permission was revoked by its user.
    event PermissionInvalidated(
        address indexed user,
        address indexed token,
        address indexed spender,
        uint256 permissionId
    );

    /// @notice Every permission for (user, token, spender) was revoked.
    event Lockdown(address indexed user, address indexed token, address indexed spender);

    /// @notice An owner bumped their permit epoch, invalidating all outstanding permit
    ///         signatures at once (see {invalidateAllPermits}).
    event PermitEpochIncremented(address indexed owner, uint256 newEpoch);

    /// @notice A spend was executed through the allowance. `transferred` is the encrypted
    ///         amount actually moved — an observer cannot tell a denied spend (0) from a
    ///         permitted one. `from`/`to` are already public in the token's own
    ///         `ConfidentialTransfer` event, so this adds no new leak.
    event AllowanceTransfer(
        address indexed from,
        address indexed to,
        address indexed token,
        address spender,
        euint64 transferred
    );

    /// @notice A {tryTransferFrom} item was skipped for a cleartext reason (encrypted
    ///         denials are NOT skips — they execute and transfer an encrypted zero).
    event TransferSkipped(
        address indexed from,
        address indexed to,
        address indexed token,
        address spender,
        SkipReason reason
    );

    /// @notice A one-shot {permitTransferFrom} executed. As with {AllowanceTransfer},
    ///         `transferred` is encrypted and may be zero (over-cap or balance-short).
    event PermitSpent(
        address indexed owner,
        address indexed to,
        address indexed token,
        address spender,
        uint256 nonce,
        euint64 transferred
    );

    /// @notice Grant `spender` an encrypted per-period spending budget on `token`.
    ///         The caller must separately make this contract an ERC-7984 operator.
    /// @return permissionId Stable id of the new permission.
    function setPermission(
        address token,
        address spender,
        externalEuint64 limit,
        bytes calldata inputProof,
        uint64 duration,
        uint64 startTime,
        uint64 endTime
    ) external returns (uint256 permissionId);

    /// @notice Modify an existing permission of the caller, addressed by (index, id).
    ///         Zero-valued time fields and an empty `inputProof` mean "leave unchanged";
    ///         changing the grid (`duration`/`startTime`) resets `spent`.
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
    ) external;

    /// @notice Revoke one of the caller's permissions, addressed by (index, id).
    function invalidatePermission(
        address token,
        address spender,
        uint256 permissionIndex,
        uint256 permissionId
    ) external;

    /// @notice Revoke every stored permission for each given (token, spender) pair.
    function lockdown(TokenSpenderPair[] calldata pairs) external;

    /// @notice Invalidate all of the caller's outstanding permit signatures at once by
    ///         bumping their {permitEpoch}. Signature-level counterpart to {lockdown}.
    /// @return newEpoch The caller's epoch after the bump.
    function invalidateAllPermits() external returns (uint256 newEpoch);

    /// @notice Current permit epoch for `owner`, mixed into every permit digest.
    function permitEpoch(address owner) external view returns (uint256);

    /// @notice Spend `from`'s allowance: move up to encrypted `amount` of `token` to `to`
    ///         if every active permission for (from, token, msg.sender) allows it. A denied
    ///         spend moves an encrypted zero instead of reverting.
    /// @return transferred Encrypted amount actually moved (transiently ACL'd to the caller).
    function transferFrom(
        address from,
        address to,
        externalEuint64 amount,
        bytes calldata inputProof,
        address token
    ) external returns (euint64 transferred);

    /// @notice Atomic batch {transferFrom}: any cleartext revert reverts the whole batch.
    function transferFrom(TransferDetails[] calldata transfers) external;

    /// @notice Lenient batch {transferFrom} for processors: items that fail a cleartext
    ///         precondition are skipped ({TransferSkipped}) rather than reverting the batch.
    /// @return executed Per-item flag: true if the token transfer was executed (its
    ///         encrypted outcome may still be zero).
    function tryTransferFrom(TransferDetails[] calldata transfers) external returns (bool[] memory executed);

    /// @notice Create a permission from `owner`'s off-chain {PermitGrant} signature (the
    ///         gasless-grant flow — the named spender submits and pays gas).
    /// @return permissionId Stable id of the new permission.
    function permitSetPermission(
        address owner,
        PermitGrant calldata grant,
        bytes calldata inputProof,
        bytes calldata signature
    ) external returns (uint256 permissionId);

    /// @notice Execute an `owner`-signed one-shot transfer up to a signed encrypted cap (a
    ///         "confidential cheque"); over-cap requests move an encrypted zero, obliviously.
    /// @return transferred Encrypted amount actually moved (transiently ACL'd to the caller).
    function permitTransferFrom(
        address owner,
        PermitSpend calldata permit,
        bytes calldata capProof,
        externalEuint64 requested,
        bytes calldata requestedProof,
        address to,
        bytes calldata signature
    ) external returns (euint64 transferred);

    /// @notice Permission at `permissionIndex` for the key. Indices are NOT stable across
    ///         writes (swap-and-pop); re-address by the returned `id`.
    function getPermission(
        address user,
        address token,
        address spender,
        uint256 permissionIndex
    ) external view returns (Permission memory);

    /// @notice Permission with id `permissionId` for the key (linear scan).
    function getPermissionById(
        address user,
        address token,
        address spender,
        uint256 permissionId
    ) external view returns (Permission memory);

    /// @notice Number of permissions stored for the (user, token, spender) key.
    function getPermissionCount(address user, address token, address spender) external view returns (uint256);

    /// @notice Number of (token, spender) pairs for which `user` has stored permissions.
    function getGrantedPairCount(address user) external view returns (uint256);

    /// @notice The (token, spender) pair at `index` (unstable order — swap-and-pop).
    function getGrantedPairAt(address user, uint256 index) external view returns (TokenSpenderPair memory);

    /// @notice Every (token, spender) pair for which `user` has stored permissions.
    ///         Entries may hold only EXPIRED permissions until a write prunes them —
    ///         read the permissions themselves for freshness.
    function getGrantedPairs(address user) external view returns (TokenSpenderPair[] memory);
}
