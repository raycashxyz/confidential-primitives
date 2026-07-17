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
        ///      Invariant: `startTime <= lastUpdated <= block.timestamp`.
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

    /// @dev A (token, spender) pair for {lockdown}.
    struct TokenSpenderPair {
        address token;
        address spender;
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

    function setPermission(
        address token,
        address spender,
        externalEuint64 limit,
        bytes calldata inputProof,
        uint64 duration,
        uint64 startTime,
        uint64 endTime
    ) external returns (uint256 permissionId);

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

    function invalidatePermission(
        address token,
        address spender,
        uint256 permissionIndex,
        uint256 permissionId
    ) external;

    function lockdown(TokenSpenderPair[] calldata pairs) external;

    function transferFrom(
        address from,
        address to,
        externalEuint64 amount,
        bytes calldata inputProof,
        address token
    ) external returns (euint64 transferred);

    function transferFrom(TransferDetails[] calldata transfers) external;

    function getPermission(
        address user,
        address token,
        address spender,
        uint256 permissionIndex
    ) external view returns (Permission memory);

    function getPermissionById(
        address user,
        address token,
        address spender,
        uint256 permissionId
    ) external view returns (Permission memory);

    function getPermissionCount(address user, address token, address spender) external view returns (uint256);
}
