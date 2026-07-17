// SPDX-License-Identifier: MIT
pragma solidity ^0.8.27;

/**
 * @title UnorderedNonces
 * @author Valerio Leo (@valeriohq)
 * @notice Permit2-style unordered nonces: a nonce is `(wordPos << 8) | bitPos`, one bit
 *         in a per-owner bitmap. Unordered (any nonce, any order) so many permits can be
 *         outstanding concurrently, and cancellable in bulk via {invalidateUnorderedNonces}.
 */
abstract contract UnorderedNonces {
    /// @dev The nonce's bit was already set (permit replayed, or cancelled by its owner).
    error InvalidNonce();

    /// @notice Emitted when an owner proactively burns nonces (cancels unsubmitted permits).
    event UnorderedNonceInvalidation(address indexed owner, uint256 word, uint256 mask);

    /// @notice Bitmap of used nonces per owner: bit `n & 0xff` of word `n >> 8`.
    mapping(address owner => mapping(uint256 wordPos => uint256 bitmap)) public nonceBitmap;

    /**
     * @notice Burn arbitrary nonces for `msg.sender` — cancels any signed-but-unsubmitted
     *         permits carrying them. Setting already-used bits is a no-op.
     * @param wordPos Which 256-nonce word to write
     * @param mask Bits to set in that word
     */
    function invalidateUnorderedNonces(uint256 wordPos, uint256 mask) external {
        nonceBitmap[msg.sender][wordPos] |= mask;
        emit UnorderedNonceInvalidation(msg.sender, wordPos, mask);
    }

    /// @dev Flip `nonce`'s bit for `owner`; revert {InvalidNonce} if it was already set.
    function _useUnorderedNonce(address owner, uint256 nonce) internal {
        uint256 wordPos = nonce >> 8;
        uint256 bit = 1 << (nonce & 0xff);
        uint256 flipped = nonceBitmap[owner][wordPos] ^= bit;
        if (flipped & bit == 0) revert InvalidNonce();
    }
}
