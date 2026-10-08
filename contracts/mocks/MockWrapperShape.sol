// SPDX-License-Identifier: MIT
pragma solidity ^0.8.27;

/// @dev Only the two views `StealthWrapAdapter`'s constructor reads, with arbitrary values, so its
///      rejection of a zero underlying and a zero rate can be exercised.
contract MockWrapperShape {
    address public immutable underlying;
    uint256 public immutable rate;

    constructor(address underlying_, uint256 rate_) {
        underlying = underlying_;
        rate = rate_;
    }
}
