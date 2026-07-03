// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "@openzeppelin/contracts/token/ERC20/ERC20.sol";
import "@openzeppelin/contracts/access/Ownable.sol";

contract MockUSDC is ERC20, Ownable {
    uint8 private DECIMALS;

    // We use a constructor parameter to set the decimals, so we can test TokenScaler with different decimals.
    constructor(uint8 _decimals) ERC20("USD Coin", "USDC") Ownable(msg.sender) {
        DECIMALS = _decimals;
        // Initial supply of 1,000,000 USDC scaled by the configured decimals
        _mint(msg.sender, 1_000_000 * 10**DECIMALS);
    }

    function decimals() public view override returns (uint8) {
        return DECIMALS;
    }

    function mint(uint256 amount) external {
        _mint(msg.sender, amount);
    }
}
