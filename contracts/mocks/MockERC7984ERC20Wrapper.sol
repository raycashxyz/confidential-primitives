// SPDX-License-Identifier: MIT
pragma solidity ^0.8.27;

import {IERC20} from "@openzeppelin/contracts/interfaces/IERC20.sol";
import {euint64} from "@fhevm/solidity/lib/FHE.sol";
import {ZamaEthereumConfig} from "@fhevm/solidity/config/ZamaConfig.sol";
import {ERC7984} from "@openzeppelin/confidential-contracts/token/ERC7984/ERC7984.sol";
import {ERC7984ERC20Wrapper} from "@openzeppelin/confidential-contracts/token/ERC7984/extensions/ERC7984ERC20Wrapper.sol";

contract MockERC7984ERC20Wrapper is ERC7984, ERC7984ERC20Wrapper, ZamaEthereumConfig {
    constructor(IERC20 underlying_, string memory name_, string memory symbol_)
        ERC7984(name_, symbol_, "")
        ERC7984ERC20Wrapper(underlying_)
    {}

    function decimals() public view override(ERC7984, ERC7984ERC20Wrapper) returns (uint8) {
        return super.decimals();
    }

    function supportsInterface(bytes4 interfaceId)
        public
        view
        override(ERC7984, ERC7984ERC20Wrapper)
        returns (bool)
    {
        return super.supportsInterface(interfaceId);
    }

    function _update(address from, address to, euint64 amount)
        internal
        override(ERC7984, ERC7984ERC20Wrapper)
        returns (euint64)
    {
        return super._update(from, to, amount);
    }
}
