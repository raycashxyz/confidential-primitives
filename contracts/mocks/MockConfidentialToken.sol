// SPDX-License-Identifier: MIT
pragma solidity ^0.8.27;

import {FHE, externalEuint64} from "@fhevm/solidity/lib/FHE.sol";
import {ZamaEthereumConfig} from "@fhevm/solidity/config/ZamaConfig.sol";
import {ERC7984} from "@openzeppelin/confidential-contracts/token/ERC7984/ERC7984.sol";

/// @dev Plain ERC-7984 with an open mint — the simplest confidential token the
///      RecurringAllowance tests can grant permissions on.
contract MockConfidentialToken is ZamaEthereumConfig, ERC7984 {
    constructor() ERC7984("Mock Confidential Token", "MCT", "") {}

    function mint(address to, externalEuint64 amount, bytes calldata inputProof) external {
        _mint(to, FHE.fromExternal(amount, inputProof));
    }
}
