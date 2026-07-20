// SPDX-License-Identifier: MIT
pragma solidity ^0.8.27;

import {IERC1271} from "@openzeppelin/contracts/interfaces/IERC1271.sol";
import {ECDSA} from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";

/**
 * @title Mock1271Wallet
 * @notice Minimal ERC-1271 smart wallet for tests: a signature is valid iff it recovers to
 *         a fixed `signer` EOA. Two of these deployed with the SAME signer model the
 *         cross-account replay scenario the permit digests must resist.
 * @dev `execute` lets a test drive arbitrary calls from the wallet (e.g. `setOperator`).
 */
contract Mock1271Wallet is IERC1271 {
    address public immutable signer;

    constructor(address signer_) {
        signer = signer_;
    }

    function isValidSignature(bytes32 hash, bytes calldata signature) external view returns (bytes4 magicValue) {
        (address recovered, ECDSA.RecoverError err, ) = ECDSA.tryRecoverCalldata(hash, signature);
        if (err == ECDSA.RecoverError.NoError && recovered == signer) {
            return IERC1271.isValidSignature.selector;
        }
        return 0xffffffff;
    }

    function execute(address target, bytes calldata data) external returns (bytes memory) {
        (bool ok, bytes memory ret) = target.call(data);
        require(ok, "Mock1271Wallet: call failed");
        return ret;
    }
}
