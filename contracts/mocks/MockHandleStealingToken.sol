// SPDX-License-Identifier: MIT
pragma solidity ^0.8.27;

import {FHE, euint64, externalEuint64} from "@fhevm/solidity/lib/FHE.sol";
import {ZamaEthereumConfig} from "@fhevm/solidity/config/ZamaConfig.sol";
import {ERC7984} from "@openzeppelin/confidential-contracts/token/ERC7984/ERC7984.sol";

/**
 * @dev A hostile ERC-7984: it moves funds like a normal token but returns a handle of the
 *      attacker's choosing instead of the amount it actually transferred.
 *
 *      Handles are global rather than namespaced per token, so without a provenance check the
 *      victim's `limit`/`spent` ciphertext flows into the attacker's own permission accounting and
 *      is then granted to them for decryption. `stolenHandle` is deliberately a handle this
 *      contract was never authorized on — that is exactly what
 *      {RecurringAllowance-_isTokenAuthored} detects.
 */
contract MockHandleStealingToken is ZamaEthereumConfig, ERC7984 {
    euint64 private _stolenHandle;

    constructor() ERC7984("Handle Stealing Token", "EVIL", "") {}

    function mint(address to, externalEuint64 amount, bytes calldata inputProof) external {
        _mint(to, FHE.fromExternal(amount, inputProof));
    }

    /// @param handle Any ciphertext handle — typically another user's `limit`, read straight out of
    ///        {RecurringAllowance-getPermission}. No proof or ACL grant needed to name it.
    function setStolenHandle(euint64 handle) external {
        _stolenHandle = handle;
    }

    /// @dev Behaves exactly like the honest token until {setStolenHandle} arms it, so a test can
    ///      show the same setup succeeding first and prove the later revert is the substitution.
    function confidentialTransferFrom(
        address from,
        address to,
        euint64 amount
    ) public override returns (euint64) {
        euint64 transferred = super.confidentialTransferFrom(from, to, amount);
        if (!FHE.isInitialized(_stolenHandle)) return transferred;
        return _stolenHandle;
    }
}
