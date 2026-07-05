// SPDX-License-Identifier: MIT
pragma solidity ^0.8.27;

import {FHE, euint64, externalEuint64, ebool, eaddress, externalEaddress} from "@fhevm/solidity/lib/FHE.sol";
import {ZamaEthereumConfig} from "@fhevm/solidity/config/ZamaConfig.sol";
import {IERC20} from "@openzeppelin/contracts/interfaces/IERC20.sol";
import {SafeERC20} from "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import {SafeCast} from "@openzeppelin/contracts/utils/math/SafeCast.sol";
import {ERC7984} from "@openzeppelin/confidential-contracts/token/ERC7984/ERC7984.sol";
import {ERC7984ERC20Wrapper} from "@openzeppelin/confidential-contracts/token/ERC7984/extensions/ERC7984ERC20Wrapper.sol";
import {IERC7984AsyncWrapper} from "./IERC7984AsyncWrapper.sol";

/**
 * @title BatchedAsyncWrapperV2
 * @notice Cheaper, single-finalize redesign of {BatchedAsyncWrapper}: a cleartext
 *         per-(batch, recipient) nullifier replaces the confidential bitmap, and the
 *         payout sum is tree-reduced so the FHE dependency DEPTH is O(log N), not O(N).
 *
 *         Same privacy model as the other wrappers: a deposit is SENDER-TRANSPARENT
 *         (depositor + cleartext amount are public) but RECIPIENT-PRIVATE (an
 *         `eaddress`). finalize scans whole batches, so the decoy set is the batch and
 *         the minted sum stays encrypted — observers learn only "R finalized batch B".
 *
 *         What changed vs {BatchedAsyncWrapper}, and why:
 *
 *         1. ONE finalize path. The bitmap design ships two (per-slot reference +
 *            bulk); they are individually replay-safe but must both gate on complete
 *            batches to compose. Here there is a single {finalizeWrap} and no
 *            second path to reason about.
 *
 *         2. Cleartext nullifier. The recipient is already public at finalize time
 *            (it is an address argument, emitted in {WrapFinalized}), so a plain
 *            `finalized[batchId][recipient]` bool leaks nothing the call does not
 *            already reveal — and it deletes ALL per-slot bitmap FHE ops (`and`/`ne`/
 *            `or` + the bitmap SSTORE of a fresh ciphertext handle).
 *
 *         3. Tree-reduced sum ({_sumTree}). The bitmap variants accumulate
 *            `sum = add(sum, ...)` serially: N adds of ~162k HCU depth each hits the
 *            FHEVM 5M HCU DEPTH cap at ~29 slots. Pairwise reduction cuts the
 *            critical path to ceil(log2 N) adds, moving the binding constraint to the
 *            20M TOTAL HCU budget (~56 slots measured) — hence {MAX_BATCH_LIMIT} = 48
 *            with headroom, vs ~28 usable under the serial designs.
 *
 *         Tradeoff: the nullifier is all-or-nothing per (batch, recipient), so a batch
 *         must be CLOSED (full, or timeout-sealed via {sealBatch}) before finalizing —
 *         this freezes each recipient's matched set (no later top-ups into a finalized
 *         batch). {sealBatch} is the liveness escape hatch for a tail batch that never
 *         fills: permissionless, but only `sealDelay` after the batch's last deposit so
 *         a griefer cannot prematurely shrink the anonymity set.
 *
 *         Recipient handshake (how the depositor never learns the recipient): the
 *         RECIPIENT encrypts their own address off-chain with the input proof bound to
 *         the DEPOSITOR as userAddress, and hands (handle, proof) to the depositor,
 *         who submits it via {initWrap}. The recipient recognises their deposit by
 *         watching for their handle in {WrapInitiated}.
 *
 *         Like the other wrappers: deposits pulled via IERC20.transferFrom, unwrap via
 *         the inherited OZ ERC7984ERC20Wrapper lifecycle, unowned, no hooks.
 */
contract BatchedAsyncWrapperV2 is IERC7984AsyncWrapper, ZamaEthereumConfig, ERC7984ERC20Wrapper {
    using SafeERC20 for IERC20;

    /// @dev Hard cap on batch size, set so {finalizeWrap} over ONE batch is PROVABLY
    ///      completable — an unfinalizable batch would lock funds. finalize does a
    ///      fixed amount of FHE work per slot (`eq` + `select` + tree `add`), so its
    ///      binding limit is the FHEVM 20M TOTAL-HCU/tx budget: measured on the FHEVM
    ///      coprocessor mocks (which meter HCU via the HCULimit host contract),
    ///      56 slots fits and >=60 reverts; the analytic op-cost model agrees (~60).
    ///      48 leaves ~15-20% headroom while still nearly doubling the ~28-slot
    ///      ceiling the serial-sum designs get under the 5M HCU DEPTH cap.
    ///      NOTE the budget applies to TOTAL SLOTS SCANNED PER CALL: near the cap,
    ///      finalize one batch per call; multi-batch calls suit smaller batch sizes.
    uint256 private constant MAX_BATCH_LIMIT = 48;

    euint64 public immutable E_ZERO;
    uint256 public immutable maxBatchDeposits;

    /// @notice Seconds after a batch's last deposit before anyone may {sealBatch} it.
    uint256 public immutable sealDelay;

    /// @notice Batch currently accepting deposits.
    uint256 public currentBatchId;

    /// @notice Total deposits recorded across all batches.
    uint256 public totalDeposits;

    /// @notice Number of deposits recorded in a batch (also its finalize scan bound).
    mapping(uint256 batchId => uint256) public batchFillCount;

    /// @notice A batch is closed once full or {sealBatch}ed; only closed batches finalize.
    mapping(uint256 batchId => bool) public batchClosed;

    /// @notice Timestamp of the most recent deposit into a batch (drives the seal timeout).
    mapping(uint256 batchId => uint64) public batchLastDepositAt;

    /// @notice Cleartext replay nullifier: recipient already paid for this batch.
    mapping(uint256 batchId => mapping(address recipient => bool)) public finalized;

    /// @notice Global slot index (batchId * maxBatchDeposits + batchIndex) => deposit.
    mapping(uint256 slot => Deposit) public deposits;

    struct Deposit {
        address depositor;
        uint256 amount; // cleartext — the transparent side of the mix
        euint64 eAmount;
        eaddress eRecipient;
    }

    event WrapInitiated(
        uint256 indexed batchId,
        uint256 indexed slot,
        address indexed depositor,
        uint256 amount,
        bytes32 eRecipient
    );
    event WrapFinalized(address indexed recipient, bytes32 amount, uint256[] ids);
    event BatchSealed(uint256 indexed batchId, uint256 filled);

    // ZeroAmount, ZeroAddress, DuplicateId, ExternalWrapNotSupported inherited from IERC7984AsyncWrapper.
    error InvalidBatchSize();
    error BatchNotClosed();
    error BatchAlreadyClosed();
    error NotCurrentBatch();
    error NothingToSeal();
    error SealDelayNotElapsed();
    error SealDelayTooShort();
    error AlreadyFinalized();
    error UnauthorizedDepositor();
    error AmountNotMultipleOfRate();

    constructor(
        uint256 _maxBatchDeposits,
        uint256 _sealDelay,
        IERC20 _underlying,
        string memory name_,
        string memory symbol_
    )
        ERC7984(name_, symbol_, "")
        ERC7984ERC20Wrapper(_underlying)
    {
        if (address(_underlying) == address(0)) revert ZeroAddress();
        if (_maxBatchDeposits == 0 || _maxBatchDeposits > MAX_BATCH_LIMIT) revert InvalidBatchSize();
        // sealBatch's griefer-resistance IS the delay: with sealDelay = 0 anyone could
        // seal every batch at fill count 1, collapsing the anonymity set to a single
        // deposit. Zero is rejected; choosing a meaningfully large delay (hours) is
        // still the deployer's responsibility, like maxBatchDeposits itself.
        if (_sealDelay == 0) revert SealDelayTooShort();
        maxBatchDeposits = _maxBatchDeposits;
        sealDelay = _sealDelay;
        E_ZERO = FHE.asEuint64(0);
        FHE.allowThis(E_ZERO);
    }

    // -----------------------------------------------------------------------
    // Disabled OZ wrap paths — deposits must go through initWrap
    // -----------------------------------------------------------------------

    function wrap(address, uint256) public pure override returns (euint64) {
        revert ExternalWrapNotSupported();
    }

    function onTransferReceived(address, address, uint256, bytes calldata) public pure override returns (bytes4) {
        revert ExternalWrapNotSupported();
    }

    // -----------------------------------------------------------------------
    // IERC7984AsyncWrapper: deposit count + unwrap lifecycle
    // -----------------------------------------------------------------------

    /// @inheritdoc IERC7984AsyncWrapper
    function getDepositsLength() external view override returns (uint256) {
        return totalDeposits;
    }

    /// @inheritdoc IERC7984AsyncWrapper
    function initUnwrap(
        externalEuint64 encryptedAmount,
        bytes calldata inputProof,
        address destination
    ) external override {
        if (destination == address(0)) revert ZeroAddress();
        euint64 amount = FHE.fromExternal(encryptedAmount, inputProof);
        FHE.allowThis(amount);
        _unwrap(msg.sender, destination, amount);
    }

    /// @inheritdoc IERC7984AsyncWrapper
    function initUnwrap(uint64 compressedAmount, address destination) external override {
        if (destination == address(0)) revert ZeroAddress();
        if (compressedAmount == 0) revert ZeroAmount();
        euint64 amount = FHE.asEuint64(compressedAmount);
        FHE.allowThis(amount);
        _unwrap(msg.sender, destination, amount);
    }

    // -----------------------------------------------------------------------
    // initWrap: record a write-once deposit, then pull tokens (CEI)
    // -----------------------------------------------------------------------

    /**
     * @notice Record a deposit into the current batch by pulling `amount` underlying
     *         from `depositor` (who must have approved this wrapper). `inputProof`
     *         must bind `eRecipient` to `(this, msg.sender)`.
     *
     *         The caller MUST be the depositor: `eRecipient` is caller-supplied, so a
     *         third party could otherwise spend a standing allowance and route the
     *         wrapped tokens to a recipient of THEIR choosing — hidden, because the
     *         recipient is encrypted. This also matches the proof-binding reality:
     *         the recipient encrypts their address against the depositor as
     *         userAddress, so only the depositor can submit it anyway.
     *
     *         `amount` must be an exact multiple of {rate}: the cleartext amount is
     *         recorded and pulled in full, so a non-multiple would transfer more
     *         underlying in than the floored confidential units minted against it.
     * @return slot Global slot index of the new deposit.
     */
    function initWrap(
        address depositor,
        uint256 amount,
        externalEaddress eRecipient,
        bytes calldata inputProof
    ) external returns (uint256 slot) {
        if (depositor != msg.sender) revert UnauthorizedDepositor();
        if (amount == 0) revert ZeroAmount();
        if (amount % rate() != 0) revert AmountNotMultipleOfRate();
        uint64 compressed = SafeCast.toUint64(amount / rate());
        if (compressed == 0) revert ZeroAmount();

        uint256 batchId = currentBatchId;
        uint256 batchIndex = batchFillCount[batchId];

        eaddress verifiedRecipient = FHE.fromExternal(eRecipient, inputProof);
        euint64 eAmount = FHE.asEuint64(compressed);
        FHE.allowThis(verifiedRecipient);
        FHE.allowThis(eAmount);

        slot = batchId * maxBatchDeposits + batchIndex;
        deposits[slot] = Deposit({
            depositor: depositor,
            amount: amount,
            eAmount: eAmount,
            eRecipient: verifiedRecipient
        });

        batchFillCount[batchId] = batchIndex + 1;
        batchLastDepositAt[batchId] = uint64(block.timestamp);
        totalDeposits += 1;

        // Auto-close and roll over when the batch fills.
        if (batchIndex + 1 == maxBatchDeposits) {
            batchClosed[batchId] = true;
            currentBatchId = batchId + 1;
        }

        emit WrapInitiated(batchId, slot, depositor, amount, FHE.toBytes32(verifiedRecipient));

        // Interactions last (Checks-Effects-Interactions): pull tokens only after the deposit is
        // recorded, so a reentrant initWrap (via a token transfer hook) cannot observe the same
        // fill count, recompute the same `slot`, and have its record overwritten by this call.
        IERC20(underlying()).safeTransferFrom(depositor, address(this), amount);
    }

    // -----------------------------------------------------------------------
    // sealBatch: liveness escape hatch for a tail batch that never fills
    // -----------------------------------------------------------------------

    /**
     * @notice Close the current, still-open batch early so its deposits can be
     *         finalized. Permissionless, but only after `sealDelay` since the last
     *         deposit — the delay stops a griefer from prematurely shrinking the
     *         anonymity set while guaranteeing funds are never stuck.
     */
    function sealBatch(uint256 batchId) external {
        if (batchId != currentBatchId) revert NotCurrentBatch();
        if (batchClosed[batchId]) revert BatchAlreadyClosed();
        uint256 filled = batchFillCount[batchId];
        if (filled == 0) revert NothingToSeal();
        if (block.timestamp < uint256(batchLastDepositAt[batchId]) + sealDelay) revert SealDelayNotElapsed();

        batchClosed[batchId] = true;
        currentBatchId = batchId + 1;

        emit BatchSealed(batchId, filled);
    }

    // -----------------------------------------------------------------------
    // finalizeWrap: scan closed batches, tree-reduce the recipient's matches
    // -----------------------------------------------------------------------

    /**
     * @notice Mint the encrypted sum of every deposit in the given CLOSED batches whose
     *         encrypted recipient equals `recipient`. Permissionless; replay-safe via the
     *         cleartext nullifier (a second call for the same (batch, recipient) reverts).
     *
     *         HCU note: the FHEVM per-tx budget bounds TOTAL SLOTS SCANNED PER CALL
     *         (~56 measured). With `maxBatchDeposits` near the 48 cap, finalize one
     *         batch per call; multi-batch calls suit smaller batch sizes.
     * @param ids Batch ids to finalize — MUST be strictly increasing (no duplicates).
     * @param recipient Address to match deposits against and mint the total to.
     */
    function finalizeWrap(uint256[] calldata ids, address recipient) external override {
        if (recipient == address(0)) revert ZeroAddress();

        // Count scanned slots across batches to size the payout array.
        uint256 totalSlots;
        uint256 prev;
        for (uint256 k = 0; k < ids.length; k++) {
            uint256 batchId = ids[k];
            if (k > 0 && batchId <= prev) revert DuplicateId(); // strictly increasing, no dupes
            prev = batchId;
            if (!batchClosed[batchId]) revert BatchNotClosed();
            if (finalized[batchId][recipient]) revert AlreadyFinalized();
            finalized[batchId][recipient] = true;
            totalSlots += batchFillCount[batchId];
        }

        // Per-slot payouts are independent (depth ~2 each); only the reduction deepens
        // the FHE dependency chain, and the tree keeps that at ceil(log2 N) adds.
        euint64[] memory payouts = new euint64[](totalSlots);
        uint256 p;
        for (uint256 k = 0; k < ids.length; k++) {
            uint256 startIndex = ids[k] * maxBatchDeposits;
            uint256 count = batchFillCount[ids[k]];
            for (uint256 j = 0; j < count; j++) {
                Deposit storage d = deposits[startIndex + j];
                ebool isMatch = FHE.eq(d.eRecipient, recipient);
                payouts[p++] = FHE.select(isMatch, d.eAmount, E_ZERO);
            }
        }

        euint64 total = _sumTree(payouts);

        emit WrapFinalized(recipient, FHE.toBytes32(total), ids);
        _mint(recipient, total);
    }

    // -----------------------------------------------------------------------
    // _sumTree: pairwise (tree) reduction — O(log N) FHE dependency depth
    // -----------------------------------------------------------------------

    /**
     * @dev Reduce `xs` to a single encrypted sum with a pairwise (binary-tree) reduction
     *      instead of a serial fold. Returns E_ZERO when empty.
     *
     *      Why not `for (i) sum = FHE.add(sum, xs[i])`? Both shapes emit the same number
     *      of adds (N-1), but FHEVM meters SEQUENTIAL DEPTH per transaction, not just
     *      total work: every result handle carries depth(result) = opHCU + max(depth of
     *      its inputs), and the tx reverts if any handle reaches 5M. In a serial fold the
     *      accumulator flows through every add, so its depth grows by ~162k per element
     *      and crosses 5M near N = 29. In the tree, each round's adds consume only the
     *      PREVIOUS round's outputs, so any value flows through at most one add per
     *      round: final depth is ceil(log2 N) adds (~1.1M at N = 48), and the batch-size
     *      ceiling moves to the 20M total-HCU budget instead.
     *
     *      Mechanics of a round: pair up neighbours and write each pair's sum to the
     *      front of the array, in place —
     *          xs[0] = xs[0] + xs[1];  xs[1] = xs[2] + xs[3];  xs[2] = xs[4] + xs[5]; ...
     *      i.e. xs[i] = xs[2i] + xs[2i+1] for i < half, where half = ceil(n / 2). Writes
     *      never clobber unread inputs (2i >= i always). If n is odd the last element has
     *      no partner and is carried through unchanged (`r < n` guard) — it just joins a
     *      pair in a later round. The live prefix halves every round: n -> ceil(n/2) ->
     *      ... -> 1, after which xs[0] holds the sum of every original element exactly
     *      once.
     *
     *      Example, n = 5 (a b c d e):
     *          round 1: [a+b, c+d, e]        depth grown by 1 add
     *          round 2: [a+b+c+d, e]         depth grown by 1 add
     *          round 3: [a+b+c+d+e]          depth grown by 1 add  (serial fold: 4 deep)
     */
    function _sumTree(euint64[] memory xs) private returns (euint64) {
        uint256 n = xs.length;
        if (n == 0) return E_ZERO;
        while (n > 1) {
            uint256 half = (n + 1) >> 1;
            for (uint256 i = 0; i < half; i++) {
                uint256 l = i << 1;
                uint256 r = l + 1;
                xs[i] = r < n ? FHE.add(xs[l], xs[r]) : xs[l];
            }
            n = half;
        }
        return xs[0];
    }
}
