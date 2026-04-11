// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

interface IERC20 {
    function transferFrom(address from, address to, uint256 value) external returns (bool);
    function allowance(address owner, address spender) external view returns (uint256);
    function balanceOf(address account) external view returns (uint256);
}

/// @title SenseifiSubscriptionPayments
/// @notice Non-custodial recurring subscription charging for USDC on Base.
/// @dev Amounts use token native decimals (USDC = 6). Backend should pass 6-decimal amounts.
contract SenseifiSubscriptionPayments {
    struct BillingConfig {
        address payer;
        uint256 maxChargeAmount;
        bool active;
        uint64 updatedAt;
    }

    struct ChargeRequest {
        bytes32 chargeId; // deterministic idempotency key from backend
        bytes32 subscriptionId; // backend subscription reference hashed to bytes32
        address payer;
        uint256 amount;
        uint64 periodStart;
        uint64 periodEnd;
    }

    IERC20 public immutable usdc;
    address public owner;
    address public treasury;
    mapping(address => bool) public relayers;

    mapping(bytes32 => BillingConfig) public billingBySubscription;
    mapping(bytes32 => bool) public processedCharges;

    event OwnerTransferred(address indexed previousOwner, address indexed newOwner);
    event RelayerUpdated(address indexed relayer, bool allowed);
    event TreasuryUpdated(address indexed previousTreasury, address indexed newTreasury);

    event AllowanceUpdated(
        bytes32 indexed subscriptionId,
        address indexed payer,
        uint256 maxChargeAmount,
        bool active
    );

    event ChargeSubmitted(
        bytes32 indexed chargeId,
        bytes32 indexed subscriptionId,
        address indexed payer,
        uint256 amount,
        uint64 periodStart,
        uint64 periodEnd
    );

    event ChargeConfirmed(
        bytes32 indexed chargeId,
        bytes32 indexed subscriptionId,
        address indexed payer,
        uint256 amount,
        address treasury
    );

    event ChargeFailed(
        bytes32 indexed chargeId,
        bytes32 indexed subscriptionId,
        address indexed payer,
        uint256 amount,
        string code
    );

    error Unauthorized();
    error InvalidAddress();
    error InvalidPeriod();
    error InvalidAmount();
    error AlreadyProcessed();

    modifier onlyOwner() {
        if (msg.sender != owner) revert Unauthorized();
        _;
    }

    modifier onlyRelayer() {
        if (!relayers[msg.sender]) revert Unauthorized();
        _;
    }

    constructor(address usdcToken, address treasuryAddress, address initialRelayer) {
        if (usdcToken == address(0) || treasuryAddress == address(0) || initialRelayer == address(0)) {
            revert InvalidAddress();
        }
        usdc = IERC20(usdcToken);
        owner = msg.sender;
        treasury = treasuryAddress;
        relayers[initialRelayer] = true;
        emit OwnerTransferred(address(0), msg.sender);
        emit RelayerUpdated(initialRelayer, true);
        emit TreasuryUpdated(address(0), treasuryAddress);
    }

    /// @notice User registers or updates their recurring payment authorization.
    /// @dev User must separately approve this contract on USDC to at least maxChargeAmount.
    function upsertBilling(bytes32 subscriptionId, uint256 maxChargeAmount) external {
        if (subscriptionId == bytes32(0)) revert InvalidAddress();
        if (maxChargeAmount == 0) revert InvalidAmount();

        billingBySubscription[subscriptionId] = BillingConfig({
            payer: msg.sender,
            maxChargeAmount: maxChargeAmount,
            active: true,
            updatedAt: uint64(block.timestamp)
        });

        emit AllowanceUpdated(subscriptionId, msg.sender, maxChargeAmount, true);
    }

    /// @notice User revokes backend charging for this subscription.
    function revokeBilling(bytes32 subscriptionId) external {
        BillingConfig storage config = billingBySubscription[subscriptionId];
        if (config.payer != msg.sender) revert Unauthorized();
        config.active = false;
        config.updatedAt = uint64(block.timestamp);
        emit AllowanceUpdated(subscriptionId, msg.sender, config.maxChargeAmount, false);
    }

    /// @notice Owner can rotate relayer(s) used by backend infrastructure.
    function setRelayer(address relayer, bool allowed) external onlyOwner {
        if (relayer == address(0)) revert InvalidAddress();
        relayers[relayer] = allowed;
        emit RelayerUpdated(relayer, allowed);
    }

    /// @notice Owner can rotate treasury wallet.
    function setTreasury(address newTreasury) external onlyOwner {
        if (newTreasury == address(0)) revert InvalidAddress();
        address previous = treasury;
        treasury = newTreasury;
        emit TreasuryUpdated(previous, newTreasury);
    }

    /// @notice Owner transfer.
    function transferOwnership(address newOwner) external onlyOwner {
        if (newOwner == address(0)) revert InvalidAddress();
        address previous = owner;
        owner = newOwner;
        emit OwnerTransferred(previous, newOwner);
    }

    /// @notice Relayer executes one idempotent subscription charge.
    /// @return success False for expected business failures, true on successful transfer.
    function chargeSubscription(ChargeRequest calldata req) external onlyRelayer returns (bool success) {
        if (req.chargeId == bytes32(0) || req.subscriptionId == bytes32(0)) revert InvalidAddress();
        if (req.amount == 0) revert InvalidAmount();
        if (req.periodEnd <= req.periodStart) revert InvalidPeriod();
        if (processedCharges[req.chargeId]) revert AlreadyProcessed();

        BillingConfig memory config = billingBySubscription[req.subscriptionId];
        emit ChargeSubmitted(
            req.chargeId,
            req.subscriptionId,
            req.payer,
            req.amount,
            req.periodStart,
            req.periodEnd
        );

        if (!config.active || config.payer != req.payer) {
            emit ChargeFailed(req.chargeId, req.subscriptionId, req.payer, req.amount, "user_revoked");
            return false;
        }
        if (req.amount > config.maxChargeAmount) {
            emit ChargeFailed(req.chargeId, req.subscriptionId, req.payer, req.amount, "insufficient_allowance");
            return false;
        }
        if (usdc.allowance(req.payer, address(this)) < req.amount) {
            emit ChargeFailed(req.chargeId, req.subscriptionId, req.payer, req.amount, "insufficient_allowance");
            return false;
        }
        if (usdc.balanceOf(req.payer) < req.amount) {
            emit ChargeFailed(req.chargeId, req.subscriptionId, req.payer, req.amount, "insufficient_balance");
            return false;
        }

        if (!_safeTransferFrom(address(usdc), req.payer, treasury, req.amount)) {
            emit ChargeFailed(req.chargeId, req.subscriptionId, req.payer, req.amount, "transfer_failed");
            return false;
        }

        processedCharges[req.chargeId] = true;
        emit ChargeConfirmed(req.chargeId, req.subscriptionId, req.payer, req.amount, treasury);
        return true;
    }

    // Supports tokens that either return bool or no return data.
    function _safeTransferFrom(address token, address from, address to, uint256 amount) private returns (bool) {
        (bool success, bytes memory data) = token.call(
            abi.encodeWithSelector(IERC20.transferFrom.selector, from, to, amount)
        );
        if (!success) return false;
        if (data.length == 0) return true;
        if (data.length == 32) return abi.decode(data, (bool));
        return false;
    }
}
