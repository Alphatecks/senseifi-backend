/** Live Base Sepolia deployment (biller role, simpler charge). */
export const BILLER_ABI = [
  'function charge(bytes32 subscriptionId, uint256 amount) external',
  'function getBilling(bytes32 subscriptionId) external view returns (address payer, uint256 maxChargeUsdcRaw, uint256 chargedUsdcRaw, bool active, uint64 updatedAt)',
  'function billers(address biller) external view returns (bool)',
  'function upsertBilling(bytes32 subscriptionId, uint256 maxChargeAmount) external',
];

/** In-repo SenseifiSubscriptionPayments (relayer role + ChargeRequest tuple). */
export const RELAYER_ABI = [
  'function chargeSubscription((bytes32 chargeId, bytes32 subscriptionId, address payer, uint256 amount, uint64 periodStart, uint64 periodEnd) req) external returns (bool success)',
  'function billingBySubscription(bytes32 subscriptionId) external view returns (address payer, uint256 maxChargeAmount, bool active, uint64 updatedAt)',
  'function relayers(address relayer) external view returns (bool)',
  'function processedCharges(bytes32 chargeId) external view returns (bool)',
];
