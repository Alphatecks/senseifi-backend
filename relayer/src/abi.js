/** Minimal ABI for SenseifiSubscriptionPayments (charge + reads). */
export const PAYMENT_ABI = [
  'function chargeSubscription((bytes32 chargeId, bytes32 subscriptionId, address payer, uint256 amount, uint64 periodStart, uint64 periodEnd) req) external returns (bool success)',
  'function billingBySubscription(bytes32 subscriptionId) external view returns (address payer, uint256 maxChargeAmount, bool active, uint64 updatedAt)',
  'function relayers(address relayer) external view returns (bool)',
  'function processedCharges(bytes32 chargeId) external view returns (bool)',
];
