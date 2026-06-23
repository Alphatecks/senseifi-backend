import { ethers } from 'ethers';
import { PAYMENT_ABI } from './abi.js';

/**
 * keccak256(UTF-8 hyphenated UUID) — matches backend `subscription_id_bytes32`.
 */
export function subscriptionIdBytes32(subscriptionUuid) {
  return ethers.keccak256(ethers.toUtf8Bytes(subscriptionUuid.trim()));
}

/**
 * keccak256(UTF-8 idempotency key) — deterministic on-chain charge id.
 * Backend key format: `{subscription_uuid}:{period_start_unix}:{period_end_unix}`
 */
export function chargeIdBytes32(idempotencyKey) {
  return ethers.keccak256(ethers.toUtf8Bytes(idempotencyKey.trim()));
}

export function parseIdempotencyKey(idempotencyKey) {
  const parts = idempotencyKey.trim().split(':');
  if (parts.length < 3) {
    throw new Error(
      'idempotency_key must be `{subscription_uuid}:{period_start_unix}:{period_end_unix}`',
    );
  }
  const periodEnd = parts.pop();
  const periodStart = parts.pop();
  const subscriptionId = parts.join(':');
  if (!subscriptionId || !periodStart || !periodEnd) {
    throw new Error('idempotency_key is missing subscription id or period timestamps');
  }
  return {
    subscriptionId,
    periodStart: BigInt(periodStart),
    periodEnd: BigInt(periodEnd),
  };
}

export function usdcToBaseUnits(amountUsdc) {
  const n = Number(amountUsdc);
  if (!Number.isFinite(n) || n <= 0) {
    throw new Error('amount_usdc must be a positive number');
  }
  return ethers.parseUnits(n.toFixed(6), 6);
}

export function validateChargeBody(body) {
  if (!body || typeof body !== 'object') {
    throw new Error('JSON body is required');
  }
  const idempotencyKey = String(body.idempotency_key ?? '').trim();
  const userId = String(body.user_id ?? '').trim();
  const subscriptionId = String(body.subscription_id ?? '').trim();
  const amountUsdc = body.amount_usdc;
  const chainId = Number(body.chain_id);

  if (!idempotencyKey) throw new Error('idempotency_key is required');
  if (!userId) throw new Error('user_id is required');
  if (!subscriptionId) throw new Error('subscription_id is required');
  if (!Number.isInteger(chainId) || chainId <= 0) {
    throw new Error('chain_id is required');
  }
  if (amountUsdc === undefined || amountUsdc === null) {
    throw new Error('amount_usdc is required');
  }

  return { idempotencyKey, userId, subscriptionId, amountUsdc, chainId };
}

/**
 * @param {import('ethers').Contract} contract
 * @param {object} input
 */
export async function buildChargeRequest(contract, input) {
  const { idempotencyKey, subscriptionId, amountUsdc } = input;
  const { periodStart, periodEnd } = parseIdempotencyKey(idempotencyKey);

  const subscriptionIdHash = subscriptionIdBytes32(subscriptionId);
  const chargeId = chargeIdBytes32(idempotencyKey);
  const amount = usdcToBaseUnits(amountUsdc);

  const billing = await contract.billingBySubscription(subscriptionIdHash);
  const payer = billing.payer ?? billing[0];
  const maxCharge = billing.maxChargeAmount ?? billing[1];
  const active = billing.active ?? billing[2];

  if (!active) {
    throw new Error('On-chain billing is not active for this subscription (upsertBilling missing or revoked)');
  }
  if (!payer || payer === ethers.ZeroAddress) {
    throw new Error('No payer registered on-chain for this subscription');
  }
  if (maxCharge < amount) {
    throw new Error(`On-chain max charge ${maxCharge} is less than requested amount ${amount}`);
  }

  const alreadyProcessed = await contract.processedCharges(chargeId);
  if (alreadyProcessed) {
    const err = new Error('Charge already processed on-chain for this idempotency key');
    err.code = 'ALREADY_PROCESSED';
    throw err;
  }

  return {
    chargeId,
    subscriptionId: subscriptionIdHash,
    payer,
    amount,
    periodStart,
    periodEnd,
  };
}

export async function submitCharge(contract, req) {
  const tx = await contract.chargeSubscription(req);
  const receipt = await tx.wait();
  return receipt.hash;
}
