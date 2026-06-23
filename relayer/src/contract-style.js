import { BILLER_ABI, RELAYER_ABI } from './abi.js';

/**
 * @param {import('ethers').Contract} billerProbe
 * @param {import('ethers').Contract} relayerProbe
 * @param {string} walletAddress
 * @param {string | undefined} configured
 */
export async function resolveContractStyle(
  billerProbe,
  relayerProbe,
  walletAddress,
  configured,
) {
  const normalized = configured?.trim().toLowerCase();
  if (normalized === 'biller' || normalized === 'relayer') {
    return normalized;
  }

  try {
    const allowed = await billerProbe.billers(walletAddress);
    if (allowed) {
      return 'biller';
    }
  } catch {
    // not a biller-style contract
  }

  try {
    const allowed = await relayerProbe.relayers(walletAddress);
    if (allowed) {
      return 'relayer';
    }
  } catch {
    // not a relayer-style contract
  }

  throw new Error(
    'Could not detect contract style; set PAYMENT_CONTRACT_STYLE=biller or relayer',
  );
}

export function abiForStyle(style) {
  return style === 'biller' ? BILLER_ABI : RELAYER_ABI;
}
