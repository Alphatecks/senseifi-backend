import express from 'express';
import { ethers } from 'ethers';
import { PAYMENT_ABI } from './abi.js';
import {
  buildChargeRequest,
  submitCharge,
  validateChargeBody,
} from './charge.js';

function requiredEnv(name) {
  const value = process.env[name]?.trim();
  if (!value) {
    throw new Error(`${name} must be set`);
  }
  return value;
}

function loadConfig() {
  const chainId = Number(process.env.CHAIN_ID ?? '84532');
  const rpcUrl =
    process.env.RPC_URL?.trim() ||
    (chainId === 84532 ? 'https://sepolia.base.org' : 'https://mainnet.base.org');

  return {
    port: Number(process.env.PORT ?? '8080'),
    apiKey: requiredEnv('RELAYER_API_KEY'),
    privateKey: requiredEnv('RELAYER_PRIVATE_KEY'),
    chainId,
    rpcUrl,
    paymentContract: requiredEnv('PAYMENT_CONTRACT'),
  };
}

function bearerToken(req) {
  const header = req.headers.authorization ?? '';
  const [scheme, token] = header.split(' ');
  if (scheme?.toLowerCase() !== 'bearer' || !token) {
    return null;
  }
  return token.trim();
}

function createApp(config) {
  const provider = new ethers.JsonRpcProvider(config.rpcUrl, config.chainId);
  const wallet = new ethers.Wallet(config.privateKey, provider);
  const contract = new ethers.Contract(
    config.paymentContract,
    PAYMENT_ABI,
    wallet,
  );

  const app = express();
  app.use(express.json({ limit: '64kb' }));

  app.get('/health', async (_req, res) => {
    try {
      const network = await provider.getNetwork();
      const allowed = await contract.relayers(wallet.address);
      res.json({
        ok: true,
        relayer_address: wallet.address,
        chain_id: Number(network.chainId),
        payment_contract: config.paymentContract,
        relayer_allowed_on_contract: Boolean(allowed),
      });
    } catch (err) {
      res.status(503).json({
        ok: false,
        error: err instanceof Error ? err.message : String(err),
      });
    }
  });

  app.post('/charge', async (req, res) => {
    const token = bearerToken(req);
    if (!token || token !== config.apiKey) {
      return res.status(401).json({ error: 'Unauthorized' });
    }

    try {
      const body = validateChargeBody(req.body);
      if (body.chainId !== config.chainId) {
        return res.status(400).json({
          error: `chain_id mismatch: request=${body.chainId} relayer=${config.chainId}`,
        });
      }

      const allowed = await contract.relayers(wallet.address);
      if (!allowed) {
        return res.status(503).json({
          error: `Relayer wallet ${wallet.address} is not allowed on payment contract`,
        });
      }

      const chargeReq = await buildChargeRequest(contract, body);
      const txHash = await submitCharge(contract, chargeReq);

      return res.json({
        tx_hash: txHash,
        relayer_address: wallet.address,
        payer: chargeReq.payer,
        subscription_id_bytes32: chargeReq.subscriptionId,
        charge_id: chargeReq.chargeId,
      });
    } catch (err) {
      if (err && typeof err === 'object' && err.code === 'ALREADY_PROCESSED') {
        return res.status(409).json({ error: err.message });
      }
      console.error('charge failed:', err);
      return res.status(400).json({
        error: err instanceof Error ? err.message : String(err),
      });
    }
  });

  return app;
}

const config = loadConfig();
const app = createApp(config);

app.listen(config.port, () => {
  const wallet = new ethers.Wallet(config.privateKey);
  console.log(
    `senseifi relayer listening on :${config.port} chain=${config.chainId} relayer=${wallet.address}`,
  );
});
