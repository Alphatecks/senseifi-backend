import express from 'express';
import { ethers } from 'ethers';
import { BILLER_ABI, RELAYER_ABI } from './abi.js';
import { abiForStyle, resolveContractStyle } from './contract-style.js';
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
    contractStyle: process.env.PAYMENT_CONTRACT_STYLE?.trim(),
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

async function createRuntime(config) {
  const provider = new ethers.JsonRpcProvider(config.rpcUrl, config.chainId);
  const wallet = new ethers.Wallet(config.privateKey, provider);
  const billerProbe = new ethers.Contract(
    config.paymentContract,
    BILLER_ABI,
    provider,
  );
  const relayerProbe = new ethers.Contract(
    config.paymentContract,
    RELAYER_ABI,
    provider,
  );

  const contractStyle = await resolveContractStyle(
    billerProbe,
    relayerProbe,
    wallet.address,
    config.contractStyle,
  );
  const contract = new ethers.Contract(
    config.paymentContract,
    abiForStyle(contractStyle),
    wallet,
  );

  let operatorAllowed = false;
  if (contractStyle === 'biller') {
    operatorAllowed = Boolean(await contract.billers(wallet.address));
  } else {
    operatorAllowed = Boolean(await contract.relayers(wallet.address));
  }

  return { provider, wallet, contract, contractStyle, operatorAllowed };
}

function createApp(runtime, config) {
  const { provider, wallet, contract, contractStyle, operatorAllowed } = runtime;

  const app = express();
  app.use(express.json({ limit: '64kb' }));

  app.get('/health', async (_req, res) => {
    try {
      const network = await provider.getNetwork();
      res.json({
        ok: true,
        contract_style: contractStyle,
        operator_address: wallet.address,
        relayer_address: wallet.address,
        chain_id: Number(network.chainId),
        payment_contract: config.paymentContract,
        operator_allowed_on_contract: operatorAllowed,
        relayer_allowed_on_contract: operatorAllowed,
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

      if (!operatorAllowed) {
        return res.status(503).json({
          error: `${contractStyle} wallet ${wallet.address} is not allowed on payment contract`,
        });
      }

      const chargeReq = await buildChargeRequest(contract, body, contractStyle);
      const txHash = await submitCharge(contract, chargeReq);

      return res.json({
        tx_hash: txHash,
        contract_style: contractStyle,
        operator_address: wallet.address,
        relayer_address: wallet.address,
        payer: chargeReq.payer,
        subscription_id_bytes32: chargeReq.subscriptionId,
        charge_id: chargeReq.chargeId ?? null,
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
const runtime = await createRuntime(config);
const app = createApp(runtime, config);

app.listen(config.port, () => {
  console.log(
    `senseifi relayer listening on :${config.port} chain=${config.chainId} style=${runtime.contractStyle} operator=${runtime.wallet.address}`,
  );
});
