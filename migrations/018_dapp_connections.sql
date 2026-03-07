-- Connected dApps for Activity Monitor "Connected dApps" tab.
-- Populated when extension/client reports a wallet connecting to a dApp (e.g. Uniswap).
CREATE TABLE IF NOT EXISTS dapp_connections (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    wallet_address VARCHAR(42) NOT NULL,
    domain VARCHAR(255) NOT NULL,
    dapp_name VARCHAR(128) NOT NULL,
    description TEXT,
    tokens TEXT,
    connected_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    last_activity_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    UNIQUE(wallet_address, domain)
);

CREATE INDEX IF NOT EXISTS idx_dapp_connections_wallet ON dapp_connections(wallet_address);
COMMENT ON TABLE dapp_connections IS 'dApps connected per wallet for Activity Monitor; extension/client ingests via API.';
