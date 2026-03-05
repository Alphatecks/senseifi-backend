-- Contract DNA fingerprinting: bytecode/ABI/opcode hashes for malware-style detection.
CREATE TABLE IF NOT EXISTS contract_fingerprints (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    contract_address VARCHAR(42) NOT NULL UNIQUE,
    bytecode_hash VARCHAR(64) NOT NULL,
    abi_pattern_hash VARCHAR(64),
    family VARCHAR(64),
    known_attack_type VARCHAR(64),
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_contract_fingerprints_bytecode_hash ON contract_fingerprints(bytecode_hash);
CREATE INDEX IF NOT EXISTS idx_contract_fingerprints_family ON contract_fingerprints(family);

COMMENT ON TABLE contract_fingerprints IS 'Contract DNA: hashes and families for drainer/honeypot/proxy detection.';
