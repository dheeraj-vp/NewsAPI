
-- Create API keys table
CREATE TABLE api_keys (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    client_name TEXT NOT NULL,
    client_email TEXT NOT NULL,
    description TEXT,
    key_hash TEXT NOT NULL UNIQUE,
    tier TEXT NOT NULL DEFAULT 'standard',
    created_at TIMESTAMPTZ NOT NULL,
    last_used TIMESTAMPTZ,
    is_active BOOLEAN NOT NULL DEFAULT TRUE
);

-- Create index for faster lookups
CREATE INDEX idx_api_keys_hash ON api_keys(key_hash);
CREATE INDEX idx_api_keys_email ON api_keys(client_email);
CREATE INDEX idx_api_keys_active ON api_keys(is_active);

-- Row level security policies
ALTER TABLE api_keys ENABLE ROW LEVEL SECURITY;

-- Only allow authenticated service accounts to access this table
CREATE POLICY api_keys_policy ON api_keys
    USING (auth.role() = 'service_role');

-- Add comment for documentation
COMMENT ON TABLE api_keys IS 'Stores client API key information for authentication and rate limiting';