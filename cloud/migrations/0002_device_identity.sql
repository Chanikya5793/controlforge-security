CREATE TABLE devices (
  tenant_id TEXT NOT NULL REFERENCES tenants(tenant_id),
  device_id TEXT NOT NULL,
  display_name TEXT NOT NULL,
  status TEXT NOT NULL CHECK (status IN ('pending', 'active', 'degraded', 'revoked')),
  platform TEXT,
  agent_version TEXT,
  first_seen_at TEXT,
  last_seen_at TEXT,
  created_at TEXT NOT NULL,
  revoked_at TEXT,
  PRIMARY KEY (tenant_id, device_id)
);
CREATE INDEX idx_devices_tenant_status ON devices(tenant_id, status, last_seen_at DESC);

ALTER TABLE collector_credentials ADD COLUMN device_id TEXT;
CREATE INDEX idx_collector_credentials_device
  ON collector_credentials(tenant_id, device_id, revoked_at, expires_at);

-- Existing deployed credentials deliberately remain unbound. The next deployment must
-- insert its device row and bind each credential before code requiring device identity is
-- activated. Silently guessing a device identity would weaken the authorization boundary.
