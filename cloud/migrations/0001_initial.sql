PRAGMA foreign_keys = ON;

CREATE TABLE tenants (
  tenant_id TEXT PRIMARY KEY,
  slug TEXT NOT NULL UNIQUE,
  display_name TEXT NOT NULL,
  status TEXT NOT NULL CHECK (status IN ('active', 'suspended')),
  created_at TEXT NOT NULL
);

CREATE TABLE analyst_memberships (
  tenant_id TEXT NOT NULL REFERENCES tenants(tenant_id),
  principal_id TEXT NOT NULL,
  role TEXT NOT NULL CHECK (role IN ('viewer', 'analyst', 'responder', 'admin')),
  created_at TEXT NOT NULL,
  PRIMARY KEY (tenant_id, principal_id)
);
CREATE INDEX idx_memberships_principal ON analyst_memberships(principal_id, tenant_id);

CREATE TABLE collector_credentials (
  credential_id TEXT PRIMARY KEY,
  tenant_id TEXT NOT NULL REFERENCES tenants(tenant_id),
  name TEXT NOT NULL,
  secret_ciphertext TEXT NOT NULL,
  secret_iv TEXT NOT NULL,
  created_at TEXT NOT NULL,
  expires_at TEXT NOT NULL,
  last_used_at TEXT,
  revoked_at TEXT
);
CREATE INDEX idx_collector_credentials_tenant ON collector_credentials(tenant_id);

CREATE TABLE ingestion_nonces (
  credential_id TEXT NOT NULL REFERENCES collector_credentials(credential_id),
  nonce TEXT NOT NULL,
  expires_at TEXT NOT NULL,
  PRIMARY KEY (credential_id, nonce)
);
CREATE INDEX idx_ingestion_nonces_expiry ON ingestion_nonces(expires_at);

CREATE TABLE events (
  tenant_id TEXT NOT NULL REFERENCES tenants(tenant_id),
  event_id TEXT NOT NULL,
  event_type TEXT NOT NULL,
  occurred_at TEXT NOT NULL,
  received_at TEXT NOT NULL,
  actor TEXT NOT NULL,
  source_ip TEXT,
  target TEXT,
  device_id TEXT,
  attributes_json TEXT NOT NULL,
  payload_sha256 TEXT NOT NULL,
  processed_at TEXT,
  processing_error TEXT,
  PRIMARY KEY (tenant_id, event_id)
);
CREATE INDEX idx_events_tenant_time ON events(tenant_id, occurred_at DESC);
CREATE INDEX idx_events_tenant_actor_time ON events(tenant_id, actor, occurred_at DESC);
CREATE INDEX idx_events_tenant_source_time ON events(tenant_id, source_ip, occurred_at DESC);
CREATE INDEX idx_events_unprocessed ON events(tenant_id, received_at) WHERE processed_at IS NULL;

CREATE TABLE alerts (
  tenant_id TEXT NOT NULL REFERENCES tenants(tenant_id),
  alert_id TEXT NOT NULL,
  event_id TEXT NOT NULL,
  rule_id TEXT NOT NULL,
  title TEXT NOT NULL,
  severity TEXT NOT NULL CHECK (severity IN ('informational', 'low', 'medium', 'high', 'critical')),
  actor TEXT NOT NULL,
  reasons_json TEXT NOT NULL,
  tags_json TEXT NOT NULL,
  created_at TEXT NOT NULL,
  PRIMARY KEY (tenant_id, alert_id),
  FOREIGN KEY (tenant_id, event_id) REFERENCES events(tenant_id, event_id)
);
CREATE INDEX idx_alerts_tenant_time ON alerts(tenant_id, created_at DESC);
CREATE INDEX idx_alerts_tenant_severity ON alerts(tenant_id, severity, created_at DESC);

CREATE TABLE cases (
  tenant_id TEXT NOT NULL REFERENCES tenants(tenant_id),
  case_id TEXT NOT NULL,
  title TEXT NOT NULL,
  priority TEXT NOT NULL CHECK (priority IN ('low', 'medium', 'high', 'critical')),
  status TEXT NOT NULL CHECK (status IN ('open', 'investigating', 'contained', 'closed')),
  opened_at TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  closed_at TEXT,
  PRIMARY KEY (tenant_id, case_id)
);
CREATE INDEX idx_cases_tenant_status ON cases(tenant_id, status, updated_at DESC);

CREATE TABLE case_alerts (
  tenant_id TEXT NOT NULL,
  case_id TEXT NOT NULL,
  alert_id TEXT NOT NULL,
  linked_at TEXT NOT NULL,
  PRIMARY KEY (tenant_id, case_id, alert_id),
  FOREIGN KEY (tenant_id, case_id) REFERENCES cases(tenant_id, case_id),
  FOREIGN KEY (tenant_id, alert_id) REFERENCES alerts(tenant_id, alert_id)
);

CREATE TABLE triage_assessments (
  tenant_id TEXT NOT NULL,
  assessment_id TEXT NOT NULL,
  alert_id TEXT NOT NULL,
  model TEXT NOT NULL,
  assessment_json TEXT NOT NULL,
  created_by TEXT NOT NULL,
  created_at TEXT NOT NULL,
  PRIMARY KEY (tenant_id, assessment_id),
  FOREIGN KEY (tenant_id, alert_id) REFERENCES alerts(tenant_id, alert_id)
);

CREATE TABLE response_actions (
  tenant_id TEXT NOT NULL,
  action_id TEXT NOT NULL,
  case_id TEXT NOT NULL,
  action_type TEXT NOT NULL CHECK (action_type IN (
    'collect_diagnostics', 'enrich_indicator', 'isolate_endpoint',
    'release_endpoint', 'disable_identity', 'revoke_sessions'
  )),
  target_type TEXT NOT NULL CHECK (target_type IN ('device', 'identity', 'indicator')),
  target_id TEXT NOT NULL,
  rationale TEXT NOT NULL,
  risk_level TEXT NOT NULL CHECK (risk_level IN ('read_only', 'active', 'high_impact')),
  status TEXT NOT NULL CHECK (status IN (
    'proposed', 'approved', 'rejected', 'dispatched', 'succeeded', 'failed', 'expired'
  )),
  proposed_by TEXT NOT NULL,
  proposed_at TEXT NOT NULL,
  approved_by TEXT,
  approved_at TEXT,
  expires_at TEXT NOT NULL,
  result_json TEXT,
  completed_at TEXT,
  PRIMARY KEY (tenant_id, action_id),
  FOREIGN KEY (tenant_id, case_id) REFERENCES cases(tenant_id, case_id)
);
CREATE INDEX idx_actions_dispatch ON response_actions(tenant_id, target_id, status, expires_at);

CREATE TABLE audit_log (
  sequence INTEGER PRIMARY KEY AUTOINCREMENT,
  audit_id TEXT NOT NULL UNIQUE,
  tenant_id TEXT NOT NULL,
  action TEXT NOT NULL,
  actor_type TEXT NOT NULL,
  actor_id TEXT NOT NULL,
  resource_type TEXT NOT NULL,
  resource_id TEXT NOT NULL,
  payload_json TEXT NOT NULL,
  integrity_hmac TEXT NOT NULL,
  created_at TEXT NOT NULL
);
CREATE INDEX idx_audit_tenant_time ON audit_log(tenant_id, created_at DESC);

CREATE TRIGGER audit_log_no_update
BEFORE UPDATE ON audit_log
BEGIN
  SELECT RAISE(ABORT, 'audit_log is append-only');
END;

CREATE TRIGGER audit_log_no_delete
BEFORE DELETE ON audit_log
BEGIN
  SELECT RAISE(ABORT, 'audit_log is append-only');
END;
