-- Operational safety for the paid-plan production pilot. Retention deliberately
-- targets only terminal event rows that are not referenced by an alert. Alerts,
-- cases, dispositions, response actions, replay records, and audit evidence are
-- outside the deletion graph and remain preserved.
CREATE INDEX idx_events_terminal_retention
ON events(received_at)
WHERE processed_at IS NOT NULL AND processing_error IS NULL;

CREATE INDEX idx_events_tenant_terminal_retention
ON events(tenant_id, received_at)
WHERE processed_at IS NOT NULL AND processing_error IS NULL;

CREATE INDEX idx_events_tenant_processing_error
ON events(tenant_id, received_at)
WHERE processing_error IS NOT NULL;

CREATE TRIGGER events_conflicting_duplicate_guard
BEFORE INSERT ON events
WHEN EXISTS (
  SELECT 1 FROM events existing
   WHERE existing.tenant_id = NEW.tenant_id
     AND existing.event_id = NEW.event_id
     AND existing.payload_sha256 != NEW.payload_sha256
)
BEGIN
  SELECT RAISE(ABORT, 'conflicting event payload for existing identity');
END;

-- One fixed-window counter per tenant bounds ingestion amplification without an
-- ever-growing rate-limit log.
CREATE TABLE tenant_ingestion_windows (
  tenant_id TEXT NOT NULL REFERENCES tenants(tenant_id),
  scope_type TEXT NOT NULL CHECK (scope_type IN ('tenant', 'device')),
  scope_id TEXT NOT NULL,
  window_started_at TEXT NOT NULL,
  event_count INTEGER NOT NULL CHECK (event_count >= 0),
  event_limit INTEGER NOT NULL CHECK (event_limit >= 1),
  updated_at TEXT NOT NULL,
  CHECK (event_count <= event_limit),
  PRIMARY KEY (tenant_id, scope_type, scope_id)
);

CREATE TRIGGER tenant_ingestion_windows_insert_limit
BEFORE INSERT ON tenant_ingestion_windows
WHEN NEW.event_count > NEW.event_limit
BEGIN
  SELECT RAISE(ABORT, 'ingestion rate limit exceeded');
END;

CREATE TRIGGER tenant_ingestion_windows_update_limit
BEFORE UPDATE ON tenant_ingestion_windows
WHEN NEW.event_count > NEW.event_limit
BEGIN
  SELECT RAISE(ABORT, 'ingestion rate limit exceeded');
END;

-- A singleton operational row keeps the last retention outcome. It contains no
-- event payloads, identities, credentials, or analyst evidence.
CREATE TABLE retention_state (
  singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
  last_started_at TEXT,
  last_completed_at TEXT,
  next_run_at TEXT,
  cutoff_at TEXT,
  deleted_events INTEGER NOT NULL DEFAULT 0 CHECK (deleted_events >= 0),
  last_error TEXT,
  database_size_bytes INTEGER,
  updated_at TEXT NOT NULL
);

INSERT INTO retention_state(singleton, updated_at)
VALUES (1, '1970-01-01T00:00:00.000Z');
