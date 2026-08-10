-- Fail closed if historical duplicate alert occurrences exist. This index neither
-- rewrites nor removes legacy alerts; production preflight must inspect duplicates
-- before applying the migration.
CREATE UNIQUE INDEX idx_alerts_semantic_occurrence
ON alerts(tenant_id, rule_id, event_id);

CREATE TABLE alert_replay_evaluations (
  tenant_id TEXT NOT NULL,
  evaluation_id TEXT NOT NULL,
  alert_id TEXT NOT NULL,
  mode TEXT NOT NULL CHECK (mode IN ('current', 'original')),
  outcome TEXT NOT NULL CHECK (outcome IN ('same', 'changed', 'no_match')),
  evaluated_rule_version INTEGER,
  evaluated_rule_digest TEXT,
  snapshot_kind TEXT NOT NULL CHECK (snapshot_kind IN ('sigma', 'builtin', 'correlation', 'unavailable')),
  evidence_basis TEXT NOT NULL CHECK (evidence_basis IN ('source_event', 'current_retained_history')),
  result_json TEXT NOT NULL,
  created_by TEXT NOT NULL,
  created_at TEXT NOT NULL,
  PRIMARY KEY (tenant_id, evaluation_id),
  FOREIGN KEY (tenant_id, alert_id) REFERENCES alerts(tenant_id, alert_id)
);
CREATE INDEX idx_alert_replays_alert_time
ON alert_replay_evaluations(tenant_id, alert_id, created_at DESC);

CREATE TRIGGER alert_replay_evaluations_no_update
BEFORE UPDATE ON alert_replay_evaluations
BEGIN
  SELECT RAISE(ABORT, 'alert replay evaluations are append-only');
END;

CREATE TRIGGER alert_replay_evaluations_no_delete
BEFORE DELETE ON alert_replay_evaluations
BEGIN
  SELECT RAISE(ABORT, 'alert replay evaluations are append-only');
END;
