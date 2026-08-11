"""Ordered SQLite migrations for the standalone control plane."""

from dataclasses import dataclass


@dataclass(frozen=True)
class Migration:
    version: int
    name: str
    sql: str


INITIAL_SCHEMA = r"""
CREATE TABLE tenants (
    tenant_id TEXT PRIMARY KEY,
    slug TEXT NOT NULL UNIQUE,
    display_name TEXT NOT NULL,
    status TEXT NOT NULL CHECK (status IN ('active', 'suspended')),
    created_at TEXT NOT NULL
);

CREATE TABLE users (
    tenant_id TEXT NOT NULL REFERENCES tenants(tenant_id),
    user_id TEXT NOT NULL,
    email TEXT NOT NULL,
    display_name TEXT NOT NULL,
    role TEXT NOT NULL CHECK (role IN ('viewer', 'analyst', 'responder', 'admin')),
    status TEXT NOT NULL CHECK (status IN ('invited', 'active', 'disabled')),
    created_at TEXT NOT NULL,
    PRIMARY KEY (tenant_id, user_id),
    UNIQUE (tenant_id, email)
);

CREATE TABLE sessions (
    tenant_id TEXT NOT NULL,
    session_id TEXT NOT NULL,
    user_id TEXT NOT NULL,
    secret_hash TEXT NOT NULL,
    csrf_hash TEXT NOT NULL,
    created_at TEXT NOT NULL,
    expires_at TEXT NOT NULL,
    last_seen_at TEXT NOT NULL,
    revoked_at TEXT,
    PRIMARY KEY (tenant_id, session_id),
    UNIQUE (session_id),
    FOREIGN KEY (tenant_id, user_id) REFERENCES users(tenant_id, user_id)
);
CREATE INDEX idx_sessions_expiry ON sessions(tenant_id, expires_at);

CREATE TABLE passkey_credentials (
    tenant_id TEXT NOT NULL,
    user_id TEXT NOT NULL,
    credential_id TEXT NOT NULL,
    public_key BLOB NOT NULL,
    sign_count INTEGER NOT NULL CHECK (sign_count >= 0),
    label TEXT NOT NULL,
    created_at TEXT NOT NULL,
    last_used_at TEXT,
    revoked_at TEXT,
    PRIMARY KEY (tenant_id, credential_id),
    FOREIGN KEY (tenant_id, user_id) REFERENCES users(tenant_id, user_id)
);
CREATE INDEX idx_passkeys_user ON passkey_credentials(tenant_id, user_id, revoked_at);

CREATE TABLE bootstrap_tokens (
    token_hash TEXT PRIMARY KEY,
    created_at TEXT NOT NULL,
    expires_at TEXT NOT NULL,
    used_at TEXT,
    revoked_at TEXT
);

CREATE TABLE auth_challenges (
    challenge_id TEXT PRIMARY KEY,
    tenant_id TEXT,
    user_id TEXT,
    purpose TEXT NOT NULL CHECK (purpose IN ('bootstrap', 'registration', 'authentication')),
    challenge_b64 TEXT NOT NULL,
    context_json TEXT NOT NULL,
    created_at TEXT NOT NULL,
    expires_at TEXT NOT NULL,
    consumed_at TEXT,
    FOREIGN KEY (tenant_id, user_id) REFERENCES users(tenant_id, user_id)
);
CREATE INDEX idx_auth_challenges_expiry ON auth_challenges(expires_at, consumed_at);

CREATE TABLE recovery_codes (
    tenant_id TEXT NOT NULL,
    user_id TEXT NOT NULL,
    code_hash TEXT NOT NULL,
    created_at TEXT NOT NULL,
    used_at TEXT,
    PRIMARY KEY (tenant_id, code_hash),
    FOREIGN KEY (tenant_id, user_id) REFERENCES users(tenant_id, user_id)
);

CREATE TABLE devices (
    tenant_id TEXT NOT NULL REFERENCES tenants(tenant_id),
    device_id TEXT NOT NULL,
    display_name TEXT NOT NULL,
    platform TEXT NOT NULL,
    status TEXT NOT NULL CHECK (status IN ('enrolling', 'active', 'revoked')),
    enrolled_at TEXT,
    last_seen_at TEXT,
    revoked_at TEXT,
    PRIMARY KEY (tenant_id, device_id)
);
CREATE INDEX idx_devices_status ON devices(tenant_id, status, last_seen_at);

CREATE TABLE device_credentials (
    credential_id TEXT PRIMARY KEY,
    tenant_id TEXT NOT NULL,
    device_id TEXT NOT NULL,
    name TEXT NOT NULL,
    secret_ciphertext TEXT NOT NULL,
    secret_iv TEXT NOT NULL,
    created_at TEXT NOT NULL,
    expires_at TEXT NOT NULL,
    last_used_at TEXT,
    revoked_at TEXT,
    FOREIGN KEY (tenant_id, device_id) REFERENCES devices(tenant_id, device_id)
);
CREATE INDEX idx_device_credentials_device
    ON device_credentials(tenant_id, device_id, expires_at);

CREATE TABLE device_auth_nonces (
    credential_id TEXT NOT NULL REFERENCES device_credentials(credential_id),
    nonce TEXT NOT NULL,
    expires_at TEXT NOT NULL,
    PRIMARY KEY (credential_id, nonce)
);
CREATE INDEX idx_device_auth_nonces_expiry ON device_auth_nonces(expires_at);

CREATE TABLE enrollment_tokens (
    token_id TEXT PRIMARY KEY,
    tenant_id TEXT NOT NULL REFERENCES tenants(tenant_id),
    token_hash TEXT NOT NULL UNIQUE,
    expected_device_id TEXT,
    created_by TEXT NOT NULL,
    created_at TEXT NOT NULL,
    expires_at TEXT NOT NULL,
    used_at TEXT,
    revoked_at TEXT
);
CREATE INDEX idx_enrollment_tokens_expiry ON enrollment_tokens(tenant_id, expires_at);

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
    payload_json TEXT NOT NULL,
    payload_sha256 TEXT NOT NULL,
    PRIMARY KEY (tenant_id, event_id),
    FOREIGN KEY (tenant_id, device_id) REFERENCES devices(tenant_id, device_id)
);
CREATE INDEX idx_events_time ON events(tenant_id, occurred_at DESC);
CREATE INDEX idx_events_actor_time ON events(tenant_id, actor, occurred_at DESC);
CREATE INDEX idx_events_device_time ON events(tenant_id, device_id, occurred_at DESC);

CREATE TABLE detection_jobs (
    tenant_id TEXT NOT NULL,
    job_id TEXT NOT NULL,
    event_id TEXT NOT NULL,
    status TEXT NOT NULL CHECK (
        status IN ('pending', 'leased', 'retry', 'succeeded', 'dead')
    ),
    attempts INTEGER NOT NULL DEFAULT 0 CHECK (attempts >= 0),
    available_at TEXT NOT NULL,
    lease_owner TEXT,
    lease_expires_at TEXT,
    last_error TEXT,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    PRIMARY KEY (tenant_id, job_id),
    UNIQUE (tenant_id, event_id),
    FOREIGN KEY (tenant_id, event_id) REFERENCES events(tenant_id, event_id)
);
CREATE INDEX idx_detection_jobs_ready
    ON detection_jobs(tenant_id, status, available_at, lease_expires_at);

CREATE TABLE alerts (
    tenant_id TEXT NOT NULL,
    alert_id TEXT NOT NULL,
    event_id TEXT NOT NULL,
    rule_id TEXT NOT NULL,
    rule_version TEXT NOT NULL,
    rule_digest TEXT NOT NULL,
    rule_snapshot_json TEXT NOT NULL,
    fingerprint_version TEXT NOT NULL,
    detector_version TEXT NOT NULL,
    title TEXT NOT NULL,
    severity TEXT NOT NULL CHECK (
        severity IN ('informational', 'low', 'medium', 'high', 'critical')
    ),
    actor TEXT NOT NULL,
    reasons_json TEXT NOT NULL,
    tags_json TEXT NOT NULL,
    evidence_json TEXT NOT NULL,
    created_at TEXT NOT NULL,
    PRIMARY KEY (tenant_id, alert_id),
    FOREIGN KEY (tenant_id, event_id) REFERENCES events(tenant_id, event_id)
);
CREATE INDEX idx_alerts_time ON alerts(tenant_id, created_at DESC);
CREATE INDEX idx_alerts_severity ON alerts(tenant_id, severity, created_at DESC);

CREATE TABLE detection_replays (
    tenant_id TEXT NOT NULL,
    replay_id TEXT NOT NULL,
    alert_id TEXT NOT NULL,
    requested_by TEXT NOT NULL,
    replay_mode TEXT NOT NULL CHECK (replay_mode IN ('original', 'current')),
    rule_id TEXT NOT NULL,
    rule_version TEXT NOT NULL,
    rule_digest TEXT NOT NULL,
    detector_version TEXT NOT NULL,
    outcome TEXT NOT NULL CHECK (outcome IN ('same', 'changed', 'unavailable')),
    result_json TEXT NOT NULL,
    created_at TEXT NOT NULL,
    PRIMARY KEY (tenant_id, replay_id),
    FOREIGN KEY (tenant_id, alert_id) REFERENCES alerts(tenant_id, alert_id)
);
CREATE INDEX idx_detection_replays_alert
    ON detection_replays(tenant_id, alert_id, created_at DESC);

CREATE TABLE cases (
    tenant_id TEXT NOT NULL REFERENCES tenants(tenant_id),
    case_id TEXT NOT NULL,
    title TEXT NOT NULL,
    priority TEXT NOT NULL CHECK (priority IN ('low', 'medium', 'high', 'critical')),
    status TEXT NOT NULL CHECK (
        status IN ('open', 'investigating', 'contained', 'closed')
    ),
    assignee_user_id TEXT,
    opened_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    closed_at TEXT,
    PRIMARY KEY (tenant_id, case_id),
    FOREIGN KEY (tenant_id, assignee_user_id) REFERENCES users(tenant_id, user_id)
);
CREATE INDEX idx_cases_status ON cases(tenant_id, status, updated_at DESC);

CREATE TABLE case_alerts (
    tenant_id TEXT NOT NULL,
    case_id TEXT NOT NULL,
    alert_id TEXT NOT NULL,
    linked_at TEXT NOT NULL,
    PRIMARY KEY (tenant_id, case_id, alert_id),
    FOREIGN KEY (tenant_id, case_id) REFERENCES cases(tenant_id, case_id),
    FOREIGN KEY (tenant_id, alert_id) REFERENCES alerts(tenant_id, alert_id)
);

CREATE TABLE case_activity (
    tenant_id TEXT NOT NULL,
    activity_id TEXT NOT NULL,
    case_id TEXT NOT NULL,
    activity_type TEXT NOT NULL,
    actor_id TEXT NOT NULL,
    body_json TEXT NOT NULL,
    created_at TEXT NOT NULL,
    PRIMARY KEY (tenant_id, activity_id),
    FOREIGN KEY (tenant_id, case_id) REFERENCES cases(tenant_id, case_id)
);
CREATE INDEX idx_case_activity_time ON case_activity(tenant_id, case_id, created_at);

CREATE TABLE dispositions (
    tenant_id TEXT NOT NULL,
    disposition_id TEXT NOT NULL,
    case_id TEXT NOT NULL,
    status TEXT NOT NULL CHECK (
        status IN ('true_positive', 'false_positive', 'benign', 'inconclusive')
    ),
    rationale TEXT NOT NULL,
    rule_version TEXT NOT NULL,
    created_by TEXT NOT NULL,
    created_at TEXT NOT NULL,
    PRIMARY KEY (tenant_id, disposition_id),
    FOREIGN KEY (tenant_id, case_id) REFERENCES cases(tenant_id, case_id)
);

CREATE TABLE response_actions (
    tenant_id TEXT NOT NULL,
    action_id TEXT NOT NULL,
    case_id TEXT NOT NULL,
    action_type TEXT NOT NULL,
    target_type TEXT NOT NULL CHECK (target_type IN ('device', 'identity', 'indicator')),
    target_id TEXT NOT NULL,
    rationale TEXT NOT NULL,
    risk_level TEXT NOT NULL CHECK (risk_level IN ('read_only', 'active', 'high_impact')),
    status TEXT NOT NULL CHECK (
        status IN (
            'proposed', 'approved', 'rejected', 'dispatched',
            'succeeded', 'failed', 'expired'
        )
    ),
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
CREATE INDEX idx_response_dispatch
    ON response_actions(tenant_id, target_type, target_id, status, expires_at);

CREATE TABLE audit_log (
    sequence INTEGER PRIMARY KEY AUTOINCREMENT,
    audit_id TEXT NOT NULL UNIQUE,
    tenant_id TEXT NOT NULL REFERENCES tenants(tenant_id),
    action TEXT NOT NULL,
    actor_type TEXT NOT NULL,
    actor_id TEXT NOT NULL,
    resource_type TEXT NOT NULL,
    resource_id TEXT NOT NULL,
    payload_json TEXT NOT NULL,
    previous_hmac TEXT,
    integrity_hmac TEXT NOT NULL,
    created_at TEXT NOT NULL
);
CREATE INDEX idx_audit_time ON audit_log(tenant_id, sequence);

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

CREATE TABLE audit_checkpoints (
    checkpoint_id TEXT PRIMARY KEY,
    tenant_id TEXT NOT NULL REFERENCES tenants(tenant_id),
    through_sequence INTEGER NOT NULL,
    terminal_hmac TEXT NOT NULL,
    signature TEXT NOT NULL,
    created_at TEXT NOT NULL,
    UNIQUE (tenant_id, through_sequence)
);

CREATE TABLE backup_history (
    backup_id TEXT PRIMARY KEY,
    tenant_id TEXT NOT NULL REFERENCES tenants(tenant_id),
    status TEXT NOT NULL CHECK (status IN ('started', 'succeeded', 'failed', 'restored')),
    destination TEXT NOT NULL,
    sha256 TEXT,
    size_bytes INTEGER CHECK (size_bytes IS NULL OR size_bytes >= 0),
    error_summary TEXT,
    started_at TEXT NOT NULL,
    completed_at TEXT
);
CREATE INDEX idx_backup_history_time ON backup_history(tenant_id, started_at DESC);

CREATE TABLE appliance_state (
    state_key TEXT PRIMARY KEY,
    value_json TEXT NOT NULL,
    updated_at TEXT NOT NULL
);
"""


CASE_AUDIT_SCHEMA = r"""
ALTER TABLE cases
ADD COLUMN version INTEGER NOT NULL DEFAULT 1 CHECK (version >= 1);

ALTER TABLE dispositions
ADD COLUMN false_positive_reason TEXT;

CREATE INDEX idx_dispositions_case_time
    ON dispositions(tenant_id, case_id, created_at DESC);

CREATE INDEX idx_audit_resource
    ON audit_log(tenant_id, resource_type, resource_id, sequence);

CREATE TRIGGER cases_status_transition_guard
BEFORE UPDATE OF status ON cases
WHEN NOT (
    (OLD.status = 'open' AND NEW.status IN ('investigating', 'closed')) OR
    (OLD.status = 'investigating' AND NEW.status IN ('contained', 'closed')) OR
    (OLD.status = 'contained' AND NEW.status IN ('investigating', 'closed')) OR
    (OLD.status = 'closed' AND NEW.status = 'open')
)
BEGIN
    SELECT RAISE(ABORT, 'invalid case status transition');
END;

CREATE TRIGGER cases_status_version_guard
BEFORE UPDATE OF status ON cases
WHEN NEW.version != OLD.version + 1
BEGIN
    SELECT RAISE(ABORT, 'case status transition must increment version');
END;

CREATE TRIGGER cases_close_requires_disposition
BEFORE UPDATE OF status ON cases
WHEN NEW.status = 'closed' AND NOT EXISTS (
    SELECT 1 FROM dispositions
    WHERE tenant_id = OLD.tenant_id AND case_id = OLD.case_id
)
BEGIN
    SELECT RAISE(ABORT, 'case cannot close without a disposition');
END;

CREATE TRIGGER dispositions_false_positive_reason_guard
BEFORE INSERT ON dispositions
WHEN (
    NEW.status = 'false_positive' AND (
        NEW.false_positive_reason IS NULL OR length(trim(NEW.false_positive_reason)) = 0
    )
) OR (
    NEW.status != 'false_positive' AND NEW.false_positive_reason IS NOT NULL
)
BEGIN
    SELECT RAISE(ABORT, 'false-positive reason does not match disposition');
END;

CREATE TRIGGER case_activity_no_update
BEFORE UPDATE ON case_activity
BEGIN
    SELECT RAISE(ABORT, 'case_activity is append-only');
END;

CREATE TRIGGER case_activity_no_delete
BEFORE DELETE ON case_activity
BEGIN
    SELECT RAISE(ABORT, 'case_activity is append-only');
END;

CREATE TRIGGER dispositions_no_update
BEFORE UPDATE ON dispositions
BEGIN
    SELECT RAISE(ABORT, 'dispositions is append-only');
END;

CREATE TRIGGER dispositions_no_delete
BEFORE DELETE ON dispositions
BEGIN
    SELECT RAISE(ABORT, 'dispositions is append-only');
END;

CREATE TRIGGER audit_checkpoints_no_update
BEFORE UPDATE ON audit_checkpoints
BEGIN
    SELECT RAISE(ABORT, 'audit_checkpoints is append-only');
END;

CREATE TRIGGER audit_checkpoints_no_delete
BEFORE DELETE ON audit_checkpoints
BEGIN
    SELECT RAISE(ABORT, 'audit_checkpoints is append-only');
END;
"""


RESUMABLE_ENROLLMENT_SCHEMA = r"""
ALTER TABLE enrollment_tokens
ADD COLUMN claimed_device_id TEXT;

CREATE INDEX idx_enrollment_tokens_claimed_device
    ON enrollment_tokens(tenant_id, claimed_device_id, expires_at);
"""


ACTIVE_RESPONSE_GOVERNANCE_SCHEMA = r"""
CREATE TABLE human_invites (
    invite_id TEXT PRIMARY KEY,
    tenant_id TEXT NOT NULL REFERENCES tenants(tenant_id),
    token_hash TEXT NOT NULL UNIQUE,
    email TEXT NOT NULL,
    display_name TEXT NOT NULL,
    role TEXT NOT NULL CHECK (role IN ('responder', 'admin')),
    created_by TEXT NOT NULL,
    created_at TEXT NOT NULL,
    expires_at TEXT NOT NULL,
    consumed_at TEXT,
    revoked_at TEXT,
    FOREIGN KEY (tenant_id, created_by) REFERENCES users(tenant_id, user_id)
);
CREATE INDEX idx_human_invites_active
    ON human_invites(tenant_id, email, expires_at, consumed_at, revoked_at);

CREATE TABLE human_invite_challenges (
    challenge_id TEXT PRIMARY KEY,
    invite_id TEXT NOT NULL REFERENCES human_invites(invite_id),
    user_id TEXT NOT NULL,
    challenge_b64 TEXT NOT NULL,
    created_at TEXT NOT NULL,
    expires_at TEXT NOT NULL,
    consumed_at TEXT
);
CREATE INDEX idx_human_invite_challenges_expiry
    ON human_invite_challenges(invite_id, expires_at, consumed_at);

CREATE TRIGGER human_invite_identity_immutable
BEFORE UPDATE ON human_invites
WHEN NEW.invite_id IS NOT OLD.invite_id
  OR NEW.tenant_id IS NOT OLD.tenant_id
  OR NEW.token_hash IS NOT OLD.token_hash
  OR NEW.email IS NOT OLD.email
  OR NEW.display_name IS NOT OLD.display_name
  OR NEW.role IS NOT OLD.role
  OR NEW.created_by IS NOT OLD.created_by
  OR NEW.created_at IS NOT OLD.created_at
  OR NEW.expires_at IS NOT OLD.expires_at
BEGIN
    SELECT RAISE(ABORT, 'human invite identity is immutable');
END;

CREATE TRIGGER human_invite_no_delete
BEFORE DELETE ON human_invites
BEGIN
    SELECT RAISE(ABORT, 'human invites are append-only');
END;

CREATE TRIGGER human_invite_challenge_identity_immutable
BEFORE UPDATE ON human_invite_challenges
WHEN NEW.challenge_id IS NOT OLD.challenge_id
  OR NEW.invite_id IS NOT OLD.invite_id
  OR NEW.user_id IS NOT OLD.user_id
  OR NEW.challenge_b64 IS NOT OLD.challenge_b64
  OR NEW.created_at IS NOT OLD.created_at
  OR NEW.expires_at IS NOT OLD.expires_at
BEGIN
    SELECT RAISE(ABORT, 'human invite challenge identity is immutable');
END;

CREATE TRIGGER human_invite_challenge_no_delete
BEFORE DELETE ON human_invite_challenges
BEGIN
    SELECT RAISE(ABORT, 'human invite challenges are append-only');
END;

ALTER TABLE response_actions
ADD COLUMN rejected_by TEXT;

ALTER TABLE response_actions
ADD COLUMN rejected_at TEXT;

ALTER TABLE response_actions
ADD COLUMN rejection_reason TEXT;

ALTER TABLE response_actions
ADD COLUMN dispatch_count INTEGER NOT NULL DEFAULT 0
CHECK (dispatch_count >= 0 AND dispatch_count <= 5);

ALTER TABLE response_actions
ADD COLUMN dispatched_at TEXT;

ALTER TABLE response_actions
ADD COLUMN result_device_id TEXT;

CREATE UNIQUE INDEX idx_response_one_live_device
    ON response_actions(tenant_id, target_id)
    WHERE target_type = 'device'
      AND status IN ('proposed', 'approved', 'dispatched');

CREATE TRIGGER response_action_identity_immutable
BEFORE UPDATE ON response_actions
WHEN NEW.tenant_id IS NOT OLD.tenant_id
  OR NEW.action_id IS NOT OLD.action_id
  OR NEW.case_id IS NOT OLD.case_id
  OR NEW.action_type IS NOT OLD.action_type
  OR NEW.target_type IS NOT OLD.target_type
  OR NEW.target_id IS NOT OLD.target_id
  OR NEW.rationale IS NOT OLD.rationale
  OR NEW.risk_level IS NOT OLD.risk_level
  OR NEW.proposed_by IS NOT OLD.proposed_by
  OR NEW.proposed_at IS NOT OLD.proposed_at
  OR NEW.expires_at IS NOT OLD.expires_at
BEGIN
    SELECT RAISE(ABORT, 'response action identity is immutable');
END;

CREATE TRIGGER response_action_transition_guard
BEFORE UPDATE OF status ON response_actions
WHEN NOT (
    (OLD.status = 'proposed' AND NEW.status IN ('approved', 'rejected', 'expired')) OR
    (OLD.status = 'approved' AND NEW.status IN ('dispatched', 'expired')) OR
    (OLD.status = 'dispatched' AND NEW.status IN ('succeeded', 'failed', 'expired'))
)
BEGIN
    SELECT RAISE(ABORT, 'invalid response action transition');
END;

CREATE TRIGGER response_action_approval_guard
BEFORE UPDATE OF status ON response_actions
WHEN NEW.status = 'approved' AND (
    NEW.approved_by IS NULL
    OR NEW.approved_at IS NULL
    OR NEW.approved_by = OLD.proposed_by
    OR NEW.approved_at >= OLD.expires_at
)
BEGIN
    SELECT RAISE(ABORT, 'response approval requires an independent human');
END;

CREATE TRIGGER response_action_rejection_guard
BEFORE UPDATE OF status ON response_actions
WHEN NEW.status = 'rejected' AND (
    NEW.rejected_by IS NULL
    OR NEW.rejected_at IS NULL
    OR NEW.rejected_by = OLD.proposed_by
    OR NEW.rejected_at >= OLD.expires_at
    OR NEW.rejection_reason IS NULL
    OR length(trim(NEW.rejection_reason)) = 0
)
BEGIN
    SELECT RAISE(ABORT, 'response rejection requires an independent human and reason');
END;

CREATE TRIGGER response_action_dispatch_guard
BEFORE UPDATE OF status ON response_actions
WHEN NEW.status = 'dispatched' AND (
    OLD.status != 'approved'
    OR NEW.dispatched_at IS NULL
    OR NEW.dispatch_count != 1
    OR NEW.dispatched_at >= OLD.expires_at
)
BEGIN
    SELECT RAISE(ABORT, 'response dispatch is invalid');
END;

CREATE TRIGGER response_action_result_guard
BEFORE UPDATE OF status ON response_actions
WHEN NEW.status IN ('succeeded', 'failed') AND (
    OLD.status != 'dispatched'
    OR NEW.result_json IS NULL
    OR NEW.result_device_id IS NULL
    OR NEW.result_device_id != OLD.target_id
    OR NEW.completed_at IS NULL
    OR NEW.completed_at >= OLD.expires_at
)
BEGIN
    SELECT RAISE(ABORT, 'response result is not bound to the target device');
END;

CREATE TRIGGER response_action_terminal_immutable
BEFORE UPDATE ON response_actions
WHEN OLD.status IN ('rejected', 'succeeded', 'failed', 'expired')
BEGIN
    SELECT RAISE(ABORT, 'terminal response action is immutable');
END;

CREATE TRIGGER response_action_no_delete
BEFORE DELETE ON response_actions
BEGIN
    SELECT RAISE(ABORT, 'response actions are append-only');
END;
"""


RETENTION_GOVERNANCE_SCHEMA = r"""
CREATE TABLE retention_policies (
    tenant_id TEXT PRIMARY KEY REFERENCES tenants(tenant_id),
    telemetry_days INTEGER NOT NULL CHECK (telemetry_days BETWEEN 30 AND 3650),
    updated_by TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    FOREIGN KEY (tenant_id, updated_by) REFERENCES users(tenant_id, user_id)
);

CREATE TABLE retention_runs (
    tenant_id TEXT NOT NULL REFERENCES tenants(tenant_id),
    run_id TEXT NOT NULL,
    cutoff_at TEXT NOT NULL,
    terminal_jobs_deleted INTEGER NOT NULL CHECK (terminal_jobs_deleted >= 0),
    unreferenced_events_deleted INTEGER NOT NULL CHECK (unreferenced_events_deleted >= 0),
    executed_by TEXT NOT NULL,
    executed_at TEXT NOT NULL,
    PRIMARY KEY (tenant_id, run_id),
    FOREIGN KEY (tenant_id, executed_by) REFERENCES users(tenant_id, user_id)
);
CREATE INDEX idx_retention_runs_time
    ON retention_runs(tenant_id, executed_at DESC);

CREATE TRIGGER retention_runs_no_update
BEFORE UPDATE ON retention_runs
BEGIN
    SELECT RAISE(ABORT, 'retention runs are append-only');
END;

CREATE TRIGGER retention_runs_no_delete
BEFORE DELETE ON retention_runs
BEGIN
    SELECT RAISE(ABORT, 'retention runs are append-only');
END;
"""


CASE_INVESTIGATION_CYCLE_SCHEMA = r"""
ALTER TABLE cases
ADD COLUMN investigation_cycle INTEGER NOT NULL DEFAULT 1
CHECK (investigation_cycle >= 1);

ALTER TABLE dispositions
ADD COLUMN investigation_cycle INTEGER NOT NULL DEFAULT 1
CHECK (investigation_cycle >= 1);

DROP TRIGGER cases_close_requires_disposition;

CREATE TRIGGER cases_close_requires_disposition
BEFORE UPDATE OF status ON cases
WHEN NEW.status = 'closed' AND NOT EXISTS (
    SELECT 1 FROM dispositions
    WHERE tenant_id = OLD.tenant_id AND case_id = OLD.case_id
      AND investigation_cycle = OLD.investigation_cycle
)
BEGIN
    SELECT RAISE(ABORT, 'case cannot close without a current-cycle disposition');
END;
"""


DEVICE_CREDENTIAL_ROTATION_SCHEMA = r"""
ALTER TABLE device_credentials
ADD COLUMN activated_at TEXT;

UPDATE device_credentials
SET activated_at = created_at
WHERE activated_at IS NULL;

CREATE TABLE device_credential_rotations (
    rotation_id TEXT PRIMARY KEY,
    tenant_id TEXT NOT NULL,
    device_id TEXT NOT NULL,
    predecessor_credential_id TEXT NOT NULL,
    replacement_credential_id TEXT NOT NULL UNIQUE,
    status TEXT NOT NULL CHECK (status IN ('pending', 'delivered', 'acknowledged', 'cancelled')),
    created_by TEXT NOT NULL,
    created_at TEXT NOT NULL,
    delivery_expires_at TEXT NOT NULL,
    delivered_at TEXT,
    acknowledged_at TEXT,
    cancelled_at TEXT,
    envelope_ciphertext TEXT,
    envelope_iv TEXT,
    delivery_count INTEGER NOT NULL DEFAULT 0 CHECK (delivery_count BETWEEN 0 AND 10),
    FOREIGN KEY (tenant_id, device_id) REFERENCES devices(tenant_id, device_id),
    FOREIGN KEY (predecessor_credential_id) REFERENCES device_credentials(credential_id),
    FOREIGN KEY (replacement_credential_id) REFERENCES device_credentials(credential_id),
    CHECK (
        (status = 'pending' AND envelope_ciphertext IS NULL AND envelope_iv IS NULL)
        OR (status = 'delivered' AND envelope_ciphertext IS NOT NULL AND envelope_iv IS NOT NULL)
        OR (status IN ('acknowledged', 'cancelled')
            AND envelope_ciphertext IS NULL AND envelope_iv IS NULL)
    )
);

CREATE UNIQUE INDEX idx_device_rotation_live
    ON device_credential_rotations(tenant_id, device_id)
    WHERE status IN ('pending', 'delivered');

CREATE INDEX idx_device_rotation_replacement
    ON device_credential_rotations(replacement_credential_id, status);

CREATE TRIGGER device_rotation_identity_immutable
BEFORE UPDATE ON device_credential_rotations
WHEN NEW.rotation_id IS NOT OLD.rotation_id
  OR NEW.tenant_id IS NOT OLD.tenant_id
  OR NEW.device_id IS NOT OLD.device_id
  OR NEW.predecessor_credential_id IS NOT OLD.predecessor_credential_id
  OR NEW.replacement_credential_id IS NOT OLD.replacement_credential_id
  OR NEW.created_by IS NOT OLD.created_by
  OR NEW.created_at IS NOT OLD.created_at
  OR NEW.delivery_expires_at IS NOT OLD.delivery_expires_at
BEGIN
    SELECT RAISE(ABORT, 'device credential rotation identity is immutable');
END;

CREATE TRIGGER device_rotation_transition_guard
BEFORE UPDATE OF status ON device_credential_rotations
WHEN NOT (
    (OLD.status = 'pending' AND NEW.status IN ('delivered', 'cancelled'))
    OR (OLD.status = 'delivered' AND NEW.status IN ('acknowledged', 'cancelled'))
    OR OLD.status = NEW.status
)
BEGIN
    SELECT RAISE(ABORT, 'invalid device credential rotation transition');
END;

CREATE TRIGGER device_rotation_no_delete
BEFORE DELETE ON device_credential_rotations
BEGIN
    SELECT RAISE(ABORT, 'device credential rotations are append-only');
END;
"""


SEMANTIC_CASE_AGGREGATION_SCHEMA = r"""
ALTER TABLE cases
ADD COLUMN semantic_key TEXT;

CREATE UNIQUE INDEX idx_cases_open_semantic
    ON cases(tenant_id, semantic_key)
    WHERE semantic_key IS NOT NULL AND status != 'closed';
"""


MIGRATIONS = (
    Migration(version=1, name="initial standalone schema", sql=INITIAL_SCHEMA),
    Migration(version=2, name="case workflow and audit hardening", sql=CASE_AUDIT_SCHEMA),
    Migration(
        version=3,
        name="bounded resumable endpoint enrollment",
        sql=RESUMABLE_ENROLLMENT_SCHEMA,
    ),
    Migration(
        version=4,
        name="active response governance",
        sql=ACTIVE_RESPONSE_GOVERNANCE_SCHEMA,
    ),
    Migration(
        version=5,
        name="audited telemetry retention",
        sql=RETENTION_GOVERNANCE_SCHEMA,
    ),
    Migration(
        version=6,
        name="fresh disposition per investigation cycle",
        sql=CASE_INVESTIGATION_CYCLE_SCHEMA,
    ),
    Migration(
        version=7,
        name="endpoint-bound credential rotation",
        sql=DEVICE_CREDENTIAL_ROTATION_SCHEMA,
    ),
    Migration(
        version=8,
        name="semantic recurring-alert case aggregation",
        sql=SEMANTIC_CASE_AGGREGATION_SCHEMA,
    ),
)
