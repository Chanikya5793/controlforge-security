from __future__ import annotations

import hashlib
import hmac
import json
import sqlite3
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import cast

import pytest
from fastapi.testclient import TestClient

from controlforge.models import SecurityEvent
from controlforge.standalone.api import (
    SESSION_COOKIE,
    StandaloneApiServices,
    create_standalone_app,
)
from controlforge.standalone.audit import StandaloneAuditLog
from controlforge.standalone.auth import DeviceHmacAuthenticator
from controlforge.standalone.cases import StandaloneCaseService
from controlforge.standalone.database import StandaloneDatabase
from controlforge.standalone.enrollment import (
    AesGcmDeviceCredentialCipher,
    DeviceEnrollmentService,
)
from controlforge.standalone.identity import (
    HumanAuthorizationError,
    HumanIdentityService,
    Role,
    SessionPrincipal,
)
from controlforge.standalone.ingestion import CollectorIngestionService
from controlforge.standalone.operations import StandaloneOperationsRepository
from controlforge.standalone.passkeys import PasskeyAdapter
from controlforge.standalone.replay import DecisionReplayService
from controlforge.standalone.retention import RetentionError, StandaloneRetentionService
from controlforge.standalone.settings import StandaloneSettings
from controlforge.standalone.store import StandaloneStore

NOW = datetime(2026, 8, 23, 3, 0, tzinfo=timezone.utc)
ORIGIN = "https://admin.controlforge.test"
TENANT_ID = "00000000-0000-4000-8000-000000000501"
OTHER_TENANT_ID = "00000000-0000-4000-8000-000000000502"
SESSION_PEPPER = b"retention-session-pepper-material"
RECOVERY_PEPPER = b"retention-recovery-pepper-material"
AUDIT_KEY = b"retention-audit-key-material-00001"


class CollectorSecretResolver:
    def resolve(
        self,
        credential_id: str,
        secret_ciphertext: str,
        secret_iv: str,
    ) -> bytes:
        raise AssertionError("collector authentication is not used in retention tests")


def principal(role: Role = "admin") -> SessionPrincipal:
    return SessionPrincipal(
        tenant_id=TENANT_ID,
        user_id=f"{role}-a",
        email=f"{role}-a@example.com",
        display_name=f"{role.title()} A",
        role=role,
        session_id=f"session-{role}",
        expires_at=NOW + timedelta(hours=1),
        csrf_hash="unused",
    )


def event(event_id: str, timestamp: datetime) -> SecurityEvent:
    return SecurityEvent(
        event_id=event_id,
        event_type="process_start",
        timestamp=timestamp,
        actor=f"device:{event_id}",
        attributes={"command_line": "/usr/bin/true"},
    )


def configured_retention(
    tmp_path: Path,
) -> tuple[
    StandaloneDatabase,
    HumanIdentityService,
    StandaloneAuditLog,
    StandaloneRetentionService,
]:
    database = StandaloneDatabase(StandaloneSettings(database_path=tmp_path / "retention.db"))
    database.initialize()
    store = StandaloneStore(database)
    store.create_tenant(TENANT_ID, "retention", "Retention tenant", NOW)
    store.create_tenant(OTHER_TENANT_ID, "other-retention", "Other retention", NOW)
    identity = HumanIdentityService(
        database,
        cast(PasskeyAdapter, object()),
        SESSION_PEPPER,
        RECOVERY_PEPPER,
    )
    with database.connect() as connection:
        for user_id, role in (("admin-a", "admin"), ("analyst-a", "analyst")):
            connection.execute(
                """
                INSERT INTO users(
                    tenant_id, user_id, email, display_name, role, status, created_at
                ) VALUES (?, ?, ?, ?, ?, 'active', ?)
                """,
                (
                    TENANT_ID,
                    user_id,
                    f"{user_id}@example.com",
                    user_id,
                    role,
                    NOW.isoformat(),
                ),
            )
    old = NOW - timedelta(days=120)
    for event_id in ("old-free", "old-alert", "old-pending"):
        store.ingest_event(TENANT_ID, event(event_id, old), old)
    store.ingest_event(OTHER_TENANT_ID, event("other-old", old), old)
    with database.connect() as connection:
        connection.execute(
            """
            UPDATE detection_jobs SET status = 'succeeded', updated_at = ?
            WHERE event_id IN ('old-free', 'old-alert', 'other-old')
            """,
            (old.isoformat(),),
        )
        connection.execute(
            """
            INSERT INTO alerts(
                tenant_id, alert_id, event_id, rule_id, rule_version, rule_digest,
                rule_snapshot_json, fingerprint_version, detector_version, title,
                severity, actor, reasons_json, tags_json, evidence_json, created_at
            ) VALUES (?, 'retained-alert', 'old-alert', 'CF-TEST-001', '1', ?, ?,
                      'fingerprint-v1', 'retention-test', 'Retained evidence',
                      'high', 'device:old-alert', '[]', '[]', ?, ?)
            """,
            (
                TENANT_ID,
                "sha256:" + "a" * 64,
                json.dumps({"id": "CF-TEST-001", "rule_version": 1}),
                json.dumps({"source_event_id": "old-alert"}),
                old.isoformat(),
            ),
        )
    audit = StandaloneAuditLog(database, AUDIT_KEY)
    return database, identity, audit, StandaloneRetentionService(database, identity, audit)


def test_retention_preview_apply_preserves_alert_evidence_and_other_tenants(
    tmp_path: Path,
) -> None:
    database, _, audit, retention = configured_retention(tmp_path)
    admin = principal()

    default_preview = retention.preview(admin, NOW)
    policy = retention.set_policy(admin, 30, NOW)
    preview = retention.preview(admin, NOW)
    result = retention.apply(admin, NOW + timedelta(seconds=1))

    assert default_preview.telemetry_days == 90
    assert policy.telemetry_days == 30
    assert preview.terminal_jobs == 2
    assert preview.unreferenced_events == 1
    assert result.terminal_jobs_deleted == 2
    assert result.unreferenced_events_deleted == 1
    assert retention.latest_run(admin) == result
    assert audit.verify(TENANT_ID).valid is True
    assert audit.verify(TENANT_ID).entries_checked == 2

    with database.connect() as connection:
        tenant_events = {
            str(row[0])
            for row in connection.execute(
                "SELECT event_id FROM events WHERE tenant_id = ?",
                (TENANT_ID,),
            )
        }
        other_events = connection.execute(
            "SELECT COUNT(*) FROM events WHERE tenant_id = ?",
            (OTHER_TENANT_ID,),
        ).fetchone()[0]
        retained_alert = connection.execute(
            "SELECT COUNT(*) FROM alerts WHERE tenant_id = ? AND alert_id = 'retained-alert'",
            (TENANT_ID,),
        ).fetchone()[0]
        with pytest.raises(sqlite3.IntegrityError):
            connection.execute("DELETE FROM retention_runs")
    assert tenant_events == {"old-alert", "old-pending"}
    assert other_events == 1
    assert retained_alert == 1


def test_retention_is_admin_only_and_fails_closed_on_invalid_audit(tmp_path: Path) -> None:
    database, _, _, retention = configured_retention(tmp_path)
    analyst = principal("analyst")
    assert retention.preview(analyst, NOW).unreferenced_events == 1
    with pytest.raises(HumanAuthorizationError):
        retention.set_policy(analyst, 30, NOW)
    with pytest.raises(HumanAuthorizationError):
        retention.apply(analyst, NOW)

    admin = principal()
    retention.set_policy(admin, 30, NOW)
    with database.connect() as connection:
        connection.execute("DROP TRIGGER audit_log_no_update")
        connection.execute(
            "UPDATE audit_log SET payload_json = '{}' WHERE tenant_id = ?",
            (TENANT_ID,),
        )
    with pytest.raises(RetentionError):
        retention.apply(admin, NOW)
    with database.connect() as connection:
        assert (
            connection.execute(
                "SELECT COUNT(*) FROM events WHERE tenant_id = ?",
                (TENANT_ID,),
            ).fetchone()[0]
            == 3
        )


def authenticated_retention_api(tmp_path: Path) -> tuple[TestClient, str]:
    database, identity, audit, retention = configured_retention(tmp_path)
    token = f"{uuid.uuid4()}.server-selected-secret"
    session_id = token.partition(".")[0]
    csrf_token = str(uuid.uuid4())
    session_hash = hmac.new(
        SESSION_PEPPER,
        f"session:{token}".encode(),
        hashlib.sha256,
    ).hexdigest()
    csrf_hash = hmac.new(
        SESSION_PEPPER,
        f"csrf:{csrf_token}".encode(),
        hashlib.sha256,
    ).hexdigest()
    with database.connect() as connection:
        connection.execute(
            """
            INSERT INTO sessions(
                tenant_id, session_id, user_id, secret_hash, csrf_hash,
                created_at, expires_at, last_seen_at
            ) VALUES (?, ?, 'admin-a', ?, ?, ?, ?, ?)
            """,
            (
                TENANT_ID,
                session_id,
                session_hash,
                csrf_hash,
                NOW.isoformat(),
                (NOW + timedelta(hours=1)).isoformat(),
                NOW.isoformat(),
            ),
        )
    store = StandaloneStore(database)
    app = create_standalone_app(
        StandaloneApiServices(
            identity=identity,
            ingestion=CollectorIngestionService(
                DeviceHmacAuthenticator(database, CollectorSecretResolver()),
                store,
            ),
            enrollment=DeviceEnrollmentService(
                database,
                AesGcmDeviceCredentialCipher(b"c" * 32),
            ),
            operations=StandaloneOperationsRepository(database),
            replay=DecisionReplayService(database, [], "retention-api-v1"),
            cases=StandaloneCaseService(database, identity, audit),
            retention=retention,
        ),
        ORIGIN,
        clock=lambda: NOW,
    )
    client = TestClient(app, base_url=ORIGIN)
    client.cookies.set(SESSION_COOKIE, token)
    return client, csrf_token


def test_retention_api_requires_csrf_and_returns_exact_deletion_counts(tmp_path: Path) -> None:
    client, csrf_token = authenticated_retention_api(tmp_path)
    headers = {"origin": ORIGIN, "x-csrf-token": csrf_token}

    status = client.get("/v1/retention")
    assert status.status_code == 200
    assert status.json()["preview"] == {
        "cutoff_at": (NOW - timedelta(days=90)).isoformat(),
        "terminal_jobs": 2,
        "unreferenced_events": 1,
    }
    assert client.put("/v1/retention/policy", json={"telemetry_days": 30}).status_code == 403
    assert (
        client.put(
            "/v1/retention/policy",
            headers=headers,
            json={"telemetry_days": 30},
        ).status_code
        == 200
    )
    applied = client.post("/v1/retention/apply", headers=headers, json={})
    assert applied.status_code == 200
    assert applied.json()["terminal_jobs_deleted"] == 2
    assert applied.json()["unreferenced_events_deleted"] == 1
    refreshed = client.get("/v1/retention").json()
    assert refreshed["latest_run"]["run_id"] == applied.json()["run_id"]
