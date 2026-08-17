from __future__ import annotations

import hashlib
import hmac
import json
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
from controlforge.standalone.dashboard import dashboard_html
from controlforge.standalone.database import StandaloneDatabase
from controlforge.standalone.enrollment import (
    AesGcmDeviceCredentialCipher,
    DeviceEnrollmentService,
)
from controlforge.standalone.identity import HumanIdentityService
from controlforge.standalone.ingestion import CollectorIngestionService
from controlforge.standalone.operations import StandaloneOperationsRepository
from controlforge.standalone.passkeys import PasskeyAdapter
from controlforge.standalone.presentation import StandalonePresentationRepository
from controlforge.standalone.replay import DecisionReplayService
from controlforge.standalone.settings import StandaloneSettings
from controlforge.standalone.store import StandaloneStore

NOW = datetime(2026, 8, 23, 1, 0, tzinfo=timezone.utc)
TENANT_ID = "00000000-0000-4000-8000-000000000301"
OTHER_TENANT_ID = "00000000-0000-4000-8000-000000000302"
CASE_ID = "presentation-critical-case"
ALERT_ID = "presentation-alert"
RAW_MARKER = "must-not-leak-raw-presentation-record"
ORIGIN = "https://admin.controlforge.test"
SESSION_PEPPER = b"presentation-session-pepper-material"
RECOVERY_PEPPER = b"presentation-recovery-pepper-material"
AUDIT_KEY = b"presentation-audit-key-material-00001"


class CollectorSecretResolver:
    def resolve(
        self,
        credential_id: str,
        secret_ciphertext: str,
        secret_iv: str,
    ) -> bytes:
        raise AssertionError("collector authentication is not used in presentation tests")


def configured_repository(
    tmp_path: Path,
) -> tuple[StandaloneDatabase, StandalonePresentationRepository]:
    database = StandaloneDatabase(StandaloneSettings(database_path=tmp_path / "presentation.db"))
    database.initialize()
    store = StandaloneStore(database)
    store.create_tenant(TENANT_ID, "presentation", "Presentation tenant", NOW)
    store.create_tenant(OTHER_TENANT_ID, "other-presentation", "Other tenant", NOW)
    store.register_device(TENANT_ID, "mac-stale", "Finance Mac", "macos", NOW)
    store.register_device(TENANT_ID, "mac-new", "New Mac", "macos", NOW)
    store.register_device_credential(
        "presentation-credential",
        TENANT_ID,
        "mac-stale",
        "primary",
        f"encrypted-{RAW_MARKER}",
        "presentation-iv",
        NOW,
        NOW + timedelta(days=30),
    )
    event = SecurityEvent(
        event_id="presentation-event",
        event_type="process_start",
        timestamp=NOW - timedelta(minutes=20),
        actor="device:mac-stale",
        device_id="mac-stale",
        attributes={"command_line": RAW_MARKER},
    )
    store.ingest_event(TENANT_ID, event, NOW - timedelta(minutes=19))
    snapshot = {
        "id": "CF-ENDPOINT-001",
        "rule_version": 4,
        "title": "Encoded PowerShell execution",
        "description": "Detects encoded PowerShell command execution.",
        "status": "experimental",
        "logsource": {"category": "process_creation", "product": "windows"},
        "detection": {"selection": {"event_type": "process_start"}, "condition": "selection"},
        "level": "critical",
        "tags": ["attack.execution"],
    }
    with database.connect() as connection:
        connection.execute(
            "UPDATE devices SET last_seen_at = ? WHERE tenant_id = ? AND device_id = 'mac-stale'",
            ((NOW - timedelta(minutes=20)).isoformat(), TENANT_ID),
        )
        connection.execute(
            "UPDATE devices SET last_seen_at = NULL WHERE tenant_id = ? AND device_id = 'mac-new'",
            (TENANT_ID,),
        )
        for user_id, name, role in (
            ("responder-a", "Avery Responder", "responder"),
            ("responder-b", "Blake Reviewer", "responder"),
        ):
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
                    name,
                    role,
                    NOW.isoformat(),
                ),
            )
        connection.execute(
            """
            INSERT INTO alerts(
                tenant_id, alert_id, event_id, rule_id, rule_version, rule_digest,
                rule_snapshot_json, fingerprint_version, detector_version, title,
                severity, actor, reasons_json, tags_json, evidence_json, created_at
            ) VALUES (?, ?, 'presentation-event', 'CF-ENDPOINT-001', '4', ?, ?,
                      'fingerprint-v1', 'controlforge-test', ?, 'critical', ?, ?, ?, ?, ?)
            """,
            (
                TENANT_ID,
                ALERT_ID,
                "sha256:" + "a" * 64,
                json.dumps(snapshot, separators=(",", ":"), sort_keys=True),
                "Encoded PowerShell execution",
                "device:mac-stale",
                json.dumps(["Encoded command flag matched"]),
                json.dumps(["attack.execution"]),
                json.dumps(
                    {
                        "source_event_id": "presentation-event",
                        "source_event_sha256": "b" * 64,
                        "matched_evidence": ["Encoded command flag matched"],
                    }
                ),
                (NOW - timedelta(minutes=18)).isoformat(),
            ),
        )
        connection.execute(
            """
            INSERT INTO cases(
                tenant_id, case_id, title, priority, status, opened_at, updated_at
            ) VALUES (?, ?, 'Encoded PowerShell on Finance Mac', 'critical',
                      'investigating', ?, ?)
            """,
            (
                TENANT_ID,
                CASE_ID,
                (NOW - timedelta(minutes=18)).isoformat(),
                (NOW - timedelta(minutes=5)).isoformat(),
            ),
        )
        connection.execute(
            "INSERT INTO case_alerts VALUES (?, ?, ?, ?)",
            (TENANT_ID, CASE_ID, ALERT_ID, (NOW - timedelta(minutes=18)).isoformat()),
        )
        connection.execute(
            """
            INSERT INTO response_actions(
                tenant_id, action_id, case_id, action_type, target_type, target_id,
                rationale, risk_level, status, proposed_by, proposed_at, expires_at
            ) VALUES (?, '00000000-0000-4000-8000-000000000399', ?,
                      'isolate_endpoint', 'device', 'mac-stale',
                      'Contain confirmed credential theft.', 'active', 'proposed',
                      'responder-a', ?, ?)
            """,
            (
                TENANT_ID,
                CASE_ID,
                (NOW - timedelta(minutes=1)).isoformat(),
                (NOW + timedelta(minutes=4)).isoformat(),
            ),
        )
        connection.execute(
            """
            INSERT INTO backup_history(
                backup_id, tenant_id, status, destination, sha256,
                size_bytes, started_at, completed_at
            ) VALUES ('presentation-backup', ?, 'succeeded', ?, ?, 4096, ?, ?)
            """,
            (
                TENANT_ID,
                f"/private/path/{RAW_MARKER}.cfbackup",
                "c" * 64,
                (NOW - timedelta(hours=2)).isoformat(),
                (NOW - timedelta(hours=2)).isoformat(),
            ),
        )
        connection.execute(
            """
            INSERT INTO cases(
                tenant_id, case_id, title, priority, status, opened_at, updated_at
            ) VALUES (?, 'other-case', ?, 'critical', 'open', ?, ?)
            """,
            (OTHER_TENANT_ID, RAW_MARKER, NOW.isoformat(), NOW.isoformat()),
        )
    audit = StandaloneAuditLog(database, AUDIT_KEY)
    with database.connect() as connection:
        connection.execute("BEGIN IMMEDIATE")
        audit.append(
            connection,
            TENANT_ID,
            "case.note_added",
            "user",
            "responder-a",
            "case",
            CASE_ID,
            {"activity_id": "presentation-activity"},
            NOW,
        )
        connection.execute("COMMIT")
    return database, StandalonePresentationRepository(database)


def test_posture_and_device_health_use_real_bounded_state(tmp_path: Path) -> None:
    _, repository = configured_repository(tmp_path)

    posture = repository.posture(TENANT_ID, NOW)
    devices = repository.device_health(TENANT_ID, NOW)

    assert posture.events_24h == 1
    assert posture.ingestion_lag_seconds == 19 * 60
    assert posture.jobs_pending == 1
    assert posture.devices_active == 2
    assert posture.devices_stale == 1
    assert posture.devices_never_seen == 1
    assert posture.database_private is True
    assert posture.journal_mode == "wal"
    assert posture.foreign_keys_enabled is True
    assert posture.latest_backup_status == "succeeded"
    assert posture.last_successful_backup_at == (NOW - timedelta(hours=2)).isoformat()
    assert [(item["display_name"], item["freshness"]) for item in devices] == [
        ("Finance Mac", "stale"),
        ("New Mac", "never_seen"),
    ]
    assert devices[0]["active_credentials"] == 1


def test_case_queue_is_prioritized_searchable_and_tenant_scoped(tmp_path: Path) -> None:
    _, repository = configured_repository(tmp_path)

    cases = repository.case_queue(
        TENANT_ID,
        status="investigating",
        priority="critical",
        query="powershell",
    )
    no_match = repository.case_queue(TENANT_ID, query="other tenant")

    assert len(cases) == 1
    assert cases[0]["case_id"] == CASE_ID
    assert cases[0]["highest_severity"] == "critical"
    assert cases[0]["alert_count"] == 1
    assert cases[0]["recurrence_count"] == 0
    assert cases[0]["live_response_count"] == 1
    assert no_match == []
    assert repository.case_assignees(TENANT_ID) == [
        {
            "user_id": "responder-a",
            "display_name": "Avery Responder",
            "role": "responder",
        },
        {
            "user_id": "responder-b",
            "display_name": "Blake Reviewer",
            "role": "responder",
        },
    ]
    assert repository.case_assignees(OTHER_TENANT_ID) == []


def test_evidence_and_response_views_expose_provenance_not_raw_secrets(tmp_path: Path) -> None:
    _, repository = configured_repository(tmp_path)

    evidence = repository.case_evidence(TENANT_ID, CASE_ID)
    responses = repository.response_queue(TENANT_ID)
    serialized = json.dumps(
        {
            "posture": repository.posture(TENANT_ID, NOW).as_dict(),
            "devices": repository.device_health(TENANT_ID, NOW),
            "cases": repository.case_queue(TENANT_ID),
            "evidence": evidence,
            "responses": responses,
        },
        sort_keys=True,
    )

    assert evidence[0]["matched_evidence"] == ["Encoded command flag matched"]
    event_projection = evidence[0]["event"]
    assert isinstance(event_projection, dict)
    assert event_projection["payload_sha256"]
    assert evidence[0]["rule"] == {
        "rule_id": "CF-ENDPOINT-001",
        "rule_version": "4",
        "rule_digest": "sha256:" + "a" * 64,
        "fingerprint_version": "fingerprint-v1",
        "detector_version": "controlforge-test",
        "description": "Detects encoded PowerShell command execution.",
        "status": "experimental",
        "condition": "selection",
        "logsource": {"category": "process_creation", "product": "windows"},
    }
    assert responses[0]["proposer_name"] == "Avery Responder"
    assert responses[0]["device_name"] == "Finance Mac"
    assert RAW_MARKER not in serialized


def authenticated_viewer_api(tmp_path: Path) -> TestClient:
    database, presentation = configured_repository(tmp_path)
    identity = HumanIdentityService(
        database,
        cast(PasskeyAdapter, object()),
        SESSION_PEPPER,
        RECOVERY_PEPPER,
    )
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
            INSERT INTO users(
                tenant_id, user_id, email, display_name, role, status, created_at
            ) VALUES (?, 'presentation-viewer', 'viewer@example.com',
                      'Read-only Operator', 'viewer', 'active', ?)
            """,
            (TENANT_ID, NOW.isoformat()),
        )
        connection.execute(
            """
            INSERT INTO sessions(
                tenant_id, session_id, user_id, secret_hash, csrf_hash,
                created_at, expires_at, last_seen_at
            ) VALUES (?, ?, 'presentation-viewer', ?, ?, ?, ?, ?)
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
    audit = StandaloneAuditLog(database, AUDIT_KEY)
    app = create_standalone_app(
        StandaloneApiServices(
            identity=identity,
            ingestion=CollectorIngestionService(
                DeviceHmacAuthenticator(database, CollectorSecretResolver()),
                store,
            ),
            enrollment=DeviceEnrollmentService(
                database,
                AesGcmDeviceCredentialCipher(b"p" * 32),
            ),
            operations=StandaloneOperationsRepository(database),
            replay=DecisionReplayService(database, [], "presentation-api-v1"),
            cases=StandaloneCaseService(database, identity, audit),
            presentation=presentation,
        ),
        ORIGIN,
        clock=lambda: NOW,
    )
    client = TestClient(app, base_url=ORIGIN)
    client.cookies.set(SESSION_COOKIE, token)
    return client


def test_authenticated_viewer_can_read_bounded_dashboard_projections(tmp_path: Path) -> None:
    client = authenticated_viewer_api(tmp_path)

    for path in (
        "/v1/dashboard/posture",
        "/v1/dashboard/devices",
        "/v1/dashboard/cases?query=powershell",
        "/v1/dashboard/case-assignees",
        "/v1/dashboard/responses",
        f"/v1/cases/{CASE_ID}/evidence",
    ):
        response = client.get(path)
        assert response.status_code == 200
        assert RAW_MARKER not in response.text

    assert client.get("/v1/dashboard/cases").json()["cases"][0]["case_id"] == CASE_ID
    evidence_page = client.get(f"/v1/cases/{CASE_ID}/evidence").json()
    assert evidence_page["total"] == 1
    assert evidence_page["truncated"] is False
    assert len(evidence_page["evidence"]) == 1
    client.cookies.clear()
    assert client.get("/v1/dashboard/posture").status_code == 401


@pytest.mark.parametrize(("age", "freshness"), [(900, "fresh"), (901, "stale"), (-1, "clock_skew")])
def test_device_guidance_uses_server_time_and_includes_observation(
    tmp_path: Path, age: int, freshness: str
) -> None:
    database, repository = configured_repository(tmp_path)
    with database.connect() as connection:
        connection.execute(
            "UPDATE devices SET last_seen_at = ? WHERE tenant_id = ? AND device_id = ?",
            ((NOW - timedelta(seconds=age)).isoformat(), TENANT_ID, "mac-stale"),
        )
    records = repository.device_health(TENANT_ID, NOW, device_id="mac-stale")
    assert len(records) == 1
    assert records[0]["freshness"] == freshness
    assert datetime.fromisoformat(str(records[0]["observed_at"]).replace("Z", "+00:00")) == NOW
    assert records[0]["stale_after_seconds"] == 900
    assert "not a malware scan" in str(records[0]["guidance"])
    assert repository.device_health(OTHER_TENANT_ID, NOW, device_id="mac-stale") == []


def test_device_detail_is_scoped_redacted_and_requires_authentication(tmp_path: Path) -> None:
    client = authenticated_viewer_api(tmp_path)
    response = client.get("/v1/dashboard/devices/mac-stale")
    assert response.status_code == 200
    record = response.json()["device"]
    assert record["device_id"] == "mac-stale"
    assert record["guidance"]["title"] == "Check this Mac's connection"
    assert RAW_MARKER not in response.text
    assert "credential_id" not in response.text
    assert client.get("/v1/dashboard/devices/not-a-device").status_code == 404
    assert client.get("/v1/dashboard/devices/" + "a" * 129).status_code == 400
    client.cookies.clear()
    assert client.get("/v1/dashboard/devices/mac-stale").status_code == 401


def test_dashboard_markup_is_semantic_same_origin_and_role_aware() -> None:
    html = dashboard_html("presentation-test-nonce")

    for semantic in (
        '<aside class="sidebar"',
        '<nav id="workspace-nav"',
        '<main id="main"',
        'role="search"',
        'aria-live="polite"',
        'aria-busy="true"',
        "Evidence-first security operations",
        "a different human must review it",
        "One-time setup code",
        "Network ID",
        "Network name",
        "How setup stays safe",
        "/v1/dashboard/posture",
        "/v1/dashboard/case-assignees",
        "/v1/cases/",
        "/assignment",
        "/v1/audit/verify",
        "/response-actions",
    ):
        assert semantic in html
    assert 'nonce="presentation-test-nonce"' in html
    assert '<div id="invite-accept-card" class="card" hidden>' in html
    assert "$('#invite-accept-card').hidden=!status.configured" in html
    assert "Bootstrap token" not in html
    assert "Organization slug" not in html
    assert (
        '<label>Administrator email<input name="email" type="email" required autocomplete="email">'
        in html
    )
    assert '<form id="login-form"' in html and 'autocomplete="username webauthn"' in html
    assert "me.role!=='admin'" in html
    assert "canInvestigate" in html
    assert "canRespond" in html
    assert "action.proposed_by===me.user_id" in html
    assert 'id="refresh" class="secondary" type="button" aria-label="Refresh workspace"' in html
    assert '<span aria-hidden="true">↻</span>' in html
    assert "item.highest_severity&&item.highest_severity!==item.priority" in html
    assert "item.recurrence_count" in html
    assert "recurrence" in html
    assert "evidenceMeta.truncated" in html
    assert "detail.alert_count" in html
    assert "if(item.highest_severity)head.append" not in html
    assert ".detail-tabs{display:flex;overflow-x:auto;" in html
    assert "innerHTML" not in html
    assert "localStorage" not in html
    assert "Autonomous SOC" not in html
    assert "<canvas" not in html
    assert "<script src=" not in html
    assert '<link rel="stylesheet"' not in html
    assert RAW_MARKER not in html
