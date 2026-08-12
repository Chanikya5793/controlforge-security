from __future__ import annotations

import hashlib
import hmac
import sqlite3
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import cast

import pytest
from fastapi.testclient import TestClient

from controlforge.standalone.api import (
    SESSION_COOKIE,
    StandaloneApiServices,
    create_standalone_app,
)
from controlforge.standalone.audit import AuditError, StandaloneAuditLog
from controlforge.standalone.auth import DeviceHmacAuthenticator
from controlforge.standalone.cases import (
    CaseNotFoundError,
    CaseTransitionError,
    CaseValidationError,
    StandaloneCaseService,
)
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
from controlforge.standalone.migrations import INITIAL_SCHEMA, MIGRATIONS
from controlforge.standalone.operations import StandaloneOperationsRepository
from controlforge.standalone.passkeys import PasskeyAdapter
from controlforge.standalone.replay import DecisionReplayService
from controlforge.standalone.settings import StandaloneSettings
from controlforge.standalone.store import StandaloneStore

NOW = datetime(2026, 8, 22, 22, 0, tzinfo=timezone.utc)
ORIGIN = "https://admin.controlforge.test"
TENANT_A = "00000000-0000-4000-8000-000000000101"
TENANT_B = "00000000-0000-4000-8000-000000000102"
CASE_ID = "case-a-1"
SESSION_PEPPER = b"case-session-pepper-material-000001"
RECOVERY_PEPPER = b"case-recovery-pepper-material-0001"
AUDIT_KEY = b"case-audit-key-material-00000000001"


class CollectorSecretResolver:
    def resolve(
        self,
        credential_id: str,
        secret_ciphertext: str,
        secret_iv: str,
    ) -> bytes:
        raise AssertionError("collector authentication is not used in case tests")


def principal(tenant_id: str, user_id: str, role: Role) -> SessionPrincipal:
    return SessionPrincipal(
        tenant_id=tenant_id,
        user_id=user_id,
        email=f"{user_id}@example.com",
        display_name=user_id,
        role=role,
        session_id=f"session-{user_id}",
        expires_at=NOW + timedelta(hours=1),
        csrf_hash="unused-in-service-tests",
    )


def configured_services(
    tmp_path: Path,
) -> tuple[
    StandaloneDatabase,
    HumanIdentityService,
    StandaloneAuditLog,
    StandaloneCaseService,
]:
    database = StandaloneDatabase(StandaloneSettings(database_path=tmp_path / "cases.db"))
    database.initialize()
    store = StandaloneStore(database)
    store.create_tenant(TENANT_A, "tenant-a", "Tenant A", NOW)
    store.create_tenant(TENANT_B, "tenant-b", "Tenant B", NOW)
    identity = HumanIdentityService(
        database,
        cast(PasskeyAdapter, object()),
        SESSION_PEPPER,
        RECOVERY_PEPPER,
    )
    with database.connect() as connection:
        for tenant_id, user_id, role in (
            (TENANT_A, "analyst-a", "analyst"),
            (TENANT_A, "responder-a", "responder"),
            (TENANT_A, "viewer-a", "viewer"),
            (TENANT_B, "admin-b", "admin"),
        ):
            connection.execute(
                """
                INSERT INTO users(
                    tenant_id, user_id, email, display_name, role, status, created_at
                ) VALUES (?, ?, ?, ?, ?, 'active', ?)
                """,
                (
                    tenant_id,
                    user_id,
                    f"{user_id}@example.com",
                    user_id,
                    role,
                    NOW.isoformat(),
                ),
            )
        connection.execute(
            """
            INSERT INTO cases(
                tenant_id, case_id, title, priority, status, opened_at, updated_at
            ) VALUES (?, ?, 'Suspicious execution', 'high', 'open', ?, ?)
            """,
            (TENANT_A, CASE_ID, NOW.isoformat(), NOW.isoformat()),
        )
    audit = StandaloneAuditLog(database, AUDIT_KEY)
    return database, identity, audit, StandaloneCaseService(database, identity, audit)


def test_case_assignment_is_tenant_scoped_audited_and_reversible(tmp_path: Path) -> None:
    database, _, audit, cases = configured_services(tmp_path)
    analyst = principal(TENANT_A, "analyst-a", "analyst")

    assigned = cases.assign(analyst, CASE_ID, "responder-a", NOW)
    unassigned = cases.assign(analyst, CASE_ID, None, NOW + timedelta(seconds=1))

    assert assigned.assignee_user_id == "responder-a"
    assert unassigned.assignee_user_id is None
    assert unassigned.version == 3
    assert [item.activity_type for item in unassigned.activity] == ["assignment", "assignment"]
    assert unassigned.activity[0].body == {
        "from_user_id": None,
        "to_user_id": "responder-a",
    }
    assert audit.verify(TENANT_A).entries_checked == 2

    with pytest.raises(CaseValidationError):
        cases.assign(analyst, CASE_ID, "viewer-a", NOW + timedelta(seconds=2))
    with pytest.raises(CaseValidationError):
        cases.assign(analyst, CASE_ID, "admin-b", NOW + timedelta(seconds=2))
    with pytest.raises(HumanAuthorizationError):
        cases.assign(
            principal(TENANT_A, "viewer-a", "viewer"),
            CASE_ID,
            "analyst-a",
            NOW,
        )

    with database.connect() as connection:
        stored = connection.execute(
            "SELECT assignee_user_id, version FROM cases WHERE tenant_id = ? AND case_id = ?",
            (TENANT_A, CASE_ID),
        ).fetchone()
    assert stored["assignee_user_id"] is None
    assert int(stored["version"]) == 3


def test_v1_database_upgrades_to_exact_case_audit_migration(tmp_path: Path) -> None:
    path = tmp_path / "upgrade.db"
    connection = sqlite3.connect(path)
    connection.executescript(INITIAL_SCHEMA)
    connection.execute(
        """
        CREATE TABLE schema_migrations(
            version INTEGER PRIMARY KEY, name TEXT NOT NULL, applied_at TEXT NOT NULL
        )
        """
    )
    connection.execute(
        "INSERT INTO schema_migrations VALUES (1, 'initial standalone schema', ?)",
        (NOW.isoformat(),),
    )
    connection.commit()
    connection.close()
    path.chmod(0o600)

    database = StandaloneDatabase(StandaloneSettings(database_path=path))
    database.initialize()

    assert database.applied_versions() == tuple(migration.version for migration in MIGRATIONS)
    with database.connect() as upgraded:
        case_columns = {str(row["name"]) for row in upgraded.execute("PRAGMA table_info(cases)")}
        disposition_columns = {
            str(row["name"]) for row in upgraded.execute("PRAGMA table_info(dispositions)")
        }
        response_columns = {
            str(row["name"]) for row in upgraded.execute("PRAGMA table_info(response_actions)")
        }
        triggers = {
            str(row["name"])
            for row in upgraded.execute("SELECT name FROM sqlite_master WHERE type = 'trigger'")
        }
        indexes = {
            str(row["name"])
            for row in upgraded.execute("SELECT name FROM sqlite_master WHERE type = 'index'")
        }
    assert "version" in case_columns
    assert "semantic_key" in case_columns
    assert "false_positive_reason" in disposition_columns
    assert {"dispatch_count", "rejected_by", "result_device_id"}.issubset(response_columns)
    assert {
        "cases_status_transition_guard",
        "cases_close_requires_disposition",
        "case_activity_no_update",
        "dispositions_no_delete",
        "audit_checkpoints_no_update",
        "response_action_approval_guard",
        "response_action_no_delete",
    }.issubset(triggers)
    assert "idx_cases_open_semantic" in indexes


def test_case_workflow_is_atomic_audited_and_reopenable(tmp_path: Path) -> None:
    database, _, audit, cases = configured_services(tmp_path)
    analyst = principal(TENANT_A, "analyst-a", "analyst")

    note = cases.add_note(analyst, CASE_ID, "  Confirmed by endpoint timeline.  ", NOW)
    investigating = cases.transition(
        analyst,
        CASE_ID,
        "investigating",
        NOW + timedelta(seconds=1),
    )
    disposition = cases.record_disposition(
        analyst,
        CASE_ID,
        "false_positive",
        "The signed internal updater produced the behavior.",
        "Trusted internal software",
        NOW + timedelta(seconds=2),
    )
    closed = cases.transition(
        analyst,
        CASE_ID,
        "closed",
        NOW + timedelta(seconds=3),
    )
    reopened = cases.transition(
        analyst,
        CASE_ID,
        "open",
        NOW + timedelta(seconds=4),
    )
    with pytest.raises(CaseTransitionError):
        cases.transition(
            analyst,
            CASE_ID,
            "closed",
            NOW + timedelta(seconds=5),
        )
    second_disposition = cases.record_disposition(
        analyst,
        CASE_ID,
        "true_positive",
        "Fresh evidence was reviewed after reopening the investigation.",
        None,
        NOW + timedelta(seconds=6),
    )
    reclosed = cases.transition(
        analyst,
        CASE_ID,
        "closed",
        NOW + timedelta(seconds=7),
    )

    assert note.body == {"note": "Confirmed by endpoint timeline."}
    assert investigating.status == "investigating"
    assert disposition.false_positive_reason == "Trusted internal software"
    assert closed.closed_at == NOW + timedelta(seconds=3)
    assert reopened.status == "open"
    assert reopened.closed_at is None
    assert reopened.version == 6
    assert second_disposition.status == "true_positive"
    assert reclosed.status == "closed"
    assert reclosed.version == 8
    verification = audit.verify(TENANT_A)
    assert verification.valid is True
    assert verification.entries_checked == 7
    assert verification.checkpoints_checked == 7
    with database.connect() as connection:
        with pytest.raises(sqlite3.IntegrityError):
            connection.execute("UPDATE audit_log SET action = 'forged'")
        with pytest.raises(sqlite3.IntegrityError):
            connection.execute("DELETE FROM dispositions")
        with pytest.raises(sqlite3.IntegrityError):
            connection.execute("UPDATE case_activity SET actor_id = 'forged'")


def test_close_requires_disposition_and_invalid_work_rolls_back(tmp_path: Path) -> None:
    database, _, audit, cases = configured_services(tmp_path)
    analyst = principal(TENANT_A, "analyst-a", "analyst")

    with pytest.raises(CaseTransitionError):
        cases.transition(analyst, CASE_ID, "closed", NOW)
    with pytest.raises(CaseValidationError):
        cases.record_disposition(
            analyst,
            CASE_ID,
            "false_positive",
            "Not malicious.",
            None,
            NOW,
        )

    assert audit.verify(TENANT_A).entries_checked == 0
    with database.connect() as connection:
        case = connection.execute(
            "SELECT status, version FROM cases WHERE tenant_id = ? AND case_id = ?",
            (TENANT_A, CASE_ID),
        ).fetchone()
        assert tuple(case) == ("open", 1)
        with pytest.raises(sqlite3.IntegrityError):
            connection.execute(
                """
                UPDATE cases SET status = 'contained', version = version + 1
                WHERE tenant_id = ? AND case_id = ?
                """,
                (TENANT_A, CASE_ID),
            )
        with pytest.raises(sqlite3.IntegrityError):
            connection.execute(
                """
                UPDATE cases SET status = 'closed', version = version + 1
                WHERE tenant_id = ? AND case_id = ?
                """,
                (TENANT_A, CASE_ID),
            )
        with pytest.raises(sqlite3.IntegrityError):
            connection.execute(
                """
                INSERT INTO dispositions(
                    tenant_id, disposition_id, case_id, status, rationale,
                    rule_version, created_by, created_at, false_positive_reason
                ) VALUES (?, 'bad', ?, 'false_positive', 'rationale',
                          'v1', 'analyst-a', ?, NULL)
                """,
                (TENANT_A, CASE_ID, NOW.isoformat()),
            )


def test_closed_semantic_case_cannot_reopen_while_successor_is_active(
    tmp_path: Path,
) -> None:
    database, _, audit, cases = configured_services(tmp_path)
    analyst = principal(TENANT_A, "analyst-a", "analyst")
    semantic_key = "a" * 64
    with database.connect() as connection:
        connection.execute(
            "UPDATE cases SET semantic_key = ? WHERE tenant_id = ? AND case_id = ?",
            (semantic_key, TENANT_A, CASE_ID),
        )
    cases.record_disposition(
        analyst,
        CASE_ID,
        "true_positive",
        "Confirmed recurring behavior.",
        None,
        NOW,
    )
    cases.transition(analyst, CASE_ID, "closed", NOW + timedelta(seconds=1))
    with database.connect() as connection:
        connection.execute(
            """
            INSERT INTO cases(
                tenant_id, case_id, semantic_key, title, priority,
                status, opened_at, updated_at
            ) VALUES (?, 'case-successor', ?, 'Recurring behavior', 'high',
                      'open', ?, ?)
            """,
            (
                TENANT_A,
                semantic_key,
                (NOW + timedelta(seconds=2)).isoformat(),
                (NOW + timedelta(seconds=2)).isoformat(),
            ),
        )

    with pytest.raises(
        CaseTransitionError,
        match="successor case is active",
    ):
        cases.transition(analyst, CASE_ID, "open", NOW + timedelta(seconds=3))

    assert audit.verify(TENANT_A).entries_checked == 2
    with database.connect() as connection:
        statuses = connection.execute(
            "SELECT case_id, status FROM cases WHERE tenant_id = ? ORDER BY case_id",
            (TENANT_A,),
        ).fetchall()
    assert [tuple(row) for row in statuses] == [
        (CASE_ID, "closed"),
        ("case-successor", "open"),
    ]


def test_case_detail_bounds_recurring_evidence_and_human_history(tmp_path: Path) -> None:
    database, _, _, cases = configured_services(tmp_path)
    with database.connect() as connection:
        connection.executemany(
            """
            INSERT INTO events(
                tenant_id, event_id, event_type, occurred_at, received_at,
                actor, payload_json, payload_sha256
            ) VALUES (?, ?, 'process_start', ?, ?, 'device:mac-1', '{}', ?)
            """,
            [
                (
                    TENANT_A,
                    f"event-{index:04d}",
                    NOW.isoformat(),
                    NOW.isoformat(),
                    f"{index:064x}",
                )
                for index in range(205)
            ],
        )
        connection.executemany(
            """
            INSERT INTO alerts(
                tenant_id, alert_id, event_id, rule_id, rule_version, rule_digest,
                rule_snapshot_json, fingerprint_version, detector_version, title,
                severity, actor, reasons_json, tags_json, evidence_json, created_at
            ) VALUES (?, ?, ?, 'CF-ENDPOINT-001', '1', ?, '{}', 'legacy-local-v0',
                      'test-detector', 'Encoded PowerShell', 'high', 'device:mac-1',
                      '[]', '[]', '{}', ?)
            """,
            [
                (
                    TENANT_A,
                    f"alert-{index:04d}",
                    f"event-{index:04d}",
                    f"{index:064x}",
                    NOW.isoformat(),
                )
                for index in range(205)
            ],
        )
        connection.executemany(
            "INSERT INTO case_alerts VALUES (?, ?, ?, ?)",
            [(TENANT_A, CASE_ID, f"alert-{index:04d}", NOW.isoformat()) for index in range(205)],
        )
        connection.executemany(
            """
            INSERT INTO case_activity(
                tenant_id, activity_id, case_id, activity_type,
                actor_id, body_json, created_at
            ) VALUES (?, ?, ?, 'note', 'analyst-a', '{}', ?)
            """,
            [(TENANT_A, f"activity-{index:04d}", CASE_ID, NOW.isoformat()) for index in range(505)],
        )
        connection.executemany(
            """
            INSERT INTO dispositions(
                tenant_id, disposition_id, case_id, status, rationale, rule_version,
                created_by, created_at, false_positive_reason, investigation_cycle
            ) VALUES (?, ?, ?, 'true_positive', 'bounded rationale', '1',
                      'analyst-a', ?, NULL, 1)
            """,
            [
                (TENANT_A, f"disposition-{index:04d}", CASE_ID, NOW.isoformat())
                for index in range(205)
            ],
        )

    detail = cases.get_case(principal(TENANT_A, "viewer-a", "viewer"), CASE_ID)

    assert detail.alert_count == 205
    assert len(detail.alert_ids) == 200
    assert detail.alerts_truncated is True
    assert detail.activity_count == 505
    assert len(detail.activity) == 500
    assert detail.activity_truncated is True
    assert detail.disposition_count == 205
    assert len(detail.dispositions) == 200
    assert detail.dispositions_truncated is True


def test_rbac_and_tenant_scope_fail_closed_before_mutation(tmp_path: Path) -> None:
    _, _, audit, cases = configured_services(tmp_path)
    viewer = principal(TENANT_A, "viewer-a", "viewer")
    other_tenant_admin = principal(TENANT_B, "admin-b", "admin")

    assert cases.get_case(viewer, CASE_ID).case_id == CASE_ID
    with pytest.raises(HumanAuthorizationError):
        cases.add_note(viewer, CASE_ID, "Viewer must not mutate.", NOW)
    with pytest.raises(CaseNotFoundError):
        cases.get_case(other_tenant_admin, CASE_ID)
    with pytest.raises(CaseNotFoundError):
        cases.add_note(other_tenant_admin, CASE_ID, "Cross-tenant write.", NOW)
    assert audit.verify(TENANT_A).entries_checked == 0
    assert audit.verify(TENANT_B).entries_checked == 0


def test_chain_verification_detects_entry_checkpoint_and_tail_tampering(
    tmp_path: Path,
) -> None:
    database, _, audit, cases = configured_services(tmp_path)
    analyst = principal(TENANT_A, "analyst-a", "analyst")
    cases.add_note(analyst, CASE_ID, "First observation", NOW)
    cases.add_note(analyst, CASE_ID, "Second observation", NOW + timedelta(seconds=1))
    assert audit.verify(TENANT_A).valid is True

    with database.connect() as connection:
        connection.execute("DROP TRIGGER audit_log_no_update")
        connection.execute(
            "UPDATE audit_log SET payload_json = '{}' WHERE tenant_id = ? AND sequence = 1",
            (TENANT_A,),
        )
    entry_tamper = audit.verify(TENANT_A)
    assert entry_tamper.valid is False
    assert entry_tamper.failure_sequence == 1
    assert entry_tamper.reason == "entry HMAC mismatch"

    database_2, _, audit_2, cases_2 = configured_services(tmp_path / "checkpoint")
    cases_2.add_note(analyst, CASE_ID, "Checkpoint observation", NOW)
    with database_2.connect() as connection:
        connection.execute("DROP TRIGGER audit_checkpoints_no_update")
        connection.execute(
            "UPDATE audit_checkpoints SET signature = ? WHERE tenant_id = ?",
            ("0" * 64, TENANT_A),
        )
    checkpoint_tamper = audit_2.verify(TENANT_A)
    assert checkpoint_tamper.valid is False
    assert checkpoint_tamper.reason == "checkpoint HMAC mismatch"

    database_3, _, audit_3, cases_3 = configured_services(tmp_path / "tail")
    cases_3.add_note(analyst, CASE_ID, "Tail observation", NOW)
    with database_3.connect() as connection:
        connection.execute("DROP TRIGGER audit_log_no_delete")
        connection.execute("DELETE FROM audit_log WHERE tenant_id = ?", (TENANT_A,))
    tail_tamper = audit_3.verify(TENANT_A)
    assert tail_tamper.valid is False
    assert tail_tamper.reason == "checkpoint count does not match entry count"


def test_audit_append_requires_transaction_and_bounded_payload(tmp_path: Path) -> None:
    database, _, audit, _ = configured_services(tmp_path)
    with database.connect() as connection:
        with pytest.raises(AuditError):
            audit.append(
                connection,
                TENANT_A,
                "case.note_added",
                "user",
                "analyst-a",
                "case",
                CASE_ID,
                {},
                NOW,
            )
        connection.execute("BEGIN IMMEDIATE")
        with pytest.raises(AuditError):
            audit.append(
                connection,
                TENANT_A,
                "case.note_added",
                "user",
                "analyst-a",
                "case",
                CASE_ID,
                {"oversized": "x" * 70_000},
                NOW,
            )
        connection.execute("ROLLBACK")


def test_case_mutation_rolls_back_when_audit_append_fails(tmp_path: Path) -> None:
    database, _, _, cases = configured_services(tmp_path)
    analyst = principal(TENANT_A, "analyst-a", "analyst")
    with database.connect() as connection:
        connection.execute(
            """
            CREATE TRIGGER reject_test_audit
            BEFORE INSERT ON audit_log
            BEGIN
                SELECT RAISE(ABORT, 'test audit failure');
            END
            """
        )

    with pytest.raises(sqlite3.IntegrityError):
        cases.add_note(analyst, CASE_ID, "Must roll back with audit.", NOW)

    with database.connect() as connection:
        assert connection.execute("SELECT COUNT(*) FROM case_activity").fetchone()[0] == 0
        case = connection.execute(
            "SELECT version FROM cases WHERE tenant_id = ? AND case_id = ?",
            (TENANT_A, CASE_ID),
        ).fetchone()
        assert int(case["version"]) == 1


def authenticated_api(
    tmp_path: Path,
) -> tuple[TestClient, str, StandaloneDatabase]:
    database, identity, _, cases = configured_services(tmp_path)
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
            ) VALUES (?, ?, 'analyst-a', ?, ?, ?, ?, ?)
            """,
            (
                TENANT_A,
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
            replay=DecisionReplayService(database, [], "case-api-v1"),
            cases=cases,
        ),
        ORIGIN,
        clock=lambda: NOW,
    )
    client = TestClient(app, base_url=ORIGIN)
    client.cookies.set(SESSION_COOKIE, token)
    return client, csrf_token, database


def test_case_api_enforces_csrf_and_exposes_audit_verification(tmp_path: Path) -> None:
    client, csrf_token, _ = authenticated_api(tmp_path)
    mutation_headers = {"origin": ORIGIN, "x-csrf-token": csrf_token}

    assert client.get(f"/v1/cases/{CASE_ID}").status_code == 200
    assert (
        client.post(f"/v1/cases/{CASE_ID}/notes", json={"note": "Missing CSRF"}).status_code == 403
    )
    assignment = client.post(
        f"/v1/cases/{CASE_ID}/assignment",
        headers=mutation_headers,
        json={"assignee_user_id": "responder-a"},
    )
    assert assignment.status_code == 200
    assert assignment.json()["assignee_user_id"] == "responder-a"
    note = client.post(
        f"/v1/cases/{CASE_ID}/notes",
        headers=mutation_headers,
        json={"note": "Reviewed deterministic evidence."},
    )
    assert note.status_code == 201
    investigated = client.post(
        f"/v1/cases/{CASE_ID}/transitions",
        headers=mutation_headers,
        json={"status": "investigating"},
    )
    assert investigated.status_code == 200
    missing_reason = client.post(
        f"/v1/cases/{CASE_ID}/dispositions",
        headers=mutation_headers,
        json={"status": "false_positive", "rationale": "Expected activity"},
    )
    assert missing_reason.status_code == 400
    disposition = client.post(
        f"/v1/cases/{CASE_ID}/dispositions",
        headers=mutation_headers,
        json={
            "status": "false_positive",
            "rationale": "Expected activity from signed internal tooling.",
            "false_positive_reason": "Trusted internal software",
        },
    )
    assert disposition.status_code == 201
    closed = client.post(
        f"/v1/cases/{CASE_ID}/transitions",
        headers=mutation_headers,
        json={"status": "closed"},
    )
    assert closed.status_code == 200
    assert closed.json()["status"] == "closed"

    verification = client.get("/v1/audit/verify")
    assert verification.status_code == 200
    assert verification.json()["valid"] is True
    assert verification.json()["entries_checked"] == 5
