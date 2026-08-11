from __future__ import annotations

import sqlite3
import stat
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest
from pydantic import ValidationError

from controlforge.models import SecurityEvent
from controlforge.standalone import (
    EventIdentityConflict,
    StandaloneDatabase,
    StandaloneSettings,
    StandaloneStore,
)
from controlforge.standalone.database import StandaloneDatabaseSecurityError
from controlforge.standalone.migrations import MIGRATIONS

NOW = datetime(2026, 8, 22, 12, 0, tzinfo=timezone.utc)
TENANT_ID = "00000000-0000-4000-8000-000000000001"


def configured_store(tmp_path: Path) -> tuple[StandaloneDatabase, StandaloneStore]:
    settings = StandaloneSettings(database_path=tmp_path / "standalone.db")
    database = StandaloneDatabase(settings)
    database.initialize()
    store = StandaloneStore(database)
    store.create_tenant(TENANT_ID, "controlforge", "ControlForge", NOW)
    store.register_device(TENANT_ID, "mac-1", "Primary Mac", "macos", NOW)
    return database, store


def endpoint_event(event_id: str = "event-1", *, actor: str = "device:mac-1") -> SecurityEvent:
    return SecurityEvent(
        event_id=event_id,
        event_type="endpoint_control_status",
        timestamp=NOW,
        actor=actor,
        device_id="mac-1",
        attributes={"status": "healthy"},
    )


def test_settings_load_and_validate_environment(tmp_path: Path) -> None:
    settings = StandaloneSettings.from_environment(
        {
            "CONTROLFORGE_STANDALONE_DATABASE": str(tmp_path / "env.db"),
            "CONTROLFORGE_SQLITE_BUSY_TIMEOUT_MS": "2500",
            "CONTROLFORGE_WORKER_LEASE_SECONDS": "30",
            "CONTROLFORGE_WORKER_MAX_ATTEMPTS": "7",
        }
    )

    assert settings.database_path == tmp_path / "env.db"
    assert settings.busy_timeout_ms == 2_500
    assert settings.worker_lease_seconds == 30
    assert settings.worker_max_attempts == 7
    with pytest.raises(ValidationError):
        StandaloneSettings(busy_timeout_ms=0)


def test_initialize_is_idempotent_and_configures_every_connection(tmp_path: Path) -> None:
    database, _ = configured_store(tmp_path)
    database.initialize()

    assert database.applied_versions() == tuple(migration.version for migration in MIGRATIONS)
    assert stat.S_IMODE(database.settings.database_path.stat().st_mode) == 0o600
    with database.connect() as connection:
        assert connection.execute("PRAGMA journal_mode").fetchone()[0] == "wal"
        assert connection.execute("PRAGMA foreign_keys").fetchone()[0] == 1
        assert connection.execute("PRAGMA busy_timeout").fetchone()[0] == 5_000
        tables = {
            row["name"]
            for row in connection.execute("SELECT name FROM sqlite_master WHERE type = 'table'")
        }
    assert {
        "schema_migrations",
        "tenants",
        "users",
        "sessions",
        "passkey_credentials",
        "bootstrap_tokens",
        "auth_challenges",
        "human_invites",
        "human_invite_challenges",
        "recovery_codes",
        "devices",
        "device_credentials",
        "device_auth_nonces",
        "enrollment_tokens",
        "events",
        "detection_jobs",
        "alerts",
        "cases",
        "case_activity",
        "dispositions",
        "response_actions",
        "audit_log",
        "audit_checkpoints",
        "backup_history",
        "appliance_state",
        "retention_policies",
        "retention_runs",
    }.issubset(tables)


def test_initialize_rejects_weak_or_redirected_database_paths(tmp_path: Path) -> None:
    weak = tmp_path / "weak.db"
    weak.touch(mode=0o644)
    with pytest.raises(StandaloneDatabaseSecurityError, match="mode 0600"):
        StandaloneDatabase(StandaloneSettings(database_path=weak)).initialize()

    target = tmp_path / "target.db"
    target.touch(mode=0o600)
    redirected = tmp_path / "redirected.db"
    redirected.symlink_to(target)
    with pytest.raises(StandaloneDatabaseSecurityError, match="regular file"):
        StandaloneDatabase(StandaloneSettings(database_path=redirected)).initialize()


def test_concurrent_initializers_serialize_migration_application(tmp_path: Path) -> None:
    settings = StandaloneSettings(database_path=tmp_path / "concurrent.db")

    with ThreadPoolExecutor(max_workers=2) as executor:
        results = list(
            executor.map(
                lambda _: StandaloneDatabase(settings).initialize(),
                range(2),
            )
        )

    assert results == [None, None]
    assert StandaloneDatabase(settings).applied_versions() == tuple(
        migration.version for migration in MIGRATIONS
    )


def test_device_credentials_are_bound_to_an_existing_device(tmp_path: Path) -> None:
    database, _ = configured_store(tmp_path)

    with database.connect() as connection, pytest.raises(sqlite3.IntegrityError):
        connection.execute(
            """
            INSERT INTO device_credentials(
                credential_id, tenant_id, device_id, name, secret_ciphertext,
                secret_iv, created_at, expires_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                "credential-1",
                TENANT_ID,
                "another-device",
                "primary",
                "ciphertext",
                "iv",
                NOW.isoformat(),
                (NOW + timedelta(days=30)).isoformat(),
            ),
        )


def test_event_and_job_are_atomic_idempotent_and_collision_safe(tmp_path: Path) -> None:
    database, store = configured_store(tmp_path)
    event = endpoint_event()

    first = store.ingest_event(TENANT_ID, event, NOW)
    duplicate = store.ingest_event(TENANT_ID, event, NOW + timedelta(seconds=1))

    assert first.accepted is True
    assert duplicate.accepted is False
    assert duplicate.job_id == first.job_id
    with database.connect() as connection:
        event_count = connection.execute("SELECT COUNT(*) FROM events").fetchone()[0]
        job_count = connection.execute("SELECT COUNT(*) FROM detection_jobs").fetchone()[0]
    assert event_count == 1
    assert job_count == 1

    with pytest.raises(EventIdentityConflict):
        store.ingest_event(
            TENANT_ID,
            endpoint_event(actor="device:spoofed"),
            NOW + timedelta(seconds=2),
        )


def test_unknown_device_rolls_back_both_event_and_job(tmp_path: Path) -> None:
    database, store = configured_store(tmp_path)
    event = endpoint_event("unknown-device").model_copy(update={"device_id": "missing"})

    with pytest.raises(sqlite3.IntegrityError):
        store.ingest_event(TENANT_ID, event, NOW)
    with database.connect() as connection:
        assert connection.execute("SELECT COUNT(*) FROM events").fetchone()[0] == 0
        assert connection.execute("SELECT COUNT(*) FROM detection_jobs").fetchone()[0] == 0


def test_job_retry_dead_letter_and_lease_ownership(tmp_path: Path) -> None:
    _, store = configured_store(tmp_path)
    ingested = store.ingest_event(TENANT_ID, endpoint_event(), NOW)

    first = store.lease_jobs(TENANT_ID, "worker-a", 10, NOW, 30)
    assert len(first) == 1
    assert first[0].attempts == 1
    assert store.lease_jobs(TENANT_ID, "worker-b", 10, NOW, 30) == []
    rejected = store.complete_job(TENANT_ID, ingested.job_id, "worker-b", NOW)
    assert rejected.changed is False
    assert rejected.status == "leased"

    retry = store.fail_job(
        TENANT_ID,
        ingested.job_id,
        "worker-a",
        NOW,
        "temporary detector failure",
        max_attempts=2,
        retry_delay_seconds=10,
    )
    assert retry.changed is True
    assert retry.status == "retry"
    assert store.lease_jobs(TENANT_ID, "worker-b", 10, NOW + timedelta(seconds=9), 30) == []

    second = store.lease_jobs(TENANT_ID, "worker-b", 10, NOW + timedelta(seconds=10), 30)
    assert second[0].attempts == 2
    dead = store.fail_job(
        TENANT_ID,
        ingested.job_id,
        "worker-b",
        NOW + timedelta(seconds=10),
        "permanent detector failure",
        max_attempts=2,
        retry_delay_seconds=10,
    )
    assert dead.status == "dead"
    assert store.job_counts(TENANT_ID)["dead"] == 1
    assert store.lease_jobs(TENANT_ID, "worker-c", 10, NOW + timedelta(hours=1), 30) == []


def test_expired_lease_is_reclaimed_and_success_is_terminal(tmp_path: Path) -> None:
    _, store = configured_store(tmp_path)
    ingested = store.ingest_event(TENANT_ID, endpoint_event(), NOW)

    store.lease_jobs(TENANT_ID, "dead-worker", 1, NOW, 5)
    reclaimed = store.lease_jobs(
        TENANT_ID,
        "replacement-worker",
        1,
        NOW + timedelta(seconds=5),
        30,
    )

    assert reclaimed[0].attempts == 2
    completed = store.complete_job(
        TENANT_ID,
        ingested.job_id,
        "replacement-worker",
        NOW + timedelta(seconds=6),
    )
    assert completed.status == "succeeded"
    assert store.lease_jobs(TENANT_ID, "worker-c", 1, NOW + timedelta(hours=1), 30) == []


def test_jobs_lease_in_event_time_order_for_stateful_detection(tmp_path: Path) -> None:
    _, store = configured_store(tmp_path)
    late = endpoint_event("late").model_copy(update={"timestamp": NOW + timedelta(minutes=1)})
    early = endpoint_event("early").model_copy(update={"timestamp": NOW})
    store.ingest_events(TENANT_ID, [late, early], NOW + timedelta(minutes=2))

    leases = store.lease_jobs(
        TENANT_ID,
        "ordered-worker",
        2,
        NOW + timedelta(minutes=2),
        30,
    )

    assert [lease.event_id for lease in leases] == ["early", "late"]
