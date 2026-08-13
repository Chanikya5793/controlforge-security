from __future__ import annotations

import json
import os
import stat
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from controlforge import cli
from controlforge.models import SecurityEvent
from controlforge.standalone.backup import (
    ApplianceOperationLock,
    BackupError,
    RestoreOfflineError,
    StandaloneBackupService,
)
from controlforge.standalone.database import StandaloneDatabase
from controlforge.standalone.diagnostics import StandaloneDiagnosticsService
from controlforge.standalone.runtime import StandaloneRuntimeConfig, build_standalone_runtime
from controlforge.standalone.secrets import (
    SecretProvisioningError,
    StandaloneSecretBundle,
)
from controlforge.standalone.settings import StandaloneSettings
from controlforge.standalone.store import StandaloneStore

NOW = datetime(2026, 8, 22, 12, 0, tzinfo=timezone.utc)
TENANT_ID = "00000000-0000-4000-8000-000000000001"


def configured_backup(
    tmp_path: Path,
    *,
    retention_count: int = 10,
) -> tuple[
    StandaloneDatabase,
    StandaloneStore,
    StandaloneSecretBundle,
    StandaloneBackupService,
]:
    database = StandaloneDatabase(
        StandaloneSettings(database_path=tmp_path / "controlforge-standalone.db")
    )
    database.initialize()
    database.settings.database_path.chmod(0o600)
    store = StandaloneStore(database)
    store.create_tenant(TENANT_ID, "controlforge", "ControlForge", NOW)
    store.register_device(TENANT_ID, "mac-1", "Primary Mac", "macos", NOW)
    secret_bundle = StandaloneSecretBundle.load_or_create(tmp_path / "secrets")
    backups = StandaloneBackupService(
        database,
        secret_bundle,
        tmp_path / "backups",
        retention_count=retention_count,
    )
    return database, store, secret_bundle, backups


def event(event_id: str, marker: str) -> SecurityEvent:
    return SecurityEvent(
        event_id=event_id,
        event_type="endpoint_control_status",
        timestamp=NOW,
        actor=f"device:{marker}",
        device_id="mac-1",
        attributes={"status": "healthy", "raw_marker": marker},
    )


def event_count(database: StandaloneDatabase) -> int:
    with database.connect() as connection:
        return int(connection.execute("SELECT COUNT(*) FROM events").fetchone()[0])


def test_backup_is_encrypted_authenticated_and_restores_atomically(tmp_path: Path) -> None:
    database, store, secrets, backups = configured_backup(tmp_path)
    store.ingest_event(TENANT_ID, event("event-1", "raw-telemetry-secret-marker"), NOW)

    created = backups.create_backup(now=NOW)
    artifact = backups.backup_directory / created.filename
    artifact_bytes = artifact.read_bytes()

    assert created.verified is True
    assert stat.S_IMODE(artifact.stat().st_mode) == 0o600
    assert b"raw-telemetry-secret-marker" not in artifact_bytes
    assert secrets.credential_key not in artifact_bytes
    assert backups.verify_backup(artifact).artifact_sha256 == created.artifact_sha256
    assert [entry.backup_id for entry in backups.inventory()] == [created.backup_id]

    store.ingest_event(
        TENANT_ID,
        event("event-after-backup", "must-disappear-after-restore"),
        NOW + timedelta(minutes=1),
    )
    assert event_count(database) == 2

    restored = backups.restore_backup(artifact, NOW + timedelta(minutes=2))

    assert restored.backup_id == created.backup_id
    assert event_count(database) == 1
    assert stat.S_IMODE(database.settings.database_path.stat().st_mode) == 0o600
    with database.connect() as connection:
        history = connection.execute(
            "SELECT status FROM backup_history WHERE backup_id = ?",
            (created.backup_id,),
        ).fetchone()
    assert history["status"] == "restored"


def test_tamper_or_wrong_key_never_replaces_live_database(tmp_path: Path) -> None:
    database, store, _, backups = configured_backup(tmp_path)
    store.ingest_event(TENANT_ID, event("event-1", "original"), NOW)
    created = backups.create_backup(now=NOW)
    artifact = backups.backup_directory / created.filename
    original_artifact = artifact.read_bytes()
    store.ingest_event(TENANT_ID, event("event-2", "live-state"), NOW + timedelta(minutes=1))

    other_secrets = StandaloneSecretBundle.load_or_create(tmp_path / "other-secrets")
    wrong_key_service = StandaloneBackupService(
        database,
        other_secrets,
        backups.backup_directory,
    )
    with pytest.raises(BackupError, match="authentication"):
        wrong_key_service.verify_backup(artifact)
    assert event_count(database) == 2

    tampered = bytearray(original_artifact)
    tampered[-17] ^= 0x01
    artifact.write_bytes(tampered)
    artifact.chmod(0o600)

    with pytest.raises(BackupError, match="authentication"):
        backups.restore_backup(artifact, NOW + timedelta(minutes=2))
    assert event_count(database) == 2


def test_authenticated_manifest_tamper_is_rejected(tmp_path: Path) -> None:
    _, store, _, backups = configured_backup(tmp_path)
    store.ingest_event(TENANT_ID, event("event-1", "original"), NOW)
    created = backups.create_backup(now=NOW)
    artifact = backups.backup_directory / created.filename
    tampered = artifact.read_bytes().replace(
        TENANT_ID.encode(),
        b"00000000-0000-4000-8000-000000000002",
        1,
    )
    assert tampered != artifact.read_bytes()
    artifact.write_bytes(tampered)
    artifact.chmod(0o600)

    with pytest.raises(BackupError, match="authentication"):
        backups.verify_backup(artifact)


def test_restore_requires_exclusive_offline_lock(tmp_path: Path) -> None:
    database, store, _, backups = configured_backup(tmp_path)
    store.ingest_event(TENANT_ID, event("event-1", "original"), NOW)
    created = backups.create_backup(now=NOW)
    artifact = backups.backup_directory / created.filename
    store.ingest_event(TENANT_ID, event("event-2", "live-state"), NOW + timedelta(minutes=1))
    runtime_lock = ApplianceOperationLock(database.settings.database_path)
    runtime_lock.acquire_shared()
    try:
        with pytest.raises(RestoreOfflineError, match="must be stopped"):
            backups.restore_backup(artifact, NOW + timedelta(minutes=2))
    finally:
        runtime_lock.release()
    assert event_count(database) == 2


def test_restore_rejects_a_different_live_tenant_before_replacement(tmp_path: Path) -> None:
    _, store, secrets, backups = configured_backup(tmp_path / "source")
    store.ingest_event(TENANT_ID, event("event-1", "source"), NOW)
    created = backups.create_backup(now=NOW)
    artifact = backups.backup_directory / created.filename

    target_database = StandaloneDatabase(
        StandaloneSettings(database_path=tmp_path / "target" / "standalone.db")
    )
    target_database.initialize()
    target_store = StandaloneStore(target_database)
    target_tenant = "00000000-0000-4000-8000-000000000099"
    target_store.create_tenant(target_tenant, "other", "Other Tenant", NOW)
    target_service = StandaloneBackupService(
        target_database,
        secrets,
        backups.backup_directory,
    )

    with pytest.raises(BackupError, match="does not match the live appliance"):
        target_service.restore_backup(artifact, NOW + timedelta(minutes=1))
    with target_database.connect() as connection:
        tenants = connection.execute("SELECT tenant_id FROM tenants").fetchall()
    assert [str(row["tenant_id"]) for row in tenants] == [target_tenant]


def test_offline_restore_recovers_a_missing_database_with_preserved_keys(tmp_path: Path) -> None:
    _, store, secrets, backups = configured_backup(tmp_path / "source")
    store.ingest_event(TENANT_ID, event("event-1", "recoverable"), NOW)
    created = backups.create_backup(now=NOW)
    artifact = backups.backup_directory / created.filename
    recovery_database = StandaloneDatabase(
        StandaloneSettings(database_path=tmp_path / "recovery" / "standalone.db")
    )
    recovery_service = StandaloneBackupService(
        recovery_database,
        secrets,
        backups.backup_directory,
    )

    restored = recovery_service.restore_backup(artifact, NOW + timedelta(minutes=1))

    assert restored.backup_id == created.backup_id
    assert event_count(recovery_database) == 1
    assert stat.S_IMODE(recovery_database.settings.database_path.stat().st_mode) == 0o600


def test_runtime_lifetime_lock_releases_explicitly_for_restore(
    project_root: Path,
    tmp_path: Path,
) -> None:
    database, store, _, backups = configured_backup(tmp_path)
    store.ingest_event(TENANT_ID, event("event-1", "original"), NOW)
    created = backups.create_backup(now=NOW)
    artifact = backups.backup_directory / created.filename
    runtime = build_standalone_runtime(
        StandaloneRuntimeConfig(
            settings=database.settings,
            rules_directory=project_root / "rules",
            secret_directory=tmp_path / "secrets",
            admin_origin="https://localhost:8443",
            rp_id="localhost",
        )
    )
    try:
        with pytest.raises(RestoreOfflineError, match="must be stopped"):
            backups.restore_backup(artifact, NOW + timedelta(minutes=1))
    finally:
        runtime.close()

    assert (
        backups.restore_backup(artifact, NOW + timedelta(minutes=2)).backup_id == created.backup_id
    )


def test_retention_removes_only_old_verified_backups(tmp_path: Path) -> None:
    _, store, _, backups = configured_backup(tmp_path, retention_count=2)
    store.ingest_event(TENANT_ID, event("event-1", "retention"), NOW)

    first = backups.create_backup(now=NOW)
    second = backups.create_backup(now=NOW + timedelta(seconds=1))
    third = backups.create_backup(now=NOW + timedelta(seconds=2))

    entries = backups.inventory()
    assert [entry.backup_id for entry in entries] == [third.backup_id, second.backup_id]
    assert not (backups.backup_directory / first.filename).exists()


def test_diagnostics_are_bounded_and_contain_no_records_or_secrets(tmp_path: Path) -> None:
    database, store, secrets, backups = configured_backup(tmp_path)
    marker = "raw-record-must-not-enter-diagnostics"
    store.ingest_event(TENANT_ID, event("event-1", marker), NOW)
    backups.create_backup(now=NOW)

    report = StandaloneDiagnosticsService(database, backups).collect()
    serialized = json.dumps(report.as_dict(), sort_keys=True)

    assert report.status == "healthy"
    assert report.database.integrity_ok is True
    assert report.workload.events == 1
    assert report.backups.verified_backups == 1
    assert marker not in serialized
    assert secrets.credential_key.hex() not in serialized
    assert str(database.settings.database_path) not in serialized


def test_existing_secret_load_fails_closed_without_creating_material(tmp_path: Path) -> None:
    missing = tmp_path / "missing-secrets"
    with pytest.raises(SecretProvisioningError):
        StandaloneSecretBundle.load_existing(missing)
    assert not missing.exists()

    complete = tmp_path / "complete-secrets"
    StandaloneSecretBundle.load_or_create(complete)
    incomplete = tmp_path / "incomplete-secrets"
    incomplete.mkdir(mode=0o700)
    (incomplete / "credential.key").write_bytes(os.urandom(32))
    (incomplete / "credential.key").chmod(0o600)
    with pytest.raises(SecretProvisioningError):
        StandaloneSecretBundle.load_existing(incomplete)
    assert list(incomplete.iterdir()) == [incomplete / "credential.key"]


def test_existing_secret_load_rejects_symlinks_and_weak_permissions(tmp_path: Path) -> None:
    secure_directory = tmp_path / "secure-secrets"
    StandaloneSecretBundle.load_or_create(secure_directory)

    weak_directory = tmp_path / "weak-secrets"
    StandaloneSecretBundle.load_or_create(weak_directory)
    weak_directory.chmod(0o750)
    with pytest.raises(SecretProvisioningError, match="directory"):
        StandaloneSecretBundle.load_existing(weak_directory)

    weak_file_directory = tmp_path / "weak-file-secrets"
    StandaloneSecretBundle.load_or_create(weak_file_directory)
    (weak_file_directory / "credential.key").chmod(0o640)
    with pytest.raises(SecretProvisioningError, match="mode 0600"):
        StandaloneSecretBundle.load_existing(weak_file_directory)

    directory_symlink = tmp_path / "secret-directory-link"
    directory_symlink.symlink_to(secure_directory, target_is_directory=True)
    with pytest.raises(SecretProvisioningError, match="trusted directory"):
        StandaloneSecretBundle.load_existing(directory_symlink)

    file_symlink_directory = tmp_path / "file-symlink-secrets"
    StandaloneSecretBundle.load_or_create(file_symlink_directory)
    credential_path = file_symlink_directory / "credential.key"
    credential_path.unlink()
    credential_path.symlink_to(secure_directory / "credential.key")
    with pytest.raises(SecretProvisioningError, match="regular file"):
        StandaloneSecretBundle.load_existing(file_symlink_directory)


def test_operation_lock_rejects_symlink(tmp_path: Path) -> None:
    lock = ApplianceOperationLock(tmp_path / "controlforge.db")
    target = tmp_path / "unrelated-private-file"
    target.write_bytes(b"unchanged")
    target.chmod(0o600)
    lock.path.symlink_to(target)

    with pytest.raises(BackupError, match="lock is unavailable"):
        lock.acquire_shared()
    assert target.read_bytes() == b"unchanged"


def test_backup_and_diagnostics_cli_use_existing_secrets_only(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    database, store, secrets, backups = configured_backup(tmp_path)
    marker = "cli-record-must-remain-encrypted"
    store.ingest_event(TENANT_ID, event("event-1", marker), NOW)
    shared_arguments = [
        "--database",
        str(database.settings.database_path),
        "--secrets-directory",
        str(tmp_path / "secrets"),
        "--backup-directory",
        str(backups.backup_directory),
    ]

    assert cli.run(["standalone", "backup", "create", *shared_arguments]) == 0
    created_output = capsys.readouterr().out
    created = json.loads(created_output)
    assert created["verified"] is True
    assert marker not in created_output

    assert cli.run(["standalone", "backup", "list", *shared_arguments]) == 0
    listed_output = capsys.readouterr().out
    assert json.loads(listed_output)[0]["backup_id"] == created["backup_id"]

    assert cli.run(["standalone", "diagnostics", *shared_arguments]) == 0
    diagnostics_output = capsys.readouterr().out
    assert json.loads(diagnostics_output)["status"] == "healthy"
    assert marker not in diagnostics_output
    assert secrets.credential_key.hex() not in diagnostics_output
