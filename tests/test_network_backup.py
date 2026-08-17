"""Whole-appliance recovery must preserve every network and its identity state."""

from __future__ import annotations

import base64
import hashlib
import json
import sqlite3
import struct
from datetime import timedelta
from pathlib import Path

import pytest
from pydantic import ValidationError
from test_network_accounts import PEPPER
from test_network_accounts import network_setup as make_network_setup
from test_standalone_backup import TENANT_ID, configured_backup, event, event_count
from test_standalone_identity import NOW, ORIGIN

from controlforge.standalone.backup import (
    ApplianceOperationLock,
    BackupError,
    BackupManifest,
    RestoreOfflineError,
    StandaloneBackupService,
)
from controlforge.standalone.database import StandaloneDatabase
from controlforge.standalone.network_routing import NetworkRoutingService
from controlforge.standalone.secrets import StandaloneSecretBundle
from controlforge.standalone.settings import StandaloneSettings
from controlforge.standalone.store import StandaloneStore

SECOND = "00000000-0000-4000-8000-000000000002"
THIRD = "00000000-0000-4000-8000-000000000003"


@pytest.fixture
def network_setup(tmp_path: Path):
    return make_network_setup.__wrapped__(tmp_path)


def manifest_bytes(path: Path) -> bytes:
    data = path.read_bytes()
    size = struct.unpack(">I", data[10:14])[0]
    return data[14 : 14 + size]


def configured_multi(tmp_path: Path):
    database, store, bundle, backups = configured_backup(tmp_path)
    store.create_tenant(SECOND, "second", "Private second network", NOW)
    return database, store, bundle, backups


def tenant_ids(database: StandaloneDatabase) -> tuple[str, ...]:
    with database.connect() as connection:
        return tuple(
            row[0] for row in connection.execute("SELECT tenant_id FROM tenants ORDER BY 1")
        )


def test_single_network_keeps_legacy_manifest(tmp_path: Path):
    database, _, _, backups = configured_backup(tmp_path)
    created = backups.create_backup(now=NOW)
    path = backups.backup_directory / created.filename
    metadata = json.loads(manifest_bytes(path))
    assert metadata["format_version"] == 1
    assert "tenant_ids" not in metadata
    assert backups.verify_backup(path).tenant_ids == (TENANT_ID,)
    assert backups.restore_backup(path, NOW).backup_id == created.backup_id
    assert tenant_ids(database) == (TENANT_ID,)


def test_whole_appliance_restores_accounts_devices_resets_and_audit(network_setup, tmp_path):
    database, networks, accounts, owner, admin, alpha, beta, enrollment, _ = network_setup
    bundle = StandaloneSecretBundle(PEPPER, b"r" * 32, b"c" * 32, b"a" * 32)
    backups = StandaloneBackupService(database, bundle, tmp_path / "backups")
    routing = NetworkRoutingService(networks, ORIGIN)
    routing.configure(owner.principal, str(alpha["tenant_id"]), True, 1, NOW)
    logins = []
    credentials = []
    initial_passwords = []
    for principal in (admin.principal, networks.scope(owner.principal, str(beta["tenant_id"]))):
        account = accounts.create_account(principal, "alex", "Private Alex", NOW)
        initial_passwords.append(str(account["initial_password"]))
        first = accounts.login(str(account["username"]), initial_passwords[-1], NOW)
        phrase = "One complete appliance recovery passphrase!"
        ready = accounts.change_password(str(first["token"]), phrase, NOW)
        grant = accounts.enrollment_grant(str(ready["token"]), "shared-mac", NOW)
        credentials.append(
            enrollment.claim_grant(str(grant["token"]), "shared-mac", "Private Mac", "macos", NOW)
        )
        accounts.request_reset(str(account["username"]), NOW)
        logins.append((str(account["username"]), phrase))
    before_ids = tenant_ids(database)
    created = backups.create_backup(now=NOW)
    path = backups.backup_directory / created.filename
    metadata = json.loads(manifest_bytes(path))
    assert metadata["format_version"] == 2
    assert metadata["tenant_id"] == owner.principal.tenant_id
    assert metadata["tenant_ids"] == list(before_ids)
    assert len(created.tenant_ids) == 3
    assert backups.verify_backup(path).tenant_ids == before_ids
    assert backups.inventory()[0].tenant_ids == before_ids
    for marker in [
        "Private Alex",
        "Private Mac",
        *initial_passwords,
        *[item[0] for item in logins],
    ]:
        assert marker.encode() not in path.read_bytes()
    assert bundle.credential_key not in path.read_bytes()

    # Changes after the snapshot disappear together, across both networks.
    for principal in (admin.principal, networks.scope(owner.principal, str(beta["tenant_id"]))):
        pending = accounts.reset_requests(principal)
        accounts.reset_password(principal, str(pending[0]["request_id"]), NOW)
        assert accounts.reset_requests(principal) == []
    routing.configure(owner.principal, str(alpha["tenant_id"]), False, 2, NOW)
    backups.restore_backup(path, NOW + timedelta(seconds=1))
    assert tenant_ids(database) == before_ids
    assert networks.is_owner(owner.principal)
    assert accounts.login(*logins[0], NOW)["account"]["tenant_id"] == alpha["tenant_id"]
    assert accounts.login(*logins[1], NOW)["account"]["tenant_id"] == beta["tenant_id"]
    for network in (alpha, beta):
        principal = networks.scope(owner.principal, str(network["tenant_id"]))
        assert len(accounts.reset_requests(principal)) == 1
        assert networks.audit.verify(str(network["tenant_id"])).valid
    with database.connect() as connection:
        assert (
            connection.execute("SELECT COUNT(*) FROM account_enrollment_grants").fetchone()[0] == 2
        )
        assert connection.execute("SELECT COUNT(*) FROM device_credentials").fetchone()[0] == 2
        assert connection.execute("SELECT COUNT(*) FROM platform_owners").fetchone()[0] == 1
        assert (
            connection.execute(
                "SELECT enabled FROM network_routes WHERE tenant_id=?", (alpha["tenant_id"],)
            ).fetchone()[0]
            == 1
        )
    assert credentials[0].credential_id != credentials[1].credential_id


def test_multi_network_backup_restores_to_empty_recovery_root(tmp_path: Path):
    _, _, bundle, backups = configured_multi(tmp_path / "source")
    created = backups.create_backup(now=NOW)
    target = StandaloneDatabase(StandaloneSettings(database_path=tmp_path / "recovery" / "new.db"))
    recovery = StandaloneBackupService(target, bundle, backups.backup_directory)
    assert (
        recovery.restore_backup(backups.backup_directory / created.filename, NOW).backup_id
        == created.backup_id
    )
    assert tenant_ids(target) == (TENANT_ID, SECOND)


@pytest.mark.parametrize("live_ids", [(TENANT_ID,), (TENANT_ID, THIRD), (TENANT_ID, SECOND, THIRD)])
def test_restore_never_overwrites_a_different_network_set(tmp_path: Path, live_ids):
    _, _, bundle, backups = configured_multi(tmp_path / "source")
    created = backups.create_backup(now=NOW)
    target = StandaloneDatabase(StandaloneSettings(database_path=tmp_path / "target.db"))
    target.initialize()
    store = StandaloneStore(target)
    for index, tenant in enumerate(live_ids):
        store.create_tenant(tenant, f"network-{index}", "Must survive", NOW)
    recovery = StandaloneBackupService(target, bundle, backups.backup_directory)
    with pytest.raises(BackupError, match="does not match the live appliance"):
        recovery.restore_backup(backups.backup_directory / created.filename, NOW)
    assert tenant_ids(target) == live_ids
    with target.connect() as connection:
        assert connection.execute(
            "SELECT COUNT(*) FROM tenants WHERE display_name='Must survive'"
        ).fetchone()[0] == len(live_ids)


def test_tenant_selector_does_not_export_other_networks(tmp_path: Path):
    database, _, _, backups = configured_multi(tmp_path)
    with pytest.raises(BackupError, match="tenant-scoped export"):
        backups.create_backup(TENANT_ID, NOW)
    assert list(backups.backup_directory.iterdir()) == []
    with database.connect() as connection:
        assert connection.execute("SELECT COUNT(*) FROM backup_history").fetchone()[0] == 0


@pytest.mark.parametrize("count", [0, 201])
def test_backup_rejects_empty_or_oversized_appliance_before_history(tmp_path: Path, count):
    database = StandaloneDatabase(StandaloneSettings(database_path=tmp_path / "bounded.db"))
    database.initialize()
    with database.connect() as connection:
        connection.executemany(
            """INSERT INTO tenants(tenant_id,slug,display_name,status,created_at)
               VALUES(?,?,?,'active',?)""",
            [(f"n{i}", f"n{i}", "Bounded network", NOW.isoformat()) for i in range(count)],
        )
    backups = StandaloneBackupService(
        database, StandaloneSecretBundle.load_or_create(tmp_path / "keys"), tmp_path / "backups"
    )
    with pytest.raises(BackupError, match="between 1 and 200"):
        backups.create_backup(now=NOW)
    assert list(backups.backup_directory.iterdir()) == []
    with database.connect() as connection:
        assert connection.execute("SELECT COUNT(*) FROM backup_history").fetchone()[0] == 0


@pytest.mark.parametrize("explicit", [False, True])
def test_scope_uses_consistent_snapshot_when_network_creation_races(
    tmp_path: Path, monkeypatch, explicit
):
    database, store, _, backups = configured_backup(tmp_path)
    snapshot = backups._snapshot_database

    def add_network(destination):
        store.create_tenant(SECOND, "second", "Created concurrently", NOW)
        snapshot(destination)

    monkeypatch.setattr(backups, "_snapshot_database", add_network)
    if explicit:
        with pytest.raises(BackupError, match="tenant-scoped export"):
            backups.create_backup(TENANT_ID, NOW)
        assert not list(backups.backup_directory.glob("*.cfbackup"))
    else:
        created = backups.create_backup(now=NOW)
        assert created.tenant_ids == tenant_ids(database) == (TENANT_ID, SECOND)
        assert (
            backups.verify_backup(backups.backup_directory / created.filename).tenant_ids
            == created.tenant_ids
        )


@pytest.mark.parametrize(
    "change",
    [
        {"format_version": 3},
        {"format_version": 1},
        {"tenant_ids": []},
        {"tenant_ids": [SECOND, TENANT_ID]},
        {"tenant_ids": [TENANT_ID, TENANT_ID]},
        {"tenant_ids": [SECOND]},
        {"tenant_ids": [TENANT_ID, "x" * 129]},
        {"tenant_ids": [TENANT_ID, *[f"z{i:03}" for i in range(200)]]},
    ],
)
def test_network_manifest_rejects_ambiguous_or_unbounded_scope(tmp_path: Path, change):
    _, _, _, backups = configured_multi(tmp_path)
    created = backups.create_backup(now=NOW)
    metadata = json.loads(manifest_bytes(backups.backup_directory / created.filename))
    with pytest.raises(ValidationError):
        BackupManifest.model_validate({**metadata, **change})


@pytest.mark.parametrize("kind", ["inventory", "history"])
def test_authenticated_metadata_must_match_database_before_replacement(tmp_path: Path, kind):
    database, store, _, backups = configured_multi(tmp_path)
    created = backups.create_backup(now=NOW)
    source = backups.backup_directory / created.filename
    snapshot = tmp_path / "test-snapshot.db"
    manifest = backups._decrypt_artifact(source, snapshot)
    if kind == "inventory":
        manifest = manifest.model_copy(update={"tenant_ids": [TENANT_ID, THIRD]})
    else:
        connection = sqlite3.connect(snapshot)
        try:
            connection.execute("DELETE FROM backup_history WHERE backup_id=?", (created.backup_id,))
            connection.commit()
            connection.execute("PRAGMA wal_checkpoint(TRUNCATE)")
        finally:
            connection.close()
        manifest = manifest.model_copy(
            update={
                "database_sha256": hashlib.sha256(snapshot.read_bytes()).hexdigest(),
                "database_size_bytes": snapshot.stat().st_size,
            }
        )
    # Test-key holder creates a valid GCM artifact with contradictory metadata.
    # Authentication alone must not be treated as proof of safe restoration.
    altered = backups.backup_directory / "contradictory.cfbackup"
    backups._encrypt_snapshot(
        snapshot,
        altered,
        manifest,
        base64.urlsafe_b64decode(manifest.salt + "=="),
        base64.urlsafe_b64decode(manifest.nonce),
    )
    store.ingest_event(TENANT_ID, event("live-event", "must survive rejection"), NOW)
    with pytest.raises(BackupError, match="manifest does not match"):
        backups.restore_backup(altered, NOW)
    assert event_count(database) == 1
    assert tenant_ids(database) == (TENANT_ID, SECOND)


def test_backup_holds_operation_lock_before_history_and_releases_on_failure(
    tmp_path: Path, monkeypatch
):
    database, _, _, backups = configured_multi(tmp_path)
    original = backups._record_started

    def record(*args):
        with (
            pytest.raises(RestoreOfflineError),
            ApplianceOperationLock(database.settings.database_path).exclusive(),
        ):
            pytest.fail("restore must not overlap backup history writes")
        original(*args)
        raise BackupError("injected failure")

    monkeypatch.setattr(backups, "_record_started", record)
    with pytest.raises(BackupError, match="injected"):
        backups.create_backup(now=NOW)
    with ApplianceOperationLock(database.settings.database_path).exclusive():
        pass
