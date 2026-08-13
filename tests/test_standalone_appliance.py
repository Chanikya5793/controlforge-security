from __future__ import annotations

import json
import os
import shutil
import sqlite3
import stat
from dataclasses import replace
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import cast

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID
from fastapi import FastAPI
from fastapi.testclient import TestClient

from controlforge.standalone.__main__ import run
from controlforge.standalone.appliance import (
    ApplianceLaunchConfig,
    AppliancePaths,
    AppliancePreflightError,
    StandaloneApplianceLifecycle,
)
from controlforge.standalone.database import StandaloneDatabase
from controlforge.standalone.migrations import INITIAL_SCHEMA, MIGRATIONS
from controlforge.standalone.secrets import StandaloneSecretBundle
from controlforge.standalone.settings import StandaloneSettings

TENANT_ID = "00000000-0000-4000-8000-000000000701"
NOW = datetime(2026, 8, 22, 22, 0, tzinfo=timezone.utc)
SUPPORTED_VERSIONS = tuple(migration.version for migration in MIGRATIONS)


def tls_material(
    tmp_path: Path,
    *,
    hostname: str = "localhost",
    private_key_mode: int = 0o600,
    not_before: datetime = NOW - timedelta(days=1),
    not_after: datetime = NOW + timedelta(days=45),
) -> tuple[Path, Path]:
    tmp_path.mkdir(mode=0o700, parents=True, exist_ok=True)
    key = rsa.generate_private_key(public_exponent=65_537, key_size=2_048)
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, hostname)])
    certificate = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(not_before)
        .not_valid_after(not_after)
        .add_extension(x509.SubjectAlternativeName([x509.DNSName(hostname)]), critical=False)
        .add_extension(
            x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]),
            critical=False,
        )
        .sign(key, hashes.SHA256())
    )
    certificate_path = tmp_path / "server-certificate.pem"
    private_key_path = tmp_path / "server-private-key.pem"
    certificate_path.write_bytes(certificate.public_bytes(serialization.Encoding.PEM))
    private_key_path.write_bytes(
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    certificate_path.chmod(0o644)
    private_key_path.chmod(private_key_mode)
    return certificate_path, private_key_path


def launch_config(
    tmp_path: Path,
    *,
    root: Path | None = None,
    rules_directory: Path = Path("rules"),
    hostname: str = "localhost",
    private_key_mode: int = 0o600,
) -> ApplianceLaunchConfig:
    certificate, private_key = tls_material(
        tmp_path,
        hostname=hostname,
        private_key_mode=private_key_mode,
    )
    return ApplianceLaunchConfig(
        root=root or tmp_path / "appliance",
        rules_directory=rules_directory,
        admin_origin="https://localhost:8443",
        rp_id="localhost",
        host="127.0.0.1",
        port=8443,
        tls_certificate=certificate,
        tls_private_key=private_key,
        worker_interval_seconds=0.1,
    )


def create_v1_appliance(config: ApplianceLaunchConfig) -> AppliancePaths:
    paths = AppliancePaths.from_root(config.root)
    for directory in (
        paths.root,
        paths.data_directory,
        paths.secrets_directory,
        paths.backup_directory,
    ):
        directory.mkdir(mode=0o700, parents=True, exist_ok=True)
        directory.chmod(0o700)
    connection = sqlite3.connect(paths.database)
    try:
        connection.executescript(
            """
            CREATE TABLE schema_migrations (
                version INTEGER PRIMARY KEY,
                name TEXT NOT NULL,
                applied_at TEXT NOT NULL
            );
            """
            + INITIAL_SCHEMA
        )
        connection.execute(
            "INSERT INTO schema_migrations VALUES (1, ?, ?)",
            (MIGRATIONS[0].name, NOW.isoformat()),
        )
        connection.execute(
            """
            INSERT INTO tenants(tenant_id, slug, display_name, status, created_at)
            VALUES (?, 'upgrade-fixture', 'Upgrade Fixture', 'active', ?)
            """,
            (TENANT_ID, NOW.isoformat()),
        )
        connection.commit()
    finally:
        connection.close()
    paths.database.chmod(0o600)
    StandaloneSecretBundle.load_or_create(paths.secrets_directory)
    return paths


def test_one_command_provisions_and_serves_without_external_provider(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    config = launch_config(tmp_path)
    calls: list[dict[str, object]] = []

    def server_runner(app: object, **kwargs: object) -> object:
        calls.append(kwargs)
        with TestClient(
            cast(FastAPI, app),
            base_url="https://localhost:8443",
        ) as client:
            health = client.get("/health")
            assert health.status_code == 200
            assert health.json()["worker"]["running"] is True
        return None

    result = run(
        [
            "serve",
            "--root",
            str(config.root),
            "--rules",
            str(config.rules_directory),
            "--admin-origin",
            config.admin_origin,
            "--rp-id",
            config.rp_id,
            "--host",
            config.host,
            "--port",
            str(config.port),
            "--tls-certificate",
            str(config.tls_certificate),
            "--tls-private-key",
            str(config.tls_private_key),
            "--worker-interval-seconds",
            "0.1",
        ],
        server_runner=server_runner,
    )

    output = capsys.readouterr()
    report = json.loads(output.out)
    token = output.err.strip().splitlines()[-1]
    paths = AppliancePaths.from_root(config.root)
    assert result == 0
    assert report["schema_state"] == "clean_install"
    assert report["schema_versions_after"] == list(SUPPORTED_VERSIONS)
    assert report["tls"]["identity_valid"] is True
    assert report["tls"]["browser_trust_verified"] is False
    assert len(token) >= 32
    assert calls == [
        {
            "host": "127.0.0.1",
            "port": 8443,
            "ssl_certfile": str(config.tls_certificate),
            "ssl_keyfile": str(config.tls_private_key),
        }
    ]
    for directory in (
        paths.root,
        paths.data_directory,
        paths.secrets_directory,
        paths.backup_directory,
    ):
        assert stat.S_IMODE(directory.stat().st_mode) == 0o700
    assert stat.S_IMODE(paths.database.stat().st_mode) == 0o600
    assert all(
        token.encode() not in path.read_bytes() for path in paths.root.rglob("*") if path.is_file()
    )


def test_tls_origin_identity_and_private_key_fail_closed(tmp_path: Path) -> None:
    wrong_host = launch_config(tmp_path / "wrong-host", hostname="other.example")
    with pytest.raises(AppliancePreflightError, match="does not match"):
        StandaloneApplianceLifecycle(wrong_host).preflight(NOW)

    weak_key = launch_config(tmp_path / "weak-key", private_key_mode=0o644)
    with pytest.raises(AppliancePreflightError, match="mode 0600"):
        StandaloneApplianceLifecycle(weak_key).preflight(NOW)

    wrong_origin = replace(
        launch_config(tmp_path / "wrong-origin"),
        admin_origin="https://localhost:9443",
    )
    with pytest.raises(AppliancePreflightError, match="port does not match"):
        StandaloneApplianceLifecycle(wrong_origin).preflight(NOW)

    key_source = launch_config(tmp_path / "key-source")
    mismatched = replace(
        launch_config(tmp_path / "certificate-source"),
        tls_private_key=key_source.tls_private_key,
    )
    with pytest.raises(AppliancePreflightError, match="does not match"):
        StandaloneApplianceLifecycle(mismatched).preflight(NOW)

    expired_certificate, expired_key = tls_material(
        tmp_path / "expired",
        not_before=NOW - timedelta(days=30),
        not_after=NOW - timedelta(seconds=1),
    )
    expired = replace(
        launch_config(tmp_path / "expired-config"),
        tls_certificate=expired_certificate,
        tls_private_key=expired_key,
    )
    with pytest.raises(AppliancePreflightError, match="not currently valid"):
        StandaloneApplianceLifecycle(expired).preflight(NOW)


def test_tls_renewal_window_degrades_health_without_stopping_preflight(tmp_path: Path) -> None:
    certificate, private_key = tls_material(
        tmp_path / "renewal-material",
        hostname="localhost",
        not_after=NOW + timedelta(days=20),
    )
    config = replace(
        launch_config(tmp_path / "renewal-appliance"),
        tls_certificate=certificate,
        tls_private_key=private_key,
    )
    lifecycle = StandaloneApplianceLifecycle(config)

    _, tls = lifecycle.preflight(NOW)

    assert tls.identity_valid is True
    assert tls.days_until_expiry == 20
    assert tls.renewal_status == "renewal_due"
    prepared = lifecycle.prepare_runtime(NOW, issue_bootstrap_token=False)
    prepared.runtime.close()
    report = lifecycle.health(NOW)
    assert report["status"] == "degraded"
    assert report["tls"] == {
        "hostname": "localhost",
        "certificate_subject": "CN=localhost",
        "not_before": (NOW - timedelta(days=1)).isoformat(),
        "not_after": (NOW + timedelta(days=20)).isoformat(),
        "key_algorithm": "RSA-2048",
        "identity_valid": True,
        "days_until_expiry": 20,
        "renewal_status": "renewal_due",
        "browser_trust_verified": False,
    }


def test_restart_rotates_unfinished_bootstrap_to_one_active_token(tmp_path: Path) -> None:
    lifecycle = StandaloneApplianceLifecycle(launch_config(tmp_path))
    first = lifecycle.prepare_runtime(NOW)
    first_token = first.bootstrap_token
    first.runtime.close()

    second = lifecycle.prepare_runtime(NOW + timedelta(seconds=1))
    second_token = second.bootstrap_token
    try:
        assert first_token is not None
        assert second_token is not None
        assert second_token != first_token
        with second.runtime.database.connect() as connection:
            active = connection.execute(
                """
                SELECT COUNT(*) FROM bootstrap_tokens
                WHERE used_at IS NULL AND revoked_at IS NULL
                """
            ).fetchone()[0]
            revoked = connection.execute(
                "SELECT COUNT(*) FROM bootstrap_tokens WHERE revoked_at IS NOT NULL"
            ).fetchone()[0]
        assert active == 1
        assert revoked == 1
    finally:
        second.runtime.close()


def test_upgrade_creates_encrypted_rollback_and_explicit_restore(tmp_path: Path) -> None:
    config = launch_config(tmp_path)
    paths = create_v1_appliance(config)
    lifecycle = StandaloneApplianceLifecycle(config)

    prepared = lifecycle.prepare_runtime(NOW, issue_bootstrap_token=False)
    backup_filename = prepared.report.rollback_backup_filename
    try:
        assert prepared.report.schema_state == "upgrade_required"
        assert prepared.report.schema_versions_before == (1,)
        assert prepared.report.schema_versions_after == SUPPORTED_VERSIONS
        assert backup_filename is not None
        artifact = paths.backup_directory / backup_filename
        assert artifact.read_bytes().startswith(b"CFBACKUP\x01\n")
        assert b"Upgrade Fixture" not in artifact.read_bytes()
        with prepared.runtime.database.connect() as connection:
            state = json.loads(
                connection.execute(
                    "SELECT value_json FROM appliance_state "
                    "WHERE state_key = 'last_startup_preflight'"
                ).fetchone()[0]
            )
        assert state["status"] == "ready"
        assert state["rollback_backup_filename"] == backup_filename
        health = lifecycle.health(NOW + timedelta(seconds=1))
        assert health["status"] == "healthy"
        assert health["last_startup_status"] == "ready"
        assert health["rollback_available"] is True
        diagnostics = health["diagnostics"]
        assert isinstance(diagnostics, dict)
        database_health = diagnostics["database"]
        assert isinstance(database_health, dict)
        assert database_health["integrity_ok"] is True
    finally:
        prepared.runtime.close()

    restored = lifecycle.rollback_upgrade(backup_filename, NOW + timedelta(minutes=1))
    assert restored.schema_versions == (1,)
    connection = sqlite3.connect(paths.database)
    try:
        versions = tuple(
            row[0]
            for row in connection.execute(
                "SELECT version FROM schema_migrations ORDER BY version"
            ).fetchall()
        )
        tenant = connection.execute("SELECT tenant_id FROM tenants").fetchone()[0]
    finally:
        connection.close()
    assert versions == (1,)
    assert tenant == TENANT_ID


def test_failed_upgrade_automatically_restores_preupgrade_database(tmp_path: Path) -> None:
    invalid_rules = tmp_path / "invalid-rules"
    invalid_rules.mkdir()
    (invalid_rules / "invalid.yml").write_text("not: [a valid rule")
    config = launch_config(tmp_path, rules_directory=invalid_rules)
    paths = create_v1_appliance(config)

    with pytest.raises(AppliancePreflightError, match="runtime preparation failed"):
        StandaloneApplianceLifecycle(config).prepare_runtime(
            NOW,
            issue_bootstrap_token=False,
        )

    connection = sqlite3.connect(paths.database)
    try:
        versions = tuple(
            row[0]
            for row in connection.execute(
                "SELECT version FROM schema_migrations ORDER BY version"
            ).fetchall()
        )
    finally:
        connection.close()
    assert versions == (1,)
    assert len(list(paths.backup_directory.glob("*.cfbackup"))) == 1


def test_newer_or_gapped_schema_is_rejected_without_mutation(tmp_path: Path) -> None:
    config = launch_config(tmp_path)
    paths = AppliancePaths.from_root(config.root)
    for directory in (
        paths.root,
        paths.data_directory,
        paths.secrets_directory,
        paths.backup_directory,
    ):
        directory.mkdir(mode=0o700, parents=True, exist_ok=True)
        directory.chmod(0o700)
    database = StandaloneDatabase(StandaloneSettings(database_path=paths.database))
    database.initialize()
    StandaloneSecretBundle.load_or_create(paths.secrets_directory)
    with database.connect() as connection:
        connection.execute(
            "INSERT INTO schema_migrations VALUES (999, 'future schema', ?)",
            (NOW.isoformat(),),
        )

    with pytest.raises(AppliancePreflightError, match="ledger is unsupported"):
        StandaloneApplianceLifecycle(config).preflight(NOW)

    with database.connect() as connection:
        assert (
            connection.execute("SELECT name FROM schema_migrations WHERE version = 999").fetchone()[
                0
            ]
            == "future schema"
        )


def test_schema_name_mismatch_is_rejected_before_upgrade(tmp_path: Path) -> None:
    config = launch_config(tmp_path)
    paths = create_v1_appliance(config)
    connection = sqlite3.connect(paths.database)
    try:
        connection.execute(
            "UPDATE schema_migrations SET name = 'unexpected migration' WHERE version = 1"
        )
        connection.commit()
    finally:
        connection.close()

    with pytest.raises(AppliancePreflightError, match="ledger is unsupported"):
        StandaloneApplianceLifecycle(config).preflight(NOW)

    assert not list(paths.backup_directory.glob("*.cfbackup"))


def test_appliance_paths_reject_weak_or_redirected_state(tmp_path: Path) -> None:
    weak_root = tmp_path / "weak-root"
    weak_root.mkdir(mode=0o755)
    weak_root.chmod(0o755)
    config = launch_config(tmp_path / "weak-root-config", root=weak_root)
    with pytest.raises(AppliancePreflightError, match="mode 0700"):
        StandaloneApplianceLifecycle(config).preflight(NOW)

    redirected_root = tmp_path / "redirected-root"
    target = tmp_path / "target-root"
    target.mkdir(mode=0o700)
    redirected_root.symlink_to(target, target_is_directory=True)
    redirected = launch_config(tmp_path / "redirected-config", root=redirected_root)
    with pytest.raises(AppliancePreflightError, match="trusted directory"):
        StandaloneApplianceLifecycle(redirected).preflight(NOW)


def test_appliance_rejects_writable_or_redirected_detection_rules(
    tmp_path: Path,
    project_root: Path,
) -> None:
    rules = tmp_path / "rules"
    shutil.copytree(project_root / "rules", rules)
    weak_rule = rules / "encoded_powershell.yml"
    weak_rule.chmod(0o666)
    weak = launch_config(tmp_path / "weak-rule", rules_directory=rules)

    with pytest.raises(AppliancePreflightError, match="not a trusted file"):
        StandaloneApplianceLifecycle(weak).preflight(NOW)

    weak_rule.chmod(0o644)
    target = rules / "credential_dumping.yml"
    target.unlink()
    target.symlink_to(project_root / "rules/credential_dumping.yml")
    redirected = launch_config(tmp_path / "redirected-rule", rules_directory=rules)
    with pytest.raises(AppliancePreflightError, match="not a trusted file"):
        StandaloneApplianceLifecycle(redirected).preflight(NOW)


def test_preflight_does_not_accept_naive_time(tmp_path: Path) -> None:
    with pytest.raises(ValueError, match="timezone-aware"):
        StandaloneApplianceLifecycle(launch_config(tmp_path)).preflight(
            datetime(2026, 8, 22, 22, 0)
        )


def test_private_key_is_never_group_or_world_readable(tmp_path: Path) -> None:
    config = launch_config(tmp_path)
    assert stat.S_IMODE(os.stat(config.tls_private_key).st_mode) == 0o600
