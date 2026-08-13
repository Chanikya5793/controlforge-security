from __future__ import annotations

import os
import stat
from datetime import datetime, timezone
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from controlforge.cli import run
from controlforge.standalone.runtime import (
    StandaloneRuntimeConfig,
    build_standalone_runtime,
)
from controlforge.standalone.secrets import (
    SecretProvisioningError,
    StandaloneSecretBundle,
)
from controlforge.standalone.settings import StandaloneSettings


def test_secret_bundle_is_durable_private_and_rejects_weakened_mode(tmp_path: Path) -> None:
    directory = tmp_path / "secrets"

    first = StandaloneSecretBundle.load_or_create(directory)
    second = StandaloneSecretBundle.load_or_create(directory)

    assert first == second
    assert stat.S_IMODE(directory.stat().st_mode) == 0o700
    files = list(directory.iterdir())
    assert len(files) == 4
    assert all(stat.S_IMODE(path.stat().st_mode) == 0o600 for path in files)
    assert all(path.stat().st_size == 32 for path in files)

    os.chmod(files[0], 0o644)
    with pytest.raises(SecretProvisioningError):
        StandaloneSecretBundle.load_or_create(directory)


def test_runtime_composes_dashboard_identity_and_background_worker(tmp_path: Path) -> None:
    runtime = build_standalone_runtime(
        StandaloneRuntimeConfig(
            settings=StandaloneSettings(database_path=tmp_path / "standalone.db"),
            rules_directory=Path("rules"),
            secret_directory=tmp_path / "secrets",
            admin_origin="https://localhost:8443",
            rp_id="localhost",
            worker_interval_seconds=0.1,
        )
    )
    token = runtime.identity.issue_bootstrap_token(datetime.now(timezone.utc))

    assert len(token) >= 32
    with TestClient(runtime.app, base_url="https://localhost:8443") as client:
        health = client.get("/health")
        dashboard = client.get("/admin")
        assert health.status_code == 200
        assert health.json()["status"] == "ok"
        assert health.json()["worker"]["running"] is True
        assert dashboard.status_code == 200
        assert "ControlForge Standalone Admin" in dashboard.text
    assert runtime.supervisor.status.running is False


def test_cli_issues_console_bootstrap_token_without_starting_server(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    exit_code = run(
        [
            "standalone",
            "bootstrap-token",
            "--database",
            str(tmp_path / "cli.db"),
            "--secrets-directory",
            str(tmp_path / "cli-secrets"),
            "--rules",
            "rules",
        ]
    )

    token = capsys.readouterr().out.strip()
    assert exit_code == 0
    assert len(token) >= 32
    assert (tmp_path / "cli.db").exists()
    assert len(list((tmp_path / "cli-secrets").iterdir())) == 4
