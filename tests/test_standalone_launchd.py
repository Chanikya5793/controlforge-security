from __future__ import annotations

import fcntl
import json
import os
import plistlib
import sqlite3
import stat
import sys
from collections.abc import Sequence
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

from controlforge.standalone.__main__ import run
from controlforge.standalone.appliance import (
    ApplianceLaunchConfig,
    AppliancePaths,
    AppliancePreflightError,
    StandaloneApplianceLifecycle,
)
from controlforge.standalone.launchd import (
    LAUNCHCTL,
    LAUNCHD_DOMAIN_LABEL,
    StandaloneLaunchdError,
    StandaloneLaunchdService,
)

NOW = datetime.now(timezone.utc)


class FakeLaunchdRunner:
    def __init__(self, *, fail_operation: str | None = None) -> None:
        self.calls: list[tuple[str, ...]] = []
        self.loaded = False
        self.fail_operation = fail_operation

    def run(
        self,
        arguments: Sequence[str],
        *,
        timeout_seconds: float,
        allow_failure: bool = False,
    ) -> int:
        command = tuple(arguments)
        self.calls.append(command)
        operation = command[1]
        if operation == "print":
            return 0 if self.loaded else 113
        if operation == self.fail_operation:
            if allow_failure:
                return 5
            raise StandaloneLaunchdError("injected command failure")
        if operation == "bootstrap":
            self.loaded = True
        elif operation == "bootout":
            self.loaded = False
        return 0


def launch_config(tmp_path: Path, *, key_mode: int = 0o600) -> ApplianceLaunchConfig:
    material = tmp_path / "tls"
    material.mkdir(mode=0o700, parents=True)
    key = rsa.generate_private_key(public_exponent=65_537, key_size=2_048)
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "localhost")])
    certificate = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(NOW - timedelta(days=1))
        .not_valid_after(NOW + timedelta(days=30))
        .add_extension(
            x509.SubjectAlternativeName([x509.DNSName("localhost")]),
            critical=False,
        )
        .add_extension(
            x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]),
            critical=False,
        )
        .sign(key, hashes.SHA256())
    )
    certificate_path = material / "server.pem"
    private_key_path = material / "server-key.pem"
    certificate_path.write_bytes(certificate.public_bytes(serialization.Encoding.PEM))
    certificate_path.chmod(0o644)
    private_key_path.write_bytes(
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    private_key_path.chmod(key_mode)
    return ApplianceLaunchConfig(
        root=tmp_path / "appliance",
        rules_directory=Path("rules").absolute(),
        admin_origin="https://localhost:8443",
        rp_id="localhost",
        host="127.0.0.1",
        port=8443,
        tls_certificate=certificate_path,
        tls_private_key=private_key_path,
        worker_interval_seconds=0.1,
    )


def launchd_service(
    tmp_path: Path,
    runner: FakeLaunchdRunner,
    *,
    config: ApplianceLaunchConfig | None = None,
) -> tuple[StandaloneLaunchdService, Path]:
    launch_daemons = tmp_path / "Library" / "LaunchDaemons"
    launch_daemons.mkdir(mode=0o700, parents=True)
    launch_daemons.chmod(0o700)
    executable = tmp_path / "controlforge-python"
    executable.write_text("#!/bin/sh\nexit 1\n")
    executable.chmod(0o700)
    plist_path = launch_daemons / "com.controlforge.standalone.plist"
    service = StandaloneLaunchdService(
        config or launch_config(tmp_path),
        plist_path=plist_path,
        python_executable=executable,
        runner=runner,
        system=lambda: "Darwin",
        euid=lambda: 0,
    )
    return service, plist_path


def launch_arguments(command: str, config: ApplianceLaunchConfig) -> list[str]:
    return [
        command,
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
        str(config.worker_interval_seconds),
    ]


def test_clean_install_preflights_and_activates_fixed_daemon(tmp_path: Path) -> None:
    runner = FakeLaunchdRunner()
    service, plist_path = launchd_service(tmp_path, runner)

    result = service.install()

    paths = AppliancePaths.from_root(service.config.root)
    payload = plistlib.loads(plist_path.read_bytes())
    arguments = payload["ProgramArguments"]
    assert result.loaded is True
    assert result.installed_plist is True
    assert result.already_active is False
    assert result.data_preserved is True
    assert result.bootstrap_token is not None
    assert payload["Label"] == "com.controlforge.standalone"
    assert payload["Disabled"] is True
    assert payload["RunAtLoad"] is True
    assert payload["Umask"] == 0o077
    assert arguments[:4] == [
        str(service.python_executable),
        "-m",
        "controlforge.standalone",
        "serve",
    ]
    assert arguments[-1] == "--managed-service"
    assert result.bootstrap_token not in plist_path.read_text()
    assert stat.S_IMODE(plist_path.stat().st_mode) == 0o644
    assert stat.S_IMODE(paths.database.stat().st_mode) == 0o600
    assert paths.secrets_directory.is_dir()
    assert (LAUNCHCTL, "enable", LAUNCHD_DOMAIN_LABEL) in runner.calls
    assert any(command[1] == "bootstrap" for command in runner.calls)
    with sqlite3.connect(paths.database) as connection:
        assert (
            connection.execute(
                "SELECT COUNT(*) FROM bootstrap_tokens WHERE used_at IS NULL AND revoked_at IS NULL"
            ).fetchone()[0]
            == 1
        )


def test_install_is_idempotent_without_rotating_bootstrap(tmp_path: Path) -> None:
    runner = FakeLaunchdRunner()
    service, plist_path = launchd_service(tmp_path, runner)
    first = service.install()
    original = plist_path.read_bytes()
    runner.calls.clear()

    second = service.install()

    assert first.bootstrap_token is not None
    assert second.bootstrap_token is None
    assert second.already_active is True
    assert second.installed_plist is False
    assert plist_path.read_bytes() == original
    assert runner.calls == [(LAUNCHCTL, "print", LAUNCHD_DOMAIN_LABEL)]
    with sqlite3.connect(AppliancePaths.from_root(service.config.root).database) as connection:
        assert (
            connection.execute(
                "SELECT COUNT(*) FROM bootstrap_tokens WHERE used_at IS NULL AND revoked_at IS NULL"
            ).fetchone()[0]
            == 1
        )


def test_partial_activation_rolls_back_service_but_preserves_data(tmp_path: Path) -> None:
    runner = FakeLaunchdRunner(fail_operation="kickstart")
    service, plist_path = launchd_service(tmp_path, runner)

    with pytest.raises(StandaloneLaunchdError, match="service changes were rolled back"):
        service.install()

    paths = AppliancePaths.from_root(service.config.root)
    assert plist_path.exists() is False
    assert runner.loaded is False
    assert paths.database.exists()
    assert paths.secrets_directory.exists()
    assert (LAUNCHCTL, "bootout", LAUNCHD_DOMAIN_LABEL) in runner.calls
    assert (LAUNCHCTL, "disable", LAUNCHD_DOMAIN_LABEL) in runner.calls
    with sqlite3.connect(paths.database) as connection:
        assert (
            connection.execute(
                "SELECT COUNT(*) FROM bootstrap_tokens WHERE used_at IS NULL AND revoked_at IS NULL"
            ).fetchone()[0]
            == 0
        )


def test_uninstall_is_idempotent_and_preserves_appliance_data(tmp_path: Path) -> None:
    runner = FakeLaunchdRunner()
    service, plist_path = launchd_service(tmp_path, runner)
    service.install()
    paths = AppliancePaths.from_root(service.config.root)
    sentinel = paths.data_directory / "preserved.txt"
    sentinel.write_text("preserve me")

    removed = service.uninstall()
    repeated = service.uninstall()

    assert removed.was_loaded is True
    assert removed.removed_plist is True
    assert removed.data_preserved is True
    assert repeated.was_loaded is False
    assert repeated.removed_plist is False
    assert plist_path.exists() is False
    assert paths.database.exists()
    assert sentinel.read_text() == "preserve me"


def test_unexpected_or_unsafe_plist_is_never_replaced_or_removed(tmp_path: Path) -> None:
    runner = FakeLaunchdRunner()
    service, plist_path = launchd_service(tmp_path, runner)
    plist_path.write_bytes(plistlib.dumps({"Label": "unexpected"}))
    plist_path.chmod(0o644)
    original = plist_path.read_bytes()

    with pytest.raises(StandaloneLaunchdError, match="unexpected"):
        service.install()
    with pytest.raises(StandaloneLaunchdError, match="refusing to remove"):
        service.uninstall()

    assert plist_path.read_bytes() == original
    plist_path.chmod(0o666)
    with pytest.raises(StandaloneLaunchdError, match="ownership or mode is unsafe"):
        service.status()


def test_root_and_tls_preflight_fail_before_launchctl_or_plist_write(tmp_path: Path) -> None:
    runner = FakeLaunchdRunner()
    service, plist_path = launchd_service(tmp_path, runner)
    non_root = StandaloneLaunchdService(
        service.config,
        plist_path=plist_path,
        python_executable=service.python_executable,
        runner=runner,
        system=lambda: "Darwin",
        euid=lambda: 501,
    )
    with pytest.raises(StandaloneLaunchdError, match="requires root"):
        non_root.install()
    assert runner.calls == []
    assert plist_path.exists() is False

    weak_config = launch_config(tmp_path / "weak", key_mode=0o644)
    weak_service, weak_plist = launchd_service(
        tmp_path / "weak",
        runner,
        config=weak_config,
    )
    with pytest.raises(AppliancePreflightError, match="mode 0600"):
        weak_service.install()
    assert runner.calls == []
    assert weak_plist.exists() is False


def test_status_rejects_loaded_service_without_trusted_plist(tmp_path: Path) -> None:
    runner = FakeLaunchdRunner()
    runner.loaded = True
    service, plist_path = launchd_service(tmp_path, runner)

    with pytest.raises(StandaloneLaunchdError, match="loaded without its trusted plist"):
        service.install()

    assert plist_path.exists() is False


def test_installed_plist_contains_no_shell_or_secret_values(tmp_path: Path) -> None:
    runner = FakeLaunchdRunner()
    service, plist_path = launchd_service(tmp_path, runner)
    result = service.install()
    raw = plist_path.read_bytes()
    payload = plistlib.loads(raw)
    arguments = payload["ProgramArguments"]

    assert result.bootstrap_token is not None
    assert result.bootstrap_token.encode() not in raw
    assert "/bin/sh" not in arguments
    assert "-c" not in arguments
    assert not any("token" in value.casefold() for value in arguments)
    assert not any("secret" in value.casefold() for value in arguments)
    for value in arguments:
        assert "\n" not in value
        assert "\x00" not in value


def test_plist_parent_and_executable_must_be_trusted(tmp_path: Path) -> None:
    runner = FakeLaunchdRunner()
    service, plist_path = launchd_service(tmp_path, runner)
    service.python_executable.chmod(0o722)
    with pytest.raises(StandaloneLaunchdError, match="executable is not trusted"):
        service.status()

    service.python_executable.chmod(0o700)
    plist_path.parent.chmod(0o777)
    with pytest.raises(StandaloneLaunchdError, match="directory is not trusted"):
        service.install()


def test_plist_is_not_plaintext_bootstrap_persistence(tmp_path: Path) -> None:
    runner = FakeLaunchdRunner()
    service, plist_path = launchd_service(tmp_path, runner)
    result = service.install()
    assert result.bootstrap_token is not None

    persisted = [path for path in service.config.root.rglob("*") if path.is_file()]
    persisted.append(plist_path)
    assert all(result.bootstrap_token.encode() not in path.read_bytes() for path in persisted)
    assert os.path.commonpath([service.config.root, plist_path]) != str(service.config.root)


def test_executable_service_commands_install_report_and_uninstall(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    runner = FakeLaunchdRunner()
    config = launch_config(tmp_path)
    service, plist_path = launchd_service(tmp_path, runner, config=config)

    def factory(received: ApplianceLaunchConfig) -> StandaloneLaunchdService:
        assert received.root == config.root
        return StandaloneLaunchdService(
            received,
            plist_path=plist_path,
            python_executable=service.python_executable,
            runner=runner,
            system=lambda: "Darwin",
            euid=lambda: 0,
        )

    assert (
        run(
            launch_arguments("service-install", config),
            launchd_service_factory=factory,
        )
        == 0
    )
    installed_output = capsys.readouterr()
    installed = json.loads(installed_output.out)
    assert installed["loaded"] is True
    assert "bootstrap_token" not in installed
    assert "bootstrap token" in installed_output.err.casefold()

    assert (
        run(
            launch_arguments("service-status", config),
            launchd_service_factory=factory,
        )
        == 0
    )
    status_output = capsys.readouterr()
    assert json.loads(status_output.out)["configuration_matches"] is True
    assert status_output.err == ""

    assert (
        run(
            launch_arguments("service-uninstall", config),
            launchd_service_factory=factory,
        )
        == 0
    )
    removed_output = capsys.readouterr()
    removed = json.loads(removed_output.out)
    assert removed["removed_plist"] is True
    assert removed["data_preserved"] is True
    assert removed_output.err == ""


def test_managed_serve_never_prints_or_rotates_bootstrap_token(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    config = launch_config(tmp_path)
    server_calls = 0

    def server_runner(*args: object, **kwargs: object) -> object:
        nonlocal server_calls
        server_calls += 1
        return None

    arguments = launch_arguments("serve", config)
    arguments.append("--managed-service")
    assert run(arguments, server_runner=server_runner) == 0

    output = capsys.readouterr()
    report = json.loads(output.out)
    assert report["schema_versions_after"]
    assert output.err == ""
    assert server_calls == 1
    with sqlite3.connect(AppliancePaths.from_root(config.root).database) as connection:
        assert connection.execute("SELECT COUNT(*) FROM bootstrap_tokens").fetchone()[0] == 0


def test_concurrent_service_mutation_fails_before_state_or_launchctl_change(
    tmp_path: Path,
) -> None:
    runner = FakeLaunchdRunner()
    service, plist_path = launchd_service(tmp_path, runner)
    StandaloneApplianceLifecycle(service.config).preflight()
    lock_path = service.config.root / ".launchd-service.lock"
    descriptor = os.open(lock_path, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
    try:
        fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
        with pytest.raises(StandaloneLaunchdError, match="already running"):
            service.install()
    finally:
        fcntl.flock(descriptor, fcntl.LOCK_UN)
        os.close(descriptor)

    assert runner.calls == []
    assert plist_path.exists() is False
    assert AppliancePaths.from_root(service.config.root).database.exists() is False


def test_trusted_python_symlink_preserves_virtual_environment_entrypoint(
    tmp_path: Path,
) -> None:
    runner = FakeLaunchdRunner()
    service, _ = launchd_service(tmp_path, runner)
    target = service.python_executable
    symlink = target.with_name("venv-python")
    symlink.symlink_to(target.name)
    linked_service = StandaloneLaunchdService(
        service.config,
        plist_path=service.plist_path,
        python_executable=symlink,
        runner=runner,
        system=lambda: "Darwin",
        euid=lambda: 0,
    )

    assert linked_service.status().plist_installed is False
    assert linked_service.python_executable == symlink.absolute()


def test_frozen_runtime_plist_uses_fixed_bundled_dispatch(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    runner = FakeLaunchdRunner()
    service, plist_path = launchd_service(tmp_path, runner)
    monkeypatch.setattr(sys, "frozen", True, raising=False)

    service.install()

    arguments = plistlib.loads(plist_path.read_bytes())["ProgramArguments"]
    assert arguments[:3] == [
        str(service.python_executable),
        "standalone-appliance",
        "serve",
    ]
    assert "-m" not in arguments
