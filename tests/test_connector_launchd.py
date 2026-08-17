from __future__ import annotations

import hashlib
import plistlib
import stat
from collections.abc import Sequence
from pathlib import Path

import pytest

from controlforge.standalone.__main__ import run
from controlforge.standalone.connector_launchd import (
    CONNECTOR_DOMAIN_LABEL,
    CONNECTOR_LABEL,
    LAUNCHCTL,
    ConnectorLaunchConfig,
    ConnectorLaunchdError,
    FixedConnectorRunner,
    TunnelConnectorLaunchdService,
)


class FakeConnectorRunner:
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
            raise ConnectorLaunchdError("injected connector failure")
        if operation == "bootstrap":
            self.loaded = True
        elif operation == "bootout":
            self.loaded = False
        return 0


def connector_service(
    tmp_path: Path, *, runner: FakeConnectorRunner | None = None
) -> tuple[TunnelConnectorLaunchdService, Path, FakeConnectorRunner]:
    binary_directory = tmp_path / "Library" / "ControlForge" / "bin"
    config_directory = tmp_path / "Library" / "ControlForge" / "tunnel"
    logs_directory = tmp_path / "Library" / "Logs"
    launchd_directory = tmp_path / "Library" / "LaunchDaemons"
    for directory in (
        binary_directory,
        config_directory,
        logs_directory,
        launchd_directory,
    ):
        directory.mkdir(mode=0o700, parents=True, exist_ok=True)
        directory.chmod(0o700)
    binary = binary_directory / "cloudflared"
    binary.write_bytes(b"#!/bin/sh\nexit 1\n" + b"#" * 2_048)
    binary.chmod(0o700)
    config_file = config_directory / "config.yml"
    config_file.write_text("ingress:\n  - service: http_status:404\n")
    config_file.chmod(0o600)
    digest = hashlib.sha256(binary.read_bytes()).hexdigest()
    config = ConnectorLaunchConfig(
        binary=binary,
        binary_sha256=digest,
        config_file=config_file,
        stdout_log=logs_directory / "connector.out.log",
        stderr_log=logs_directory / "connector.err.log",
    )
    command_runner = runner or FakeConnectorRunner()
    plist_path = launchd_directory / "com.controlforge.cloudflared.plist"
    service = TunnelConnectorLaunchdService(
        config,
        plist_path=plist_path,
        runner=command_runner,
        system=lambda: "Darwin",
        euid=lambda: 0,
        connector_validator=lambda: None,
    )
    return service, plist_path, command_runner


def test_install_pins_root_owned_binary_config_and_launch_arguments(tmp_path: Path) -> None:
    service, plist_path, runner = connector_service(tmp_path)

    installed = service.install()
    status = service.status()
    payload = plistlib.loads(plist_path.read_bytes())

    assert installed.loaded is True and installed.installed_plist is True
    assert installed.already_active is False
    assert status.loaded is True and status.configuration_matches is True
    assert payload["Label"] == CONNECTOR_LABEL
    assert payload["ProgramArguments"] == [
        str(service.config.binary),
        "tunnel",
        "--config",
        str(service.config.config_file),
        "run",
    ]
    assert payload["KeepAlive"] == {"SuccessfulExit": False}
    assert payload["RunAtLoad"] is True and payload["Umask"] == 0o077
    assert stat.S_IMODE(plist_path.stat().st_mode) == 0o644
    assert (LAUNCHCTL, "enable", CONNECTOR_DOMAIN_LABEL) in runner.calls


def test_install_is_idempotent_and_uninstall_preserves_private_config(tmp_path: Path) -> None:
    service, plist_path, runner = connector_service(tmp_path)
    first = service.install()
    original = plist_path.read_bytes()
    runner.calls.clear()

    repeated = service.install()
    removed = service.uninstall()
    absent = service.uninstall()

    assert first.installed_plist is True
    assert repeated == type(repeated)(False, True, True, str(plist_path))
    assert original != b"" and removed.removed_plist is True and removed.was_loaded is True
    assert removed.config_preserved is True and service.config.config_file.exists()
    assert absent.removed_plist is False and absent.was_loaded is False


def test_partial_activation_rolls_back_only_exact_connector_plist(tmp_path: Path) -> None:
    runner = FakeConnectorRunner(fail_operation="kickstart")
    service, plist_path, _ = connector_service(tmp_path, runner=runner)

    with pytest.raises(ConnectorLaunchdError, match="changes were rolled back"):
        service.install()

    assert plist_path.exists() is False
    assert runner.loaded is False
    assert service.config.config_file.exists()
    assert (LAUNCHCTL, "bootout", CONNECTOR_DOMAIN_LABEL) in runner.calls


def test_untrusted_binary_config_or_existing_plist_fails_closed(tmp_path: Path) -> None:
    service, plist_path, _ = connector_service(tmp_path)
    wrong_hash = TunnelConnectorLaunchdService(
        ConnectorLaunchConfig(
            binary=service.config.binary,
            binary_sha256="0" * 64,
            config_file=service.config.config_file,
            stdout_log=service.config.stdout_log,
            stderr_log=service.config.stderr_log,
        ),
        plist_path=plist_path,
        runner=FakeConnectorRunner(),
        system=lambda: "Darwin",
        euid=lambda: 0,
        connector_validator=lambda: None,
    )
    with pytest.raises(ConnectorLaunchdError, match="pinned SHA-256"):
        wrong_hash.install()

    service.config.config_file.chmod(0o644)
    with pytest.raises(ConnectorLaunchdError, match="not private"):
        service.install()
    service.config.config_file.chmod(0o600)

    plist_path.write_bytes(plistlib.dumps({"Label": "unexpected"}))
    plist_path.chmod(0o644)
    with pytest.raises(ConnectorLaunchdError, match="unexpected"):
        service.install()
    with pytest.raises(ConnectorLaunchdError, match="refusing to remove"):
        service.uninstall()


def test_connector_validation_and_platform_checks_precede_plist_changes(tmp_path: Path) -> None:
    service, plist_path, runner = connector_service(tmp_path)
    rejected = TunnelConnectorLaunchdService(
        service.config,
        plist_path=plist_path,
        runner=runner,
        system=lambda: "Darwin",
        euid=lambda: 0,
        connector_validator=lambda: (_ for _ in ()).throw(
            ConnectorLaunchdError("connector configuration validation failed")
        ),
    )
    with pytest.raises(ConnectorLaunchdError, match="validation failed"):
        rejected.install()
    assert not plist_path.exists() and runner.calls == []

    non_root = TunnelConnectorLaunchdService(
        service.config,
        plist_path=plist_path,
        runner=runner,
        system=lambda: "Darwin",
        euid=lambda: 501,
        connector_validator=lambda: None,
    )
    with pytest.raises(ConnectorLaunchdError, match="requires root"):
        non_root.status()


def test_fixed_runner_rejects_every_command_outside_connector_allowlist(tmp_path: Path) -> None:
    runner = FixedConnectorRunner(tmp_path / "connector.plist")
    with pytest.raises(ValueError, match="not allowlisted"):
        runner.run((LAUNCHCTL, "bootout", "system/com.controlforge.standalone"), timeout_seconds=1)


def test_module_cli_installs_exact_connector_configuration(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    service, plist_path, _ = connector_service(tmp_path)
    captured: list[ConnectorLaunchConfig] = []

    def factory(config: ConnectorLaunchConfig) -> TunnelConnectorLaunchdService:
        captured.append(config)
        return service

    assert (
        run(
            [
                "connector-service-install",
                "--binary",
                str(service.config.binary),
                "--binary-sha256",
                service.config.binary_sha256.upper(),
                "--config",
                str(service.config.config_file),
                "--stdout-log",
                str(service.config.stdout_log),
                "--stderr-log",
                str(service.config.stderr_log),
            ],
            connector_service_factory=factory,
        )
        == 0
    )
    assert captured == [service.config]
    assert plistlib.loads(plist_path.read_bytes())["Label"] == CONNECTOR_LABEL
    assert '"loaded": true' in capsys.readouterr().out


@pytest.mark.parametrize("digest", ["", "a" * 63, "g" * 64, "../" + "a" * 61])
def test_invalid_connector_digest_is_rejected(digest: str) -> None:
    with pytest.raises(ValueError, match="SHA-256"):
        ConnectorLaunchConfig(Path("/binary"), digest, Path("/config"))
