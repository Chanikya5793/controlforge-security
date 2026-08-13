import io
import json
from datetime import datetime, timezone
from pathlib import Path
from types import SimpleNamespace

import pytest

from controlforge import cli
from controlforge.collector_agent import (
    CollectorDefinition,
    CollectorSecrets,
    load_collector_definition,
)
from controlforge.config import load_control_config
from controlforge.exposure import HibpError
from controlforge.macos_lifecycle import (
    MacOSContainmentRecoveryResult,
    MacOSEndpointActivationResult,
    MacOSEndpointUninstallResult,
)
from controlforge.macos_response import MacOSContainmentStatus
from controlforge.models import EndpointSnapshot
from controlforge.probes import FixtureSystemProbe, LocalSystemProbe


def test_load_control_config(project_root: Path) -> None:
    config = load_control_config(project_root / "config" / "agents.yml")
    assert {agent.agent_id for agent in config.agents} == {
        "crowdstrike-falcon",
        "microsoft-defender",
        "sentinelone",
    }


def test_invalid_control_config_is_rejected(tmp_path: Path) -> None:
    path = tmp_path / "invalid.yml"
    path.write_text("- not-a-mapping\n", encoding="utf-8")
    with pytest.raises(ValueError, match="YAML mapping"):
        load_control_config(path)


def test_fixture_probe_returns_an_independent_copy() -> None:
    fixture = EndpointSnapshot(hostname="demo", platform="linux", running_processes={"sensor"})
    probe = FixtureSystemProbe(fixture)
    first = probe.snapshot([])
    first.running_processes.add("mutated")
    assert "mutated" not in probe.snapshot([]).running_processes


def test_local_probe_collects_processes_and_file_metadata(tmp_path: Path) -> None:
    heartbeat = tmp_path / "heartbeat"
    heartbeat.write_text("ok", encoding="utf-8")
    snapshot = LocalSystemProbe().snapshot([str(heartbeat), str(tmp_path / "missing")])

    assert snapshot.hostname
    assert snapshot.platform
    assert snapshot.running_processes
    assert str(heartbeat) in snapshot.existing_paths
    assert str(heartbeat) in snapshot.file_modified_epoch


def test_cli_scan_emits_alerts(project_root: Path, tmp_path: Path, capsys) -> None:  # type: ignore[no-untyped-def]
    exit_code = cli.run(
        [
            "scan",
            "--events",
            str(project_root / "examples" / "events.jsonl"),
            "--rules",
            str(project_root / "rules"),
            "--database",
            str(tmp_path / "cli.db"),
        ]
    )
    output = capsys.readouterr().out
    assert exit_code == 1
    assert '"events_processed": 5' in output
    assert "CF-ENDPOINT-001" in output


def test_cli_controls_uses_failure_exit_code(project_root: Path, monkeypatch, capsys) -> None:  # type: ignore[no-untyped-def]
    fixture = EndpointSnapshot(
        hostname="endpoint-01",
        platform="linux",
        observed_at=datetime(2026, 8, 11, 14, 0, tzinfo=timezone.utc),
    )
    monkeypatch.setattr(cli, "LocalSystemProbe", lambda: FixtureSystemProbe(fixture))

    exit_code = cli.run(["controls", "--config", str(project_root / "config" / "agents.yml")])
    output = capsys.readouterr().out
    assert exit_code == 2
    assert '"status": "failed"' in output


def test_cli_serve_delegates_to_uvicorn(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    calls = []
    monkeypatch.setattr(cli.uvicorn, "run", lambda *args, **kwargs: calls.append((args, kwargs)))
    assert cli.run(["serve", "--host", "127.0.0.1", "--port", "9090"]) == 0
    assert calls[0][1] == {"host": "127.0.0.1", "port": 9090}


def test_stdin_collector_secrets_are_strict_and_bounded() -> None:
    payload = {
        "credential-id": "3970e11f-f87c-4e14-9a90-d574cd2bcd95",
        "credential-secret": "s" * 48,
        "access-client-id": f"{'a' * 32}.access",
        "access-client-secret": "b" * 64,
    }
    secrets = cli._load_stdin_collector_secrets(io.BytesIO(json.dumps(payload).encode()))
    assert secrets.credential_id == payload["credential-id"]

    standalone_payload = {
        "credential-id": payload["credential-id"],
        "credential-secret": payload["credential-secret"],
    }
    standalone_secrets = cli._load_stdin_collector_secrets(
        io.BytesIO(json.dumps(standalone_payload).encode())
    )
    assert standalone_secrets.access_client_id is None
    assert standalone_secrets.access_client_secret is None

    with pytest.raises(ValueError, match="invalid fields"):
        cli._load_stdin_collector_secrets(io.BytesIO(b'{"credential-id":"only-one"}'))
    with pytest.raises(ValueError, match="exceeds 4 KB"):
        cli._load_stdin_collector_secrets(io.BytesIO(b"x" * 4097))


def test_standalone_access_policy_discards_stale_cloudflare_secrets() -> None:
    secrets = cli._load_stdin_collector_secrets(
        io.BytesIO(
            json.dumps(
                {
                    "credential-id": "3970e11f-f87c-4e14-9a90-d574cd2bcd95",
                    "credential-secret": "s" * 48,
                    "access-client-id": f"{'a' * 32}.access",
                    "access-client-secret": "b" * 64,
                }
            ).encode()
        )
    )
    standalone = CollectorDefinition(
        api_host="standalone.example.com",
        device_id="mac-primary",
        access_proxy_required=False,
    )
    filtered = cli._apply_collector_access_policy(standalone, secrets)
    assert filtered.access_client_id is None
    assert filtered.access_client_secret is None

    hosted = CollectorDefinition(api_host="soc.example.com", device_id="mac-primary")
    with pytest.raises(ValueError, match="requires Cloudflare Access"):
        cli._apply_collector_access_policy(
            hosted,
            CollectorSecrets(
                credential_id=secrets.credential_id,
                credential_secret=secrets.credential_secret,
                access_client_id=None,
                access_client_secret=None,
            ),
        )


def test_agent_enroll_preflights_and_never_prints_credentials(
    monkeypatch,
    tmp_path: Path,
    capsys,
) -> None:  # type: ignore[no-untyped-def]
    config = tmp_path / "collector.yml"
    config.write_text(
        """
api_host: soc.example.com
device_id: old-device
credential_source: macos_system_keychain
keychain_service: com.controlforge.collector.v2
access_proxy_required: true
action_polling_enabled: true
""".strip()
        + "\n",
        encoding="utf-8",
    )
    calls: list[object] = []

    class FixtureKeychain:
        def __init__(self, service: str) -> None:
            calls.append(("keychain", service))

        def require_initial_empty(self) -> None:
            calls.append("preflight")

        def store_initial(self, credential_id: str, credential_secret: str) -> None:
            calls.append(("stored", credential_id, credential_secret))

    class FixtureClient:
        def __init__(self, host: str, *, api_port: int) -> None:
            calls.append(("client", host, api_port))

        def claim(self, token: str, device_id: str, display_name: str) -> object:
            calls.append(("claim", token, device_id, display_name))
            return SimpleNamespace(
                credential_id="3970e11f-f87c-4e14-9a90-d574cd2bcd95",
                credential_secret="must-not-be-printed-" + "s" * 32,
                device_id=device_id,
                expires_at="2026-11-20T19:00:00+00:00",
            )

    class FixtureLifecycle:
        def __init__(self, *, collector_config: Path) -> None:
            calls.append(("lifecycle", collector_config))

        def activate(self) -> object:
            calls.append("activated")
            return SimpleNamespace(
                first_check_in_verified=True,
                launch_daemon_loaded=True,
            )

    monkeypatch.setattr(cli, "MacOSSystemKeychain", FixtureKeychain)
    monkeypatch.setattr(cli, "StandaloneEndpointEnrollmentClient", FixtureClient)
    monkeypatch.setattr(cli, "MacOSEndpointLifecycle", FixtureLifecycle)
    monkeypatch.setattr(cli.sys, "stdin", io.StringIO("t" * 43 + "\n"))

    assert (
        cli.run(
            [
                "agent-enroll",
                "--config",
                str(config),
                "--api-host",
                "standalone.example.com",
                "--api-port",
                "8443",
                "--device-id",
                "mac-primary",
                "--display-name",
                "Primary Mac",
                "--token-stdin",
            ]
        )
        == 0
    )

    installed = load_collector_definition(config)
    assert installed.api_host == "standalone.example.com"
    assert installed.api_port == 8443
    assert installed.access_proxy_required is False
    assert installed.action_polling_enabled is True
    assert installed.credential_rotation_enabled is True
    output = capsys.readouterr().out
    assert "must-not-be-printed" not in output
    assert calls[1] == "preflight"
    assert calls[-1] == "activated"


def test_agent_enroll_reports_safe_activation_recovery_without_reclaiming(
    monkeypatch,
    tmp_path: Path,
) -> None:  # type: ignore[no-untyped-def]
    config = tmp_path / "collector.yml"
    config.write_text(
        "\n".join(
            [
                "api_host: soc.example.com",
                "device_id: old-device",
                "credential_source: macos_system_keychain",
                "keychain_service: com.controlforge.collector.v2",
                "access_proxy_required: true",
            ]
        )
        + "\n",
        encoding="utf-8",
    )
    calls: list[str] = []

    class FixtureKeychain:
        def __init__(self, service: str) -> None:
            assert service == "com.controlforge.collector.v2"

        def require_initial_empty(self) -> None:
            calls.append("preflight")

        def store_initial(self, credential_id: str, credential_secret: str) -> None:
            assert credential_id == "3970e11f-f87c-4e14-9a90-d574cd2bcd95"
            assert credential_secret.startswith("secret-")
            calls.append("stored")

    class FixtureClient:
        def __init__(self, host: str, *, api_port: int) -> None:
            assert (host, api_port) == ("standalone.example.com", 8443)

        def claim(self, token: str, device_id: str, display_name: str) -> object:
            calls.append("claimed")
            return SimpleNamespace(
                credential_id="3970e11f-f87c-4e14-9a90-d574cd2bcd95",
                credential_secret="secret-" + "s" * 40,
                device_id=device_id,
                expires_at="2026-11-20T19:00:00+00:00",
            )

    class FailingLifecycle:
        def __init__(self, *, collector_config: Path) -> None:
            assert collector_config == config

        def activate(self) -> object:
            calls.append("activation-failed")
            raise cli.MacOSEndpointLifecycleError("provider output must stay hidden")

    monkeypatch.setattr(cli, "MacOSSystemKeychain", FixtureKeychain)
    monkeypatch.setattr(cli, "StandaloneEndpointEnrollmentClient", FixtureClient)
    monkeypatch.setattr(cli, "MacOSEndpointLifecycle", FailingLifecycle)
    monkeypatch.setattr(cli.sys, "stdin", io.StringIO("t" * 43 + "\n"))

    with pytest.raises(
        cli.EndpointEnrollmentError,
        match="run agent-activate without claiming a new code",
    ) as error:
        cli.run(
            [
                "agent-enroll",
                "--config",
                str(config),
                "--api-host",
                "standalone.example.com",
                "--device-id",
                "mac-primary",
                "--display-name",
                "Primary Mac",
                "--token-stdin",
            ]
        )

    assert "provider output" not in str(error.value)
    assert calls == ["preflight", "claimed", "stored", "activation-failed"]


def test_agent_activate_resumes_without_an_enrollment_claim(
    monkeypatch,
    tmp_path: Path,
    capsys,
) -> None:  # type: ignore[no-untyped-def]
    config = tmp_path / "collector.yml"
    calls: list[Path] = []

    class FixtureLifecycle:
        def __init__(self, *, collector_config: Path) -> None:
            calls.append(collector_config)

        def activate(self) -> object:
            return MacOSEndpointActivationResult(
                device_id="mac-primary",
                first_check_in_verified=True,
                launch_daemon_loaded=True,
                resumed_existing_daemon=False,
            )

    monkeypatch.setattr(cli, "MacOSEndpointLifecycle", FixtureLifecycle)
    assert cli.run(["agent-activate", "--config", str(config)]) == 0

    output = capsys.readouterr().out
    assert calls == [config]
    assert '"first_check_in_verified": true' in output
    assert '"launch_daemon_loaded": true' in output


def test_agent_uninstall_requires_confirmation_and_preserves_data_by_default(
    monkeypatch,
    tmp_path: Path,
    capsys,
) -> None:  # type: ignore[no-untyped-def]
    config = tmp_path / "collector.yml"
    calls: list[object] = []

    class FixtureLifecycle:
        def __init__(self, *, collector_config: Path) -> None:
            calls.append(collector_config)

        def uninstall(
            self,
            *,
            confirmation: str,
            delete_spool: bool,
            delete_logs: bool,
        ) -> MacOSEndpointUninstallResult:
            calls.append((confirmation, delete_spool, delete_logs))
            return MacOSEndpointUninstallResult(
                launch_daemon_stopped=True,
                pf_state_released_or_absent=True,
                keychain_items_removed=True,
                package_receipt_forgotten=True,
                removed=("collector_wrapper",),
                preserved=("telemetry_spool", "collector_logs"),
            )

    monkeypatch.setattr(cli, "MacOSEndpointLifecycle", FixtureLifecycle)
    assert (
        cli.run(
            [
                "agent-uninstall",
                "--config",
                str(config),
                "--confirm",
                "UNINSTALL-CONTROLFORGE",
            ]
        )
        == 0
    )

    output = capsys.readouterr().out
    assert calls == [config, ("UNINSTALL-CONTROLFORGE", False, False)]
    assert '"preserved": [' in output
    assert "telemetry_spool" in output
    assert "credential" not in output.lower()


def test_agent_uninstall_passes_explicit_spool_and_log_deletion_flags(
    monkeypatch,
    tmp_path: Path,
) -> None:  # type: ignore[no-untyped-def]
    calls: list[tuple[str, bool, bool]] = []

    class FixtureLifecycle:
        def __init__(self, *, collector_config: Path) -> None:
            assert collector_config == tmp_path / "collector.yml"

        def uninstall(
            self,
            *,
            confirmation: str,
            delete_spool: bool,
            delete_logs: bool,
        ) -> MacOSEndpointUninstallResult:
            calls.append((confirmation, delete_spool, delete_logs))
            return MacOSEndpointUninstallResult(True, True, True, False, (), ())

    monkeypatch.setattr(cli, "MacOSEndpointLifecycle", FixtureLifecycle)
    assert (
        cli.run(
            [
                "agent-uninstall",
                "--config",
                str(tmp_path / "collector.yml"),
                "--confirm",
                "UNINSTALL-CONTROLFORGE",
                "--delete-spool",
                "--delete-logs",
            ]
        )
        == 0
    )
    assert calls == [("UNINSTALL-CONTROLFORGE", True, True)]


def test_agent_containment_status_outputs_only_redacted_posture(
    monkeypatch,
    capsys,
) -> None:  # type: ignore[no-untyped-def]
    class FixtureLifecycle:
        def containment_status(self) -> MacOSContainmentStatus:
            return MacOSContainmentStatus("released")

    monkeypatch.setattr(cli, "MacOSEndpointLifecycle", FixtureLifecycle)

    assert cli.run(["agent-containment-status"]) == 0
    output = capsys.readouterr().out
    assert '"state": "released"' in output
    assert set(json.loads(output)) == {"state", "expires_at"}


def test_agent_containment_release_requires_explicit_confirmation_and_stays_redacted(
    monkeypatch,
    capsys,
) -> None:  # type: ignore[no-untyped-def]
    calls: list[str] = []

    class FixtureLifecycle:
        def release_containment(self, *, confirmation: str) -> MacOSContainmentRecoveryResult:
            calls.append(confirmation)
            return MacOSContainmentRecoveryResult(
                collector_disabled=True,
                state="released",
                summary="ControlForge containment released; collector remains disabled.",
            )

    monkeypatch.setattr(cli, "MacOSEndpointLifecycle", FixtureLifecycle)
    confirmation = "RELEASE-CONTROLFORGE-CONTAINMENT"

    assert cli.run(["agent-containment-release", "--confirm", confirmation]) == 0
    output = capsys.readouterr().out
    assert calls == [confirmation]
    assert '"collector_disabled": true' in output
    assert "token" not in output.casefold()
    assert "management" not in output.casefold()


def test_cli_main_reports_provider_error_without_traceback(monkeypatch, capsys) -> None:  # type: ignore[no-untyped-def]
    def fail() -> int:
        raise HibpError("HIBP request failed with HTTP 401")

    monkeypatch.setattr(cli, "run", fail)
    with pytest.raises(SystemExit) as exit_info:
        cli.main()

    assert exit_info.value.code == 3
    assert capsys.readouterr().err == '{"error": "HIBP request failed with HTTP 401"}\n'
