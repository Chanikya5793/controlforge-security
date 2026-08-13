from __future__ import annotations

import os
import plistlib
import shutil
from collections.abc import Sequence
from dataclasses import asdict
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from controlforge.macos_acceptance import PACKAGED_RULE_NAMES
from controlforge.macos_lifecycle import (
    CODESIGN,
    LAUNCHCTL,
    LAUNCHD_LABEL,
    RELEASE_CONTAINMENT_CONFIRMATION,
    UNINSTALL_CONFIRMATION,
    FixedMacOSLifecycleRunner,
    MacOSEndpointLifecycle,
    MacOSEndpointLifecycleError,
)
from controlforge.macos_response import (
    MacOSContainmentStatus,
    MacOSResponseError,
    MacOSResponseResult,
)


class RecordingRunner:
    def __init__(self, outcomes: dict[tuple[str, ...], list[int]] | None = None) -> None:
        self.outcomes = outcomes or {}
        self.calls: list[tuple[tuple[str, ...], float, bool]] = []

    def run(
        self,
        arguments: Sequence[str],
        *,
        timeout_seconds: float,
        allow_failure: bool = False,
    ) -> int:
        fixed = tuple(arguments)
        self.calls.append((fixed, timeout_seconds, allow_failure))
        results = self.outcomes.get(fixed)
        result = results.pop(0) if results else 0
        if result != 0 and not allow_failure:
            raise MacOSEndpointLifecycleError("fixture command failed")
        return result


class RecordingContainmentAdapter:
    def __init__(
        self,
        *,
        status: MacOSContainmentStatus,
        result: MacOSResponseResult | None = None,
        error: MacOSResponseError | None = None,
    ) -> None:
        self.status = status
        self.result = result or MacOSResponseResult(
            True,
            "released",
            "provider detail must not escape",
            ("secret-recovery-material",),
        )
        self.error = error
        self.release_calls = 0

    def containment_status(self) -> MacOSContainmentStatus:
        return self.status

    def release_owned_state_for_recovery(self) -> MacOSResponseResult:
        self.release_calls += 1
        if self.error is not None:
            raise self.error
        return self.result


def installed_fixture(tmp_path: Path) -> tuple[Path, Path, Path, Path]:
    collector = tmp_path / "Library/ControlForge/bin/controlforge"
    runtime = tmp_path / "Library/ControlForge/bin/controlforge-runtime"
    config = tmp_path / "Library/Application Support/ControlForge/collector.yml"
    launchd = tmp_path / "Library/LaunchDaemons/com.controlforge.agent.plist"
    for binary in (collector, runtime):
        binary.parent.mkdir(parents=True, exist_ok=True)
        binary.write_bytes(b"signed-fixture")
        binary.chmod(0o755)
    config.parent.mkdir(parents=True, exist_ok=True)
    config.write_text(
        "\n".join(
            [
                "api_host: standalone.example.com",
                "api_port: 8443",
                "device_id: mac-primary",
                "credential_source: macos_system_keychain",
                "access_proxy_required: false",
            ]
        )
        + "\n",
        encoding="utf-8",
    )
    config.chmod(0o600)
    launchd.parent.mkdir(parents=True, exist_ok=True)
    launchd.write_bytes(
        plistlib.dumps(
            {
                "Label": "com.controlforge.agent",
                "ProgramArguments": [
                    str(collector),
                    "agent",
                    "--config",
                    str(config),
                ],
                "RunAtLoad": True,
                "StartInterval": 60,
                "Disabled": True,
            }
        )
    )
    launchd.chmod(0o644)
    return collector, runtime, config, launchd


def lifecycle(
    tmp_path: Path,
    runner: RecordingRunner,
    *,
    credential_check=None,  # type: ignore[no-untyped-def]
) -> tuple[MacOSEndpointLifecycle, tuple[Path, Path, Path, Path]]:
    paths = installed_fixture(tmp_path)
    check = credential_check or (lambda definition: None)
    return (
        MacOSEndpointLifecycle(
            collector_binary=paths[0],
            collector_runtime=paths[1],
            collector_config=paths[2],
            launchd_plist=paths[3],
            runner=runner,
            system=lambda: "Darwin",
            euid=lambda: 0,
            expected_uid=os.geteuid(),
            credential_check=check,
        ),
        paths,
    )


def uninstall_lifecycle(
    tmp_path: Path,
    runner: RecordingRunner,
    *,
    pf_cleanup=None,  # type: ignore[no-untyped-def]
) -> tuple[MacOSEndpointLifecycle, dict[str, Path], list[str]]:
    collector, runtime, config, launchd = installed_fixture(tmp_path)
    root = config.parent
    paths = {
        "collector": collector,
        "runtime": runtime,
        "config": config,
        "launchd": launchd,
        "default": root / "collector.default.yml",
        "controls": root / "agents.yml",
        "spool": root / "controlforge-agent-spool.db",
        "status": tmp_path / "Library/ControlForge/status/agent-status.json",
        "response": root / "response/pf-state.json",
        "app": tmp_path / "Applications/ControlForge.app",
        "log": tmp_path / "var/log/controlforge-agent.log",
        "error_log": tmp_path / "var/log/controlforge-agent-error.log",
        "rules": tmp_path / "Library/ControlForge/rules",
    }
    config.write_text(
        "\n".join(
            [
                "api_host: standalone.example.com",
                "api_port: 8443",
                "device_id: mac-primary",
                f"controls_path: {paths['controls']}",
                f"spool_path: {paths['spool']}",
                f"status_snapshot_path: {paths['status']}",
                "credential_source: macos_system_keychain",
                "keychain_service: com.controlforge.collector.v2",
                "access_proxy_required: false",
                "response_adapter_enabled: false",
                f"response_state_path: {paths['response']}",
            ]
        )
        + "\n",
        encoding="utf-8",
    )
    config.chmod(0o600)
    for name in ("default", "controls", "status"):
        path = paths[name]
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("fixture\n", encoding="utf-8")
        path.chmod(0o644)
    paths["response"].parent.mkdir(parents=True, exist_ok=True)
    paths["response"].write_text("{}\n", encoding="utf-8")
    paths["response"].chmod(0o600)
    for rule_name in PACKAGED_RULE_NAMES:
        rule = paths["rules"] / rule_name
        rule.parent.mkdir(parents=True, exist_ok=True)
        rule.write_text("id: fixture\n", encoding="utf-8")
        rule.chmod(0o644)
    paths["spool"].write_bytes(b"sqlite fixture")
    paths["log"].parent.mkdir(parents=True, exist_ok=True)
    paths["log"].write_text("collector output\n", encoding="utf-8")
    paths["error_log"].write_text("collector error\n", encoding="utf-8")
    app_binary = paths["app"] / "Contents/MacOS/ControlForge"
    app_binary.parent.mkdir(parents=True, exist_ok=True)
    app_binary.write_bytes(b"dashboard")
    app_binary.chmod(0o755)
    pf_calls: list[str] = []

    def release_pf(_definition) -> None:  # type: ignore[no-untyped-def]
        pf_calls.append("released")
        paths["response"].unlink(missing_ok=True)

    service = MacOSEndpointLifecycle(
        collector_binary=collector,
        collector_runtime=runtime,
        collector_config=config,
        launchd_plist=launchd,
        runner=runner,
        system=lambda: "Darwin",
        euid=lambda: 0,
        expected_uid=os.geteuid(),
        collector_default_config=paths["default"],
        controls_config=paths["controls"],
        collector_spool=paths["spool"],
        status_snapshot=paths["status"],
        response_state=paths["response"],
        rules_directory=paths["rules"],
        user_app=paths["app"],
        collector_log=paths["log"],
        collector_error_log=paths["error_log"],
        pkgutil="/fixture/pkgutil",
        pf_cleanup=pf_cleanup or release_pf,
    )
    return service, paths, pf_calls


def test_activation_verifies_first_check_in_before_enabling_launchd(tmp_path: Path) -> None:
    collector, _, _, launchd = installed_fixture(tmp_path)
    config = tmp_path / "Library/Application Support/ControlForge/collector.yml"
    print_command = (LAUNCHCTL, "print", LAUNCHD_LABEL)
    runner = RecordingRunner({print_command: [1, 0]})
    service = MacOSEndpointLifecycle(
        collector_binary=collector,
        collector_runtime=tmp_path / "Library/ControlForge/bin/controlforge-runtime",
        collector_config=config,
        launchd_plist=launchd,
        runner=runner,
        system=lambda: "Darwin",
        euid=lambda: 0,
        expected_uid=os.geteuid(),
        credential_check=lambda definition: None,
    )

    result = service.activate()

    assert result.device_id == "mac-primary"
    assert result.first_check_in_verified is True
    assert result.launch_daemon_loaded is True
    assert result.resumed_existing_daemon is False
    commands = [call[0] for call in runner.calls]
    agent_index = commands.index((str(collector), "agent", "--config", str(config)))
    enable_index = commands.index((LAUNCHCTL, "enable", LAUNCHD_LABEL))
    assert agent_index < enable_index
    assert (LAUNCHCTL, "bootstrap", "system", str(launchd)) in commands


def test_failed_first_check_in_never_enables_daemon(tmp_path: Path) -> None:
    collector, _, config, _ = installed_fixture(tmp_path)
    agent_command = (str(collector), "agent", "--config", str(config))
    runner = RecordingRunner(
        {
            (LAUNCHCTL, "print", LAUNCHD_LABEL): [1],
            agent_command: [3],
        }
    )
    service, _ = lifecycle(tmp_path, runner)

    with pytest.raises(MacOSEndpointLifecycleError):
        service.activate()

    commands = [call[0] for call in runner.calls]
    assert (LAUNCHCTL, "enable", LAUNCHD_LABEL) not in commands
    assert not any(command[1:2] == ("bootstrap",) for command in commands)


def test_partial_new_daemon_activation_rolls_back_to_disabled(tmp_path: Path) -> None:
    _, _, _, launchd = installed_fixture(tmp_path)
    runner = RecordingRunner(
        {
            (LAUNCHCTL, "print", LAUNCHD_LABEL): [1],
            (LAUNCHCTL, "bootstrap", "system", str(launchd)): [5],
        }
    )
    service, _ = lifecycle(tmp_path, runner)

    with pytest.raises(MacOSEndpointLifecycleError, match="activation failed"):
        service.activate()

    commands = [call[0] for call in runner.calls]
    assert (LAUNCHCTL, "bootout", LAUNCHD_LABEL) in commands
    assert (LAUNCHCTL, "disable", LAUNCHD_LABEL) in commands


def test_activation_resumes_an_existing_loaded_daemon_without_bootstrap(tmp_path: Path) -> None:
    runner = RecordingRunner({(LAUNCHCTL, "print", LAUNCHD_LABEL): [0, 0]})
    service, _ = lifecycle(tmp_path, runner)

    result = service.activate()

    commands = [call[0] for call in runner.calls]
    assert result.resumed_existing_daemon is True
    assert (LAUNCHCTL, "kickstart", "-k", LAUNCHD_LABEL) in commands
    assert (LAUNCHCTL, "enable", LAUNCHD_LABEL) not in commands
    assert not any(command[1:2] == ("bootstrap",) for command in commands)


@pytest.mark.parametrize("failure", ["platform", "root", "mode", "symlink", "plist"])
def test_activation_rejects_untrusted_environment_and_package(
    tmp_path: Path,
    failure: str,
) -> None:
    runner = RecordingRunner()
    service, paths = lifecycle(tmp_path, runner)
    collector, runtime, config, launchd = paths
    if failure == "platform":
        service = MacOSEndpointLifecycle(
            collector_binary=collector,
            collector_runtime=runtime,
            collector_config=config,
            launchd_plist=launchd,
            runner=runner,
            system=lambda: "Linux",
            euid=lambda: 0,
            expected_uid=os.geteuid(),
            credential_check=lambda definition: None,
        )
    elif failure == "root":
        service = MacOSEndpointLifecycle(
            collector_binary=collector,
            collector_runtime=runtime,
            collector_config=config,
            launchd_plist=launchd,
            runner=runner,
            system=lambda: "Darwin",
            euid=lambda: 501,
            expected_uid=os.geteuid(),
            credential_check=lambda definition: None,
        )
    elif failure == "mode":
        config.chmod(0o644)
    elif failure == "symlink":
        collector.unlink()
        collector.symlink_to(runtime)
    else:
        payload = plistlib.loads(launchd.read_bytes())
        payload["ProgramArguments"] = ["/bin/sh", "-c", "unsafe"]
        launchd.write_bytes(plistlib.dumps(payload))

    with pytest.raises(MacOSEndpointLifecycleError):
        service.activate()

    assert runner.calls == []


def test_missing_credentials_stops_before_first_check_in(tmp_path: Path) -> None:
    runner = RecordingRunner()

    def missing(_definition) -> None:  # type: ignore[no-untyped-def]
        raise MacOSEndpointLifecycleError("credentials missing")

    service, paths = lifecycle(tmp_path, runner, credential_check=missing)
    with pytest.raises(MacOSEndpointLifecycleError, match="credentials missing"):
        service.activate()

    commands = [call[0] for call in runner.calls]
    assert commands == [
        (CODESIGN, "--verify", "--strict", str(paths[0])),
        (CODESIGN, "--verify", "--strict", str(paths[1])),
    ]


def test_fixed_runner_rejects_arbitrary_commands_without_execution(tmp_path: Path) -> None:
    collector, runtime, config, launchd = installed_fixture(tmp_path)
    runner = FixedMacOSLifecycleRunner(
        collector_binary=collector,
        collector_runtime=runtime,
        collector_config=config,
        launchd_plist=launchd,
    )

    with pytest.raises(ValueError, match="not allowlisted"):
        runner.run(
            ["/bin/sh", "-c", "launchctl disable system/com.controlforge.agent"],
            timeout_seconds=1,
        )


def test_local_containment_status_is_redacted_and_does_not_run_commands(tmp_path: Path) -> None:
    runner = RecordingRunner()
    adapter = RecordingContainmentAdapter(
        status=MacOSContainmentStatus(
            "isolated",
            datetime.now(timezone.utc) + timedelta(minutes=10),
        )
    )
    service = MacOSEndpointLifecycle(
        runner=runner,
        system=lambda: "Darwin",
        euid=lambda: 0,
        expected_uid=os.geteuid(),
        response_state=tmp_path / "pf-state.json",
        containment_adapter=adapter,
    )

    status = service.containment_status()

    assert status.state == "isolated"
    assert status.expires_at is not None
    assert asdict(status).keys() == {"state", "expires_at"}
    assert runner.calls == []
    assert adapter.release_calls == 0


def test_break_glass_release_disables_collector_before_releasing_pf(tmp_path: Path) -> None:
    runner = RecordingRunner({(LAUNCHCTL, "print", LAUNCHD_LABEL): [1]})
    adapter = RecordingContainmentAdapter(status=MacOSContainmentStatus("isolated"))
    service = MacOSEndpointLifecycle(
        runner=runner,
        system=lambda: "Darwin",
        euid=lambda: 0,
        expected_uid=os.geteuid(),
        response_state=tmp_path / "pf-state.json",
        containment_adapter=adapter,
    )

    result = service.release_containment(confirmation=RELEASE_CONTAINMENT_CONFIRMATION)

    assert result.collector_disabled is True
    assert result.state == "released"
    assert "provider detail" not in result.summary
    assert "secret-recovery-material" not in result.summary
    assert adapter.release_calls == 1
    assert [call[0] for call in runner.calls] == [
        (LAUNCHCTL, "bootout", LAUNCHD_LABEL),
        (LAUNCHCTL, "disable", LAUNCHD_LABEL),
        (LAUNCHCTL, "print", LAUNCHD_LABEL),
    ]


def test_break_glass_release_requires_confirmation_before_mutation(tmp_path: Path) -> None:
    runner = RecordingRunner()
    adapter = RecordingContainmentAdapter(status=MacOSContainmentStatus("isolated"))
    service = MacOSEndpointLifecycle(
        runner=runner,
        system=lambda: "Darwin",
        euid=lambda: 0,
        expected_uid=os.geteuid(),
        response_state=tmp_path / "pf-state.json",
        containment_adapter=adapter,
    )

    with pytest.raises(MacOSEndpointLifecycleError, match="requires --confirm"):
        service.release_containment(confirmation="release")

    assert runner.calls == []
    assert adapter.release_calls == 0


def test_break_glass_release_stops_if_daemon_or_pf_state_cannot_converge(
    tmp_path: Path,
) -> None:
    adapter = RecordingContainmentAdapter(status=MacOSContainmentStatus("isolated"))
    still_loaded = RecordingRunner({(LAUNCHCTL, "print", LAUNCHD_LABEL): [0]})
    service = MacOSEndpointLifecycle(
        runner=still_loaded,
        system=lambda: "Darwin",
        euid=lambda: 0,
        expected_uid=os.geteuid(),
        response_state=tmp_path / "pf-state.json",
        containment_adapter=adapter,
    )
    with pytest.raises(MacOSEndpointLifecycleError, match="remains loaded"):
        service.release_containment(confirmation=RELEASE_CONTAINMENT_CONFIRMATION)
    assert adapter.release_calls == 0

    runner = RecordingRunner({(LAUNCHCTL, "print", LAUNCHD_LABEL): [1]})
    failing = RecordingContainmentAdapter(
        status=MacOSContainmentStatus("isolated"),
        error=MacOSResponseError("release_failed"),
    )
    service = MacOSEndpointLifecycle(
        runner=runner,
        system=lambda: "Darwin",
        euid=lambda: 0,
        expected_uid=os.geteuid(),
        response_state=tmp_path / "pf-state.json",
        containment_adapter=failing,
    )
    with pytest.raises(MacOSEndpointLifecycleError, match="could not be safely released") as exc:
        service.release_containment(confirmation=RELEASE_CONTAINMENT_CONFIRMATION)
    assert "release_failed" not in str(exc.value)


def test_uninstall_preserves_spool_and_logs_by_default(tmp_path: Path) -> None:
    runner = RecordingRunner({(LAUNCHCTL, "print", LAUNCHD_LABEL): [1]})
    service, paths, pf_calls = uninstall_lifecycle(tmp_path, runner)
    operator_rule = paths["rules"] / "operator-owned.yml"
    operator_rule.write_text("id: operator-owned\n", encoding="utf-8")
    operator_rule.chmod(0o644)

    result = service.uninstall(confirmation=UNINSTALL_CONFIRMATION)

    commands = [call[0] for call in runner.calls]
    assert commands[:4] == [
        (CODESIGN, "--verify", "--strict", str(paths["collector"])),
        (LAUNCHCTL, "bootout", LAUNCHD_LABEL),
        (LAUNCHCTL, "disable", LAUNCHD_LABEL),
        (LAUNCHCTL, "print", LAUNCHD_LABEL),
    ]
    assert commands[4] == (str(paths["collector"]), "keychain-delete-all")
    assert commands[-1] == ("/fixture/pkgutil", "--forget", "com.controlforge.agent")
    assert pf_calls == ["released"]
    assert result.launch_daemon_stopped is True
    assert result.pf_state_released_or_absent is True
    assert result.keychain_items_removed is True
    assert result.preserved == ("telemetry_spool", "collector_logs")
    assert paths["spool"].exists()
    assert paths["log"].exists()
    assert paths["error_log"].exists()
    for name in ("collector", "runtime", "config", "launchd", "default", "controls", "status"):
        assert not paths[name].exists()
    assert all(not (paths["rules"] / name).exists() for name in PACKAGED_RULE_NAMES)
    assert operator_rule.exists()
    assert not paths["app"].exists()


def test_uninstall_deletes_only_explicit_spool_and_log_files_when_confirmed(
    tmp_path: Path,
) -> None:
    runner = RecordingRunner({(LAUNCHCTL, "print", LAUNCHD_LABEL): [1]})
    service, paths, _ = uninstall_lifecycle(tmp_path, runner)
    wal = Path(f"{paths['spool']}-wal")
    shm = Path(f"{paths['spool']}-shm")
    wal.write_bytes(b"wal")
    shm.write_bytes(b"shm")
    unrelated = paths["spool"].parent / "operator-backup.db"
    unrelated.write_bytes(b"keep")

    result = service.uninstall(
        confirmation=UNINSTALL_CONFIRMATION,
        delete_spool=True,
        delete_logs=True,
    )

    assert result.preserved == ()
    assert {"telemetry_spool", "telemetry_spool_wal", "telemetry_spool_shm"}.issubset(
        result.removed
    )
    assert {"collector_log", "collector_error_log"}.issubset(result.removed)
    assert not paths["spool"].exists()
    assert not wal.exists()
    assert not shm.exists()
    assert not paths["log"].exists()
    assert not paths["error_log"].exists()
    assert unrelated.exists()


def test_uninstall_confirmation_and_allowlist_fail_before_mutation(tmp_path: Path) -> None:
    runner = RecordingRunner()
    service, paths, pf_calls = uninstall_lifecycle(tmp_path, runner)
    with pytest.raises(MacOSEndpointLifecycleError, match="requires --confirm"):
        service.uninstall(confirmation="yes")
    assert runner.calls == []

    config = paths["config"]
    config.write_text(
        config.read_text(encoding="utf-8").replace(
            str(paths["response"]),
            str(tmp_path / "outside/pf-state.json"),
        ),
        encoding="utf-8",
    )
    config.chmod(0o600)
    with pytest.raises(MacOSEndpointLifecycleError, match="outside the uninstall allowlist"):
        service.uninstall(confirmation=UNINSTALL_CONFIRMATION)
    assert pf_calls == []
    assert [call[0] for call in runner.calls] == [
        (CODESIGN, "--verify", "--strict", str(paths["collector"]))
    ]


@pytest.mark.parametrize(("system", "euid"), [("Linux", 0), ("Darwin", 501)])
def test_uninstall_requires_root_on_macos_before_any_command(
    tmp_path: Path,
    system: str,
    euid: int,
) -> None:
    runner = RecordingRunner()
    service, paths, _ = uninstall_lifecycle(tmp_path, runner)
    service = MacOSEndpointLifecycle(
        collector_binary=paths["collector"],
        collector_runtime=paths["runtime"],
        collector_config=paths["config"],
        launchd_plist=paths["launchd"],
        runner=runner,
        system=lambda: system,
        euid=lambda: euid,
        expected_uid=os.geteuid(),
    )

    with pytest.raises(MacOSEndpointLifecycleError, match="uninstall requires"):
        service.uninstall(confirmation=UNINSTALL_CONFIRMATION)

    assert runner.calls == []


def test_uninstall_rejects_symlinked_app_before_stopping_daemon(tmp_path: Path) -> None:
    runner = RecordingRunner()
    service, paths, pf_calls = uninstall_lifecycle(tmp_path, runner)
    target = tmp_path / "operator-app"
    target.mkdir()
    shutil.rmtree(paths["app"])
    paths["app"].symlink_to(target, target_is_directory=True)

    with pytest.raises(MacOSEndpointLifecycleError, match="symbolic link"):
        service.uninstall(confirmation=UNINSTALL_CONFIRMATION)

    assert pf_calls == []
    assert [call[0] for call in runner.calls] == [
        (CODESIGN, "--verify", "--strict", str(paths["collector"]))
    ]
    assert target.exists()


def test_uninstall_stops_before_pf_or_keychain_if_daemon_remains_loaded(
    tmp_path: Path,
) -> None:
    runner = RecordingRunner({(LAUNCHCTL, "print", LAUNCHD_LABEL): [0]})
    service, paths, pf_calls = uninstall_lifecycle(tmp_path, runner)

    with pytest.raises(MacOSEndpointLifecycleError, match="remains loaded"):
        service.uninstall(confirmation=UNINSTALL_CONFIRMATION)

    assert pf_calls == []
    assert (str(paths["collector"]), "keychain-delete-all") not in [
        call[0] for call in runner.calls
    ]
    assert paths["config"].exists()


def test_uninstall_stops_before_keychain_and_files_if_pf_release_fails(
    tmp_path: Path,
) -> None:
    runner = RecordingRunner({(LAUNCHCTL, "print", LAUNCHD_LABEL): [1]})

    def fail_pf(_definition) -> None:  # type: ignore[no-untyped-def]
        raise MacOSResponseError("release_failed")

    service, paths, _ = uninstall_lifecycle(tmp_path, runner, pf_cleanup=fail_pf)
    with pytest.raises(MacOSEndpointLifecycleError, match="PF state"):
        service.uninstall(confirmation=UNINSTALL_CONFIRMATION)

    assert (str(paths["collector"]), "keychain-delete-all") not in [
        call[0] for call in runner.calls
    ]
    assert paths["config"].exists()


def test_uninstall_stops_before_file_removal_if_keychain_cleanup_fails(
    tmp_path: Path,
) -> None:
    runner = RecordingRunner({(LAUNCHCTL, "print", LAUNCHD_LABEL): [1]})
    service, paths, _ = uninstall_lifecycle(tmp_path, runner)
    runner.outcomes[(str(paths["collector"]), "keychain-delete-all")] = [74]

    with pytest.raises(MacOSEndpointLifecycleError, match="fixture command failed"):
        service.uninstall(confirmation=UNINSTALL_CONFIRMATION)

    assert paths["config"].exists()
    assert paths["collector"].exists()
    assert paths["app"].exists()
