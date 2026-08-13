from __future__ import annotations

import hashlib
import json
import os
import sqlite3
from datetime import datetime, timedelta, timezone
from pathlib import Path

import yaml

from controlforge.collector_agent import (
    AgentContainmentStatusSummary,
    AgentControlStatusSummary,
    AgentDeliveryStatusSummary,
    AgentStatusSnapshot,
    AgentTelemetryStatusSummary,
    CollectorDefinition,
)
from controlforge.macos_acceptance import (
    CODESIGN,
    KEYCHAIN_SERVICE,
    LAUNCHCTL,
    LAUNCHD_LABEL,
    PACKAGE_IDENTIFIER,
    PACKAGED_RULE_NAMES,
    PKGUTIL,
    SECURITY,
    SPCTL,
    STAPLER,
    SYSTEM_KEYCHAIN,
    MacOSAcceptancePaths,
    MacOSPhysicalAcceptanceVerifier,
    ReadOnlyCommandResult,
)

NOW = datetime(2026, 8, 24, 6, 0, tzinfo=timezone.utc)


class FixtureRunner:
    def __init__(self) -> None:
        self.results: dict[tuple[str, ...], ReadOnlyCommandResult] = {}
        self.calls: list[tuple[str, ...]] = []

    def run(self, arguments, timeout_seconds):  # type: ignore[no-untyped-def]
        assert 0 < timeout_seconds <= 30
        fixed = tuple(arguments)
        self.calls.append(fixed)
        return self.results.get(fixed, ReadOnlyCommandResult(1))


def trusted_file(path: Path, mode: int = 0o644) -> None:
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    path.write_bytes(b"fixture")
    path.chmod(mode)


def installed_fixture(tmp_path: Path) -> tuple[MacOSAcceptancePaths, FixtureRunner]:
    paths = MacOSAcceptancePaths.from_root(tmp_path)
    trusted_file(paths.collector_binary, 0o755)
    trusted_file(paths.collector_runtime, 0o755)
    trusted_file(paths.launchd_plist, 0o644)
    trusted_file(paths.collector_default_config, 0o644)
    trusted_file(paths.controls_config, 0o644)
    for rule_name in PACKAGED_RULE_NAMES:
        trusted_file(paths.rules_directory / rule_name, 0o644)
    paths.user_app.mkdir(mode=0o755, parents=True)
    runner = FixtureRunner()
    runner.results[(PKGUTIL, "--pkg-info", PACKAGE_IDENTIFIER)] = ReadOnlyCommandResult(0)
    runner.results[(LAUNCHCTL, "print", LAUNCHD_LABEL)] = ReadOnlyCommandResult(1)
    for command in (
        (CODESIGN, "--verify", "--strict", str(paths.collector_binary)),
        (CODESIGN, "--verify", "--strict", str(paths.collector_runtime)),
        (CODESIGN, "--verify", "--deep", "--strict", str(paths.user_app)),
    ):
        runner.results[command] = ReadOnlyCommandResult(0)
    return paths, runner


def enroll_fixture(paths: MacOSAcceptancePaths, runner: FixtureRunner) -> None:
    definition = CollectorDefinition(
        api_host="standalone.example.com",
        api_port=8443,
        device_id="physical-mac-1",
        controls_path=paths.controls_config,
        spool_path=paths.collector_spool,
        status_snapshot_path=paths.status_snapshot,
        credential_source="macos_system_keychain",
        access_proxy_required=False,
        action_polling_enabled=True,
        credential_rotation_enabled=True,
        response_adapter_enabled=False,
        keychain_service=KEYCHAIN_SERVICE,
    )
    trusted_file(paths.collector_config, 0o600)
    paths.collector_config.write_text(
        yaml.safe_dump(definition.model_dump(mode="json"), sort_keys=True),
        encoding="utf-8",
    )
    for account, result in (
        ("credential-id", 0),
        ("credential-secret", 0),
        ("credential-pair-v1", 1),
    ):
        runner.results[
            (
                SECURITY,
                "find-generic-password",
                "-s",
                KEYCHAIN_SERVICE,
                "-a",
                account,
                SYSTEM_KEYCHAIN,
            )
        ] = ReadOnlyCommandResult(result)


def test_preinstall_verifies_artifact_and_absence_without_sensitive_output(
    tmp_path: Path,
) -> None:
    paths = MacOSAcceptancePaths.from_root(tmp_path / "root")
    package = tmp_path / "ControlForge.pkg"
    package.write_bytes(b"signed-package-fixture")
    digest = hashlib.sha256(package.read_bytes()).hexdigest()
    runner = FixtureRunner()
    runner.results[(PKGUTIL, "--pkg-info", PACKAGE_IDENTIFIER)] = ReadOnlyCommandResult(1)
    runner.results[(PKGUTIL, "--check-signature", str(package))] = ReadOnlyCommandResult(
        0,
        "Status: signed by a developer certificate issued by Apple for distribution",
    )
    runner.results[(STAPLER, "stapler", "validate", str(package))] = ReadOnlyCommandResult(
        0,
        "The validate action worked!",
    )
    runner.results[(SPCTL, "--assess", "--type", "install", "-vv", str(package))] = (
        ReadOnlyCommandResult(0, "source=Notarized Developer ID")
    )

    report = MacOSPhysicalAcceptanceVerifier(
        phase="preinstall",
        paths=paths,
        package=package,
        package_sha256=digest,
        runner=runner,
        system=lambda: "Darwin",
        machine=lambda: "arm64",
        mac_version=lambda: "15.6",
        hostname=lambda: "private-clean-mac-name",
        expected_uid=os.geteuid(),
    ).verify(NOW)

    serialized = json.dumps(report.as_dict(), sort_keys=True)
    assert report.passed is True
    assert report.machine_fingerprint == hashlib.sha256(b"private-clean-mac-name").hexdigest()[:16]
    assert "private-clean-mac-name" not in serialized
    assert "credential" not in serialized.casefold()


def test_installed_enrolled_and_running_phases_prove_strict_local_boundaries(
    tmp_path: Path,
) -> None:
    paths, runner = installed_fixture(tmp_path)
    installed = MacOSPhysicalAcceptanceVerifier(
        phase="installed",
        paths=paths,
        runner=runner,
        system=lambda: "Darwin",
        machine=lambda: "arm64",
        mac_version=lambda: "15.6",
        hostname=lambda: "test-mac",
        expected_uid=os.geteuid(),
    ).verify(NOW)
    assert installed.passed is True
    assert "canonical_rule_payload" in {
        check.name for check in installed.checks if check.status == "pass"
    }

    enroll_fixture(paths, runner)
    enrolled = MacOSPhysicalAcceptanceVerifier(
        phase="enrolled",
        paths=paths,
        runner=runner,
        system=lambda: "Darwin",
        machine=lambda: "arm64",
        mac_version=lambda: "15.6",
        hostname=lambda: "test-mac",
        expected_uid=os.geteuid(),
    ).verify(NOW)
    assert enrolled.passed is True

    runner.results[(LAUNCHCTL, "print", LAUNCHD_LABEL)] = ReadOnlyCommandResult(0)
    status = AgentStatusSnapshot(
        generated_at=NOW - timedelta(seconds=30),
        device_id="physical-mac-1",
        agent_version="0.3.0",
        run_status="completed",
        controls=AgentControlStatusSummary(evaluated=True, total=3, failed=0),
        delivery=AgentDeliveryStatusSummary(
            status="succeeded",
            batches_delivered=1,
            batches_pending=0,
            batches_pending_is_lower_bound=False,
        ),
        telemetry=AgentTelemetryStatusSummary(
            events_collected=3,
            santa_events_collected=0,
            santa_lines_rejected=0,
        ),
        containment=AgentContainmentStatusSummary(state="released"),
        actions_processed=0,
    )
    trusted_file(paths.status_snapshot, 0o644)
    paths.status_snapshot.write_text(status.model_dump_json(), encoding="utf-8")
    paths.collector_spool.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    with sqlite3.connect(paths.collector_spool) as connection:
        connection.execute("CREATE TABLE spool_fixture(id INTEGER PRIMARY KEY)")
    paths.collector_spool.chmod(0o600)

    running = MacOSPhysicalAcceptanceVerifier(
        phase="running",
        paths=paths,
        runner=runner,
        system=lambda: "Darwin",
        machine=lambda: "arm64",
        mac_version=lambda: "15.6",
        hostname=lambda: "test-mac",
        expected_uid=os.geteuid(),
    ).verify(NOW)

    assert running.passed is True
    assert {check.name for check in running.checks if check.status == "pass"} >= {
        "system_keychain_credential_presence",
        "status_contract_v2",
        "status_freshness",
        "containment_posture_bounded",
        "telemetry_spool_integrity",
    }


def test_running_phase_fails_closed_for_stale_or_secret_extended_status(tmp_path: Path) -> None:
    paths, runner = installed_fixture(tmp_path)
    enroll_fixture(paths, runner)
    runner.results[(LAUNCHCTL, "print", LAUNCHD_LABEL)] = ReadOnlyCommandResult(0)
    paths.collector_spool.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    with sqlite3.connect(paths.collector_spool) as connection:
        connection.execute("CREATE TABLE spool_fixture(id INTEGER PRIMARY KEY)")
    paths.collector_spool.chmod(0o600)
    trusted_file(paths.status_snapshot, 0o644)
    paths.status_snapshot.write_text(
        json.dumps(
            {
                "schema_version": "controlforge-agent-status-v2",
                "generated_at": (NOW - timedelta(hours=1)).isoformat(),
                "device_id": "physical-mac-1",
                "agent_version": "0.3.0",
                "run_status": "completed",
                "failure_stage": None,
                "controls": {"evaluated": True, "total": 1, "failed": 0},
                "delivery": {
                    "status": "succeeded",
                    "batches_delivered": 1,
                    "batches_pending": 0,
                    "batches_pending_is_lower_bound": False,
                },
                "telemetry": {
                    "events_collected": 1,
                    "santa_events_collected": 0,
                    "santa_lines_rejected": 0,
                },
                "containment": {"state": "released", "expires_at": None},
                "actions_processed": 0,
                "credential_secret": "must-not-be-accepted",
            }
        ),
        encoding="utf-8",
    )

    report = MacOSPhysicalAcceptanceVerifier(
        phase="running",
        paths=paths,
        runner=runner,
        system=lambda: "Darwin",
        machine=lambda: "arm64",
        mac_version=lambda: "15.6",
        hostname=lambda: "test-mac",
        expected_uid=os.geteuid(),
    ).verify(NOW)

    assert report.passed is False
    failed = {check.name for check in report.checks if check.status == "fail"}
    assert {"status_contract_v2", "status_freshness", "latest_agent_run"} <= failed


def test_uninstalled_phase_proves_fixed_payload_and_receipt_absence(tmp_path: Path) -> None:
    runner = FixtureRunner()
    runner.results[(PKGUTIL, "--pkg-info", PACKAGE_IDENTIFIER)] = ReadOnlyCommandResult(1)
    report = MacOSPhysicalAcceptanceVerifier(
        phase="uninstalled",
        paths=MacOSAcceptancePaths.from_root(tmp_path),
        runner=runner,
        system=lambda: "Darwin",
        machine=lambda: "arm64",
        mac_version=lambda: "15.6",
        hostname=lambda: "test-mac",
        expected_uid=os.geteuid(),
    ).verify(NOW)
    assert report.passed is True
