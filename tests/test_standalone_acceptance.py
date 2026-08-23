from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path


def _run_harness(project_root: Path, *arguments: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(  # noqa: S603 - executable and repository-local script are fixed
        [
            sys.executable,
            str(project_root / "tools" / "verify_standalone_acceptance.py"),
            "--project-root",
            str(project_root),
            "--json",
            *arguments,
        ],
        cwd=project_root,
        capture_output=True,
        text=True,
        check=False,
    )


def test_acceptance_harness_proves_current_scope_without_overclaiming(
    project_root: Path,
) -> None:
    completed = _run_harness(project_root)

    assert completed.returncode == 0, completed.stderr
    evidence = json.loads(completed.stdout)
    assert evidence["current_scope_passed"] is True
    assert evidence["release_ready"] is False
    statuses = {item["name"]: item["status"] for item in evidence["checks"]}
    assert statuses == {
        "runtime_and_admin_surface": "pass",
        "first_admin_bootstrap_api": "pass",
        "device_enrollment_api": "pass",
        "signed_synthetic_signal": "pass",
        "worker_restart_recovery": "pass",
        "investigation_and_diagnostics_api": "pass",
        "semantic_case_aggregation": "pass",
        "analyst_disposition_api": "pass",
        "audited_telemetry_retention": "pass",
        "original_decision_replay_api": "pass",
        "active_response_governance_api": "pass",
        "endpoint_bound_credential_rotation": "pass",
        "macos_pf_adapter_contract": "pass",
        "sqlite_online_snapshot_smoke": "pass",
        "cloud_local_stateless_contract": "not_run",
        "operational_backup_restore": "pass",
        "temporary_fault_injection_matrix": "pass",
        "one_command_appliance_install": "unverified",
        "real_endpoint_and_local_app": "unverified",
        "trusted_tls_and_hardware_passkey": "unverified",
        "signed_notarized_standalone_package": "not_run",
        "clean_install_upgrade_removal": "unverified",
        "physical_active_response": "unverified",
    }
    assert "credential_secret" not in completed.stdout
    assert "bootstrap token" not in completed.stdout.casefold()


def test_release_ready_mode_fails_closed_while_required_gaps_remain(
    project_root: Path,
) -> None:
    completed = _run_harness(project_root, "--require-release-ready")

    assert completed.returncode == 2
    assert json.loads(completed.stdout)["release_ready"] is False


def test_acceptance_document_names_every_release_stage_and_non_claim(project_root: Path) -> None:
    document = " ".join(
        (project_root / "docs" / "STANDALONE_1_0_ACCEPTANCE.md").read_text(encoding="utf-8").split()
    )

    for stage in (
        "Install",
        "Bootstrap",
        "Enroll",
        "Signal",
        "Investigate",
        "Replay",
        "Disposition",
        "Response",
        "Restart",
        "Backup/restore",
        "Diagnose",
    ):
        assert f"| {stage} |" in document
    for required_boundary in (
        "No physical active-response capability is claimed",
        "historical 2026-08-24 artifact",
        "not a package of the current working tree",
        "new account-enabled release must target a verified standalone HTTPS account server",
        "trusted-certificate",
        "physical-hardware acceptance",
        "stateful correlation parity",
        "verify_macos_physical_acceptance.py",
        "never requests a Keychain secret value or reads telemetry rows",
    ):
        assert required_boundary.casefold() in document.casefold()
    assert "current-source `ControlForge-0.3.0.pkg`" not in document
