from __future__ import annotations

import json
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

import pytest

from controlforge.standalone.endurance import run_standalone_endurance


def test_endurance_gate_proves_restart_backup_restore_and_case_aggregation(
    tmp_path: Path,
    project_root: Path,
) -> None:
    report = run_standalone_endurance(
        tmp_path / "endurance",
        project_root / "rules",
        event_count=200,
        batch_size=40,
        alert_every=20,
        generated_at=datetime(2026, 8, 24, tzinfo=timezone.utc),
    )

    assert report.passed is True
    assert report.event_count == 200
    assert report.duplicate_count == 200
    assert report.worker_reconstructed is True
    assert report.online_backup_verified is True
    assert report.live_restore_rejected is True
    assert report.live.events == 200
    assert report.live.alerts == 10
    assert report.live.active_cases == 1
    assert report.live.case_alert_links == 10
    assert report.restored_midpoint.events == 100
    assert report.restored_midpoint.alerts == 5
    assert report.restored_midpoint.active_cases == 1
    assert report.restored_midpoint.case_alert_links == 5
    serialized = json.dumps(report.as_dict(), sort_keys=True)
    assert "credential" not in serialized.casefold()
    assert "/" not in report.schema_version


def test_endurance_gate_rejects_unsafe_or_invalid_workloads(
    tmp_path: Path,
    project_root: Path,
) -> None:
    occupied = tmp_path / "occupied"
    occupied.mkdir()
    (occupied / "existing.db").write_text("preserve")

    with pytest.raises(ValueError, match="must be empty"):
        run_standalone_endurance(occupied, project_root / "rules", event_count=200)
    assert (occupied / "existing.db").read_text() == "preserve"
    with pytest.raises(ValueError, match="event_count"):
        run_standalone_endurance(tmp_path / "small", project_root / "rules", event_count=199)


def test_endurance_cli_emits_redacted_json(project_root: Path) -> None:
    completed = subprocess.run(  # noqa: S603 - repository-local verifier is fixed
        [
            sys.executable,
            str(project_root / "tools" / "verify_standalone_endurance.py"),
            "--events",
            "200",
            "--batch-size",
            "50",
            "--alert-every",
            "20",
        ],
        cwd=project_root,
        capture_output=True,
        text=True,
        check=False,
    )

    assert completed.returncode == 0, completed.stderr
    payload = json.loads(completed.stdout)
    assert payload["passed"] is True
    assert payload["event_count"] == 200
    assert "credential" not in completed.stdout.casefold()
