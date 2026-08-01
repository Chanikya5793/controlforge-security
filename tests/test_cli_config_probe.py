from datetime import datetime, timezone
from pathlib import Path

import pytest

from controlforge import cli
from controlforge.config import load_control_config
from controlforge.exposure import HibpError
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


def test_cli_main_reports_provider_error_without_traceback(monkeypatch, capsys) -> None:  # type: ignore[no-untyped-def]
    def fail() -> int:
        raise HibpError("HIBP request failed with HTTP 401")

    monkeypatch.setattr(cli, "run", fail)
    with pytest.raises(SystemExit) as exit_info:
        cli.main()

    assert exit_info.value.code == 3
    assert capsys.readouterr().err == '{"error": "HIBP request failed with HTTP 401"}\n'
