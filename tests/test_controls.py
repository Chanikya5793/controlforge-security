from datetime import datetime, timezone

import pytest

from controlforge.controls import EndpointAssuranceEngine
from controlforge.models import (
    AgentDefinition,
    ControlStatus,
    EndpointSnapshot,
)
from controlforge.probes import FixtureSystemProbe


def agent() -> AgentDefinition:
    return AgentDefinition(
        agent_id="example-edr",
        display_name="Example EDR",
        process_names=["sensor"],
        install_paths=["/opt/example/sensor"],
        heartbeat_path="/var/run/example/heartbeat",
        heartbeat_max_age_seconds=300,
    )


def snapshot(**overrides: object) -> EndpointSnapshot:
    values = {
        "hostname": "endpoint-01",
        "platform": "linux",
        "observed_at": datetime(2026, 8, 11, 14, 0, tzinfo=timezone.utc),
        "running_processes": {"sensor"},
        "existing_paths": {"/opt/example/sensor", "/var/run/example/heartbeat"},
        "file_modified_epoch": {"/var/run/example/heartbeat": 1786456740.0},
    }
    values.update(overrides)
    return EndpointSnapshot.model_validate(values)


def test_healthy_agent_has_process_install_and_fresh_heartbeat() -> None:
    report = EndpointAssuranceEngine([agent()], FixtureSystemProbe(snapshot())).run()

    finding = report.findings[0]
    assert finding.status == ControlStatus.HEALTHY
    assert finding.installed is True
    assert finding.running is True
    assert finding.heartbeat_age_seconds == 60
    assert report.failed_count == 0


def test_missing_agent_fails_closed() -> None:
    fixture = snapshot(running_processes=set(), existing_paths=set(), file_modified_epoch={})
    finding = EndpointAssuranceEngine([agent()], FixtureSystemProbe(fixture)).run().findings[0]

    assert finding.status == ControlStatus.FAILED
    assert finding.installed is False
    assert "Install and enroll" in finding.recommended_action


def test_installed_but_stopped_agent_fails() -> None:
    fixture = snapshot(running_processes=set())
    finding = EndpointAssuranceEngine([agent()], FixtureSystemProbe(fixture)).run().findings[0]

    assert finding.installed is True
    assert finding.running is False
    assert finding.status == ControlStatus.FAILED
    assert "Restart" in finding.recommended_action


def test_stale_heartbeat_is_degraded() -> None:
    fixture = snapshot(file_modified_epoch={"/var/run/example/heartbeat": 1786456200.0})
    report = EndpointAssuranceEngine([agent()], FixtureSystemProbe(fixture)).run()

    assert report.findings[0].status == ControlStatus.DEGRADED
    assert report.degraded_count == 1


def test_process_names_are_case_insensitive() -> None:
    fixture = snapshot(running_processes={"SENSOR"})
    finding = EndpointAssuranceEngine([agent()], FixtureSystemProbe(fixture)).run().findings[0]
    assert finding.running is True


def test_empty_agent_configuration_is_rejected() -> None:
    with pytest.raises(ValueError, match="at least one"):
        EndpointAssuranceEngine([], FixtureSystemProbe(snapshot()))
