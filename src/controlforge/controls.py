"""Endpoint security-agent installation, process, and heartbeat assurance."""

from __future__ import annotations

import os
from collections.abc import Iterable
from pathlib import Path
from typing import Optional

from .models import (
    AgentDefinition,
    ControlFinding,
    ControlReport,
    ControlStatus,
    EndpointSnapshot,
)
from .probes import SystemProbe


class EndpointAssuranceEngine:
    def __init__(self, agents: Iterable[AgentDefinition], probe: SystemProbe) -> None:
        self._agents = list(agents)
        if not self._agents:
            raise ValueError("at least one endpoint agent must be configured")
        self._probe = probe

    def run(self) -> ControlReport:
        observed_paths = {
            self._normalize_path(path)
            for agent in self._agents
            for path in [*agent.install_paths, agent.heartbeat_path]
            if path
        }
        snapshot = self._probe.snapshot(sorted(observed_paths))
        findings = [self._evaluate(agent, snapshot) for agent in self._agents]
        return ControlReport(
            hostname=snapshot.hostname,
            platform=snapshot.platform,
            findings=findings,
        )

    @staticmethod
    def _normalize_path(raw_path: str) -> str:
        return str(Path(os.path.expandvars(os.path.expanduser(raw_path))))

    def _evaluate(self, agent: AgentDefinition, snapshot: EndpointSnapshot) -> ControlFinding:
        expected_processes = {name.casefold() for name in agent.process_names}
        observed_processes = {name.casefold() for name in snapshot.running_processes}
        matched_processes = expected_processes.intersection(observed_processes)
        normalized_install_paths = {self._normalize_path(path) for path in agent.install_paths}
        matched_paths = normalized_install_paths.intersection(snapshot.existing_paths)
        heartbeat_path = (
            self._normalize_path(agent.heartbeat_path) if agent.heartbeat_path else None
        )
        heartbeat_exists = bool(heartbeat_path and heartbeat_path in snapshot.existing_paths)
        installed = bool(matched_processes or matched_paths or heartbeat_exists)
        running = bool(matched_processes)
        evidence: list[str] = []

        if matched_processes:
            evidence.append(f"running process: {', '.join(sorted(matched_processes))}")
        if matched_paths:
            evidence.append(f"installed path: {', '.join(sorted(matched_paths))}")

        heartbeat_age: Optional[int] = None
        heartbeat_stale = False
        if heartbeat_path and heartbeat_path in snapshot.file_modified_epoch:
            modified = snapshot.file_modified_epoch[heartbeat_path]
            heartbeat_age = max(0, int(snapshot.observed_at.timestamp() - modified))
            heartbeat_stale = heartbeat_age > agent.heartbeat_max_age_seconds
            evidence.append(f"heartbeat age: {heartbeat_age}s")

        if not installed:
            status = ControlStatus.FAILED
            action = f"Install and enroll {agent.display_name}; verify policy assignment."
        elif not running:
            status = ControlStatus.FAILED
            action = f"Restart {agent.display_name} and investigate service termination."
        elif heartbeat_stale:
            status = ControlStatus.DEGRADED
            action = f"Restore {agent.display_name} telemetry connectivity."
        else:
            status = ControlStatus.HEALTHY
            action = "No action required."

        return ControlFinding(
            agent_id=agent.agent_id,
            display_name=agent.display_name,
            status=status,
            installed=installed,
            running=running,
            heartbeat_age_seconds=heartbeat_age,
            evidence=evidence,
            recommended_action=action,
            checked_at=snapshot.observed_at,
        )
