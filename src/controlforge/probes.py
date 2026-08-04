"""Endpoint state probes used by control-health checks."""

from __future__ import annotations

import os
import platform
import shutil
import socket
import subprocess  # nosec B404: fixed command without shell execution
from collections.abc import Sequence
from pathlib import Path
from typing import Protocol

from .models import EndpointSnapshot


class SystemProbe(Protocol):
    def snapshot(self, observed_paths: Sequence[str]) -> EndpointSnapshot:
        """Collect the state required by control checks."""


class LocalSystemProbe:
    """Read-only local process and filesystem probe."""

    def snapshot(self, observed_paths: Sequence[str]) -> EndpointSnapshot:
        ps_path = shutil.which("ps")
        if ps_path is None:
            raise RuntimeError("ps executable is unavailable")
        completed = subprocess.run(  # noqa: S603  # nosec B603
            [ps_path, "-axo", "comm="],
            check=True,
            capture_output=True,
            text=True,
            timeout=10,
        )
        processes = {
            Path(line.strip()).name.casefold()
            for line in completed.stdout.splitlines()
            if line.strip()
        }
        existing_paths: set[str] = set()
        modified: dict[str, float] = {}
        for raw_path in observed_paths:
            path = Path(os.path.expandvars(os.path.expanduser(raw_path)))
            if path.exists():
                normalized = str(path)
                existing_paths.add(normalized)
                modified[normalized] = path.stat().st_mtime

        return EndpointSnapshot(
            hostname=socket.gethostname().strip(),
            platform=platform.system().lower(),
            running_processes=processes,
            existing_paths=existing_paths,
            file_modified_epoch=modified,
        )


class FixtureSystemProbe:
    """Deterministic probe for demos, tests, and offline evaluation."""

    def __init__(self, fixture: EndpointSnapshot) -> None:
        self._fixture = fixture

    def snapshot(self, observed_paths: Sequence[str]) -> EndpointSnapshot:
        del observed_paths
        return self._fixture.model_copy(deep=True)
