"""Validated settings for the standalone single-node runtime."""

from __future__ import annotations

import os
from collections.abc import Mapping
from pathlib import Path
from typing import Optional

from pydantic import BaseModel, ConfigDict, Field


class StandaloneSettings(BaseModel):
    """Runtime limits with conservative defaults for one local appliance."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    database_path: Path = Path("controlforge-standalone.db")
    busy_timeout_ms: int = Field(default=5_000, ge=100, le=60_000)
    worker_lease_seconds: int = Field(default=60, ge=5, le=3_600)
    worker_max_attempts: int = Field(default=5, ge=1, le=100)

    @classmethod
    def from_environment(
        cls,
        environ: Optional[Mapping[str, str]] = None,
    ) -> StandaloneSettings:
        """Load the small standalone settings surface from environment variables."""

        values = os.environ if environ is None else environ
        payload: dict[str, object] = {}
        if "CONTROLFORGE_STANDALONE_DATABASE" in values:
            payload["database_path"] = values["CONTROLFORGE_STANDALONE_DATABASE"]
        if "CONTROLFORGE_SQLITE_BUSY_TIMEOUT_MS" in values:
            payload["busy_timeout_ms"] = values["CONTROLFORGE_SQLITE_BUSY_TIMEOUT_MS"]
        if "CONTROLFORGE_WORKER_LEASE_SECONDS" in values:
            payload["worker_lease_seconds"] = values["CONTROLFORGE_WORKER_LEASE_SECONDS"]
        if "CONTROLFORGE_WORKER_MAX_ATTEMPTS" in values:
            payload["worker_max_attempts"] = values["CONTROLFORGE_WORKER_MAX_ATTEMPTS"]
        return cls.model_validate(payload)
