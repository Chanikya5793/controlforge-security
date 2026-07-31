"""Typed domain models shared by the CLI, API, and detection engine."""

from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum
from typing import Optional

from pydantic import BaseModel, Field


def utc_now() -> datetime:
    """Return a timezone-aware UTC timestamp."""

    return datetime.now(timezone.utc)


class Severity(str, Enum):
    INFO = "informational"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class ControlStatus(str, Enum):
    HEALTHY = "healthy"
    DEGRADED = "degraded"
    FAILED = "failed"


class AgentDefinition(BaseModel):
    """Configuration for one endpoint protection agent."""

    agent_id: str = Field(min_length=1, pattern=r"^[a-z0-9_-]+$")
    display_name: str = Field(min_length=1)
    process_names: list[str] = Field(min_length=1)
    install_paths: list[str] = Field(default_factory=list)
    heartbeat_path: Optional[str] = None
    heartbeat_max_age_seconds: int = Field(default=900, ge=30, le=86400)


class EndpointSnapshot(BaseModel):
    """Observed endpoint state; injectable so checks remain deterministic."""

    hostname: str
    platform: str
    observed_at: datetime = Field(default_factory=utc_now)
    running_processes: set[str] = Field(default_factory=set)
    existing_paths: set[str] = Field(default_factory=set)
    file_modified_epoch: dict[str, float] = Field(default_factory=dict)


class ControlFinding(BaseModel):
    agent_id: str
    display_name: str
    status: ControlStatus
    installed: bool
    running: bool
    heartbeat_age_seconds: Optional[int] = None
    evidence: list[str] = Field(default_factory=list)
    recommended_action: str
    checked_at: datetime = Field(default_factory=utc_now)


class ControlReport(BaseModel):
    hostname: str
    platform: str
    findings: list[ControlFinding]
    generated_at: datetime = Field(default_factory=utc_now)

    @property
    def failed_count(self) -> int:
        return sum(finding.status == ControlStatus.FAILED for finding in self.findings)

    @property
    def degraded_count(self) -> int:
        return sum(finding.status == ControlStatus.DEGRADED for finding in self.findings)


class SecurityEvent(BaseModel):
    event_id: str = Field(min_length=1)
    event_type: str = Field(min_length=1)
    timestamp: datetime
    actor: str = Field(min_length=1)
    source_ip: Optional[str] = None
    target: Optional[str] = None
    attributes: dict[str, object] = Field(default_factory=dict)


class DetectionAlert(BaseModel):
    alert_id: str
    rule_id: str
    title: str
    severity: Severity
    event_id: str
    actor: str
    reasons: list[str]
    tags: list[str] = Field(default_factory=list)
    created_at: datetime = Field(default_factory=utc_now)


class ScanResult(BaseModel):
    events_processed: int
    alerts: list[DetectionAlert]
    generated_at: datetime = Field(default_factory=utc_now)
