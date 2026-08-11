"""Restart-safe worker around the canonical Python detection pipeline."""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from datetime import datetime
from typing import Optional, Protocol, runtime_checkable

from controlforge.models import DetectionAlert, SecurityEvent

from .settings import StandaloneSettings
from .store import StandaloneStore


class EventDetector(Protocol):
    def evaluate(self, event: SecurityEvent) -> list[DetectionAlert]:
        """Evaluate one normalized event deterministically."""


@runtime_checkable
class HistoricalEventDetector(Protocol):
    def evaluate_with_history(
        self,
        event: SecurityEvent,
        prior_events: Iterable[SecurityEvent],
    ) -> list[DetectionAlert]:
        """Evaluate using durable prior history supplied by the tenant store."""


@dataclass(frozen=True)
class WorkerRunResult:
    leased: int
    succeeded: int
    retried: int
    dead: int
    alerts_inserted: int


class StandaloneDetectionWorker:
    """Lease durable jobs and commit detector decisions idempotently."""

    def __init__(
        self,
        store: StandaloneStore,
        detector: EventDetector,
        settings: StandaloneSettings,
        rule_versions: Mapping[str, str],
        detector_version: str,
        retry_delay_seconds: int = 5,
        rule_digests: Optional[Mapping[str, str]] = None,
        rule_snapshots: Optional[Mapping[str, str]] = None,
    ) -> None:
        if not detector_version or len(detector_version) > 128:
            raise ValueError("detector_version must contain between 1 and 128 characters")
        if retry_delay_seconds < 0 or retry_delay_seconds > 3_600:
            raise ValueError("retry_delay_seconds must be between 0 and 3600")
        self._store = store
        self._detector = detector
        self._settings = settings
        self._rule_versions = dict(rule_versions)
        self._detector_version = detector_version
        self._retry_delay_seconds = retry_delay_seconds
        self._rule_digests = dict(rule_digests or {})
        self._rule_snapshots = dict(rule_snapshots or {})

    def run_once(
        self,
        tenant_id: str,
        worker_id: str,
        now: datetime,
        limit: int = 25,
    ) -> WorkerRunResult:
        leases = self._store.lease_jobs(
            tenant_id,
            worker_id,
            limit,
            now,
            self._settings.worker_lease_seconds,
        )
        succeeded = 0
        retried = 0
        dead = 0
        alerts_inserted = 0
        for lease in leases:
            try:
                event = self._store.load_event(tenant_id, lease.event_id)
                if event is None:
                    raise RuntimeError("leased detection event is missing")
                if isinstance(self._detector, HistoricalEventDetector):
                    history = self._store.load_detection_history(tenant_id, event)
                    alerts = self._detector.evaluate_with_history(event, history)
                else:
                    alerts = self._detector.evaluate(event)
                persisted = self._store.persist_alerts_and_complete_job(
                    tenant_id,
                    lease.job_id,
                    worker_id,
                    alerts,
                    now,
                    self._rule_versions,
                    self._detector_version,
                    self._rule_digests,
                    self._rule_snapshots,
                )
                succeeded += 1
                alerts_inserted += persisted.inserted_alerts
            except Exception as exc:
                delay = self._retry_delay_seconds * (2 ** min(lease.attempts - 1, 10))
                transition = self._store.fail_job(
                    tenant_id,
                    lease.job_id,
                    worker_id,
                    now,
                    str(exc),
                    self._settings.worker_max_attempts,
                    min(delay, 86_400),
                )
                if transition.changed and transition.status == "retry":
                    retried += 1
                elif transition.changed and transition.status == "dead":
                    dead += 1
        return WorkerRunResult(
            leased=len(leases),
            succeeded=succeeded,
            retried=retried,
            dead=dead,
            alerts_inserted=alerts_inserted,
        )
