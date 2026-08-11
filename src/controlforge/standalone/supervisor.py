"""Background orchestration for durable standalone detection jobs."""

from __future__ import annotations

import asyncio
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Optional

from .store import StandaloneStore
from .worker import StandaloneDetectionWorker, WorkerRunResult


@dataclass(frozen=True)
class SupervisorStatus:
    running: bool
    last_cycle_at: Optional[datetime]
    last_error: Optional[str]


class StandaloneWorkerSupervisor:
    """Continuously drain persisted jobs without making ingestion depend on worker uptime."""

    def __init__(
        self,
        store: StandaloneStore,
        worker: StandaloneDetectionWorker,
        *,
        interval_seconds: float = 2.0,
    ) -> None:
        if interval_seconds < 0.1 or interval_seconds > 60:
            raise ValueError("worker interval must be between 0.1 and 60 seconds")
        self._store = store
        self._worker = worker
        self._interval_seconds = interval_seconds
        self._worker_id = f"standalone-{uuid.uuid4()}"
        self._stop: Optional[asyncio.Event] = None
        self._running = False
        self._last_cycle_at: Optional[datetime] = None
        self._last_error: Optional[str] = None

    @property
    def status(self) -> SupervisorStatus:
        return SupervisorStatus(self._running, self._last_cycle_at, self._last_error)

    def run_cycle(self, now: Optional[datetime] = None) -> list[WorkerRunResult]:
        cycle_time = datetime.now(timezone.utc) if now is None else now
        results = [
            self._worker.run_once(tenant_id, self._worker_id, cycle_time)
            for tenant_id in self._store.active_tenant_ids()
        ]
        self._last_cycle_at = cycle_time
        self._last_error = None
        return results

    async def run(self) -> None:
        self._running = True
        self._stop = asyncio.Event()
        try:
            while self._stop is not None and not self._stop.is_set():
                try:
                    await asyncio.to_thread(self.run_cycle)
                except Exception as exc:
                    self._last_error = str(exc)[:500]
                try:
                    await asyncio.wait_for(self._stop.wait(), timeout=self._interval_seconds)
                except asyncio.TimeoutError:
                    continue
        finally:
            self._running = False
            self._stop = None

    def stop(self) -> None:
        if self._stop is not None:
            self._stop.set()


__all__ = ["StandaloneWorkerSupervisor", "SupervisorStatus"]
