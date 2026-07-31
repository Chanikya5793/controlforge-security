"""Application service coordinating detection and durable audit storage."""

from collections.abc import Iterable

from .detections import DetectionPipeline
from .models import DetectionAlert, ScanResult, SecurityEvent
from .store import AuditStore


class DetectionService:
    def __init__(self, pipeline: DetectionPipeline, store: AuditStore) -> None:
        self._pipeline = pipeline
        self._store = store

    def process(self, events: Iterable[SecurityEvent]) -> ScanResult:
        alerts: list[DetectionAlert] = []
        processed = 0
        for event in events:
            processed += 1
            self._store.save_event(event)
            event_alerts = self._pipeline.evaluate(event)
            self._store.save_alerts(event_alerts)
            alerts.extend(event_alerts)
        return ScanResult(events_processed=processed, alerts=alerts)
