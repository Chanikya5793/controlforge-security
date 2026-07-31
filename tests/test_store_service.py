from datetime import datetime, timezone

import pytest

from controlforge.detections import DetectionPipeline, SigmaRule
from controlforge.models import SecurityEvent
from controlforge.service import DetectionService
from controlforge.store import AuditStore


def test_service_persists_alert_and_deduplicates(tmp_path) -> None:  # type: ignore[no-untyped-def]
    store = AuditStore(tmp_path / "audit.db")
    rule = SigmaRule(
        id="TEST-001",
        title="Authentication failure",
        detection={"selection": {"event_type": "authentication_failure"}, "condition": "selection"},
    )
    service = DetectionService(DetectionPipeline([rule]), store)
    event = SecurityEvent(
        event_id="auth-1",
        event_type="authentication_failure",
        timestamp=datetime(2026, 8, 11, 14, 0, tzinfo=timezone.utc),
        actor="user@example.com",
    )

    first = service.process([event])
    second = service.process([event])

    assert len(first.alerts) == 1
    assert len(second.alerts) == 1
    assert len(store.recent_alerts()) == 1


@pytest.mark.parametrize("limit", [0, 1001])
def test_recent_alert_limit_is_bounded(tmp_path, limit) -> None:  # type: ignore[no-untyped-def]
    store = AuditStore(tmp_path / "audit.db")
    with pytest.raises(ValueError, match="between 1 and 1000"):
        store.recent_alerts(limit)
