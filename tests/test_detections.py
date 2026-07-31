from datetime import datetime, timedelta, timezone

import pytest

from controlforge.detections import (
    BulkAccessDetector,
    DetectionPipeline,
    ImpossibleTravelDetector,
    SigmaRule,
    SigmaSubsetEvaluator,
    load_rules,
)
from controlforge.models import SecurityEvent, Severity


def test_encoded_powershell_rule_matches(project_root) -> None:  # type: ignore[no-untyped-def]
    rules = load_rules(project_root / "rules")
    event = SecurityEvent(
        event_id="evt-powershell",
        event_type="process_start",
        timestamp=datetime(2026, 8, 11, 14, 0, tzinfo=timezone.utc),
        actor="user@example.com",
        attributes={
            "process_name": "C:\\Windows\\System32\\powershell.exe",
            "command_line": "powershell.exe -EncodedCommand SQBFAFgA",
        },
    )

    alerts = DetectionPipeline(rules).evaluate(event)
    assert [alert.rule_id for alert in alerts] == ["CF-ENDPOINT-001"]
    assert alerts[0].severity == Severity.HIGH


def test_benign_process_does_not_match(project_root) -> None:  # type: ignore[no-untyped-def]
    rules = load_rules(project_root / "rules")
    event = SecurityEvent(
        event_id="evt-benign",
        event_type="process_start",
        timestamp=datetime(2026, 8, 11, 14, 0, tzinfo=timezone.utc),
        actor="user@example.com",
        attributes={"process_name": "notepad.exe", "command_line": "notepad.exe notes.txt"},
    )
    assert DetectionPipeline(rules).evaluate(event) == []


def test_privilege_grant_excludes_approved_change(project_root) -> None:  # type: ignore[no-untyped-def]
    rules = load_rules(project_root / "rules")
    event = SecurityEvent(
        event_id="evt-approved",
        event_type="privileged_role_grant",
        timestamp=datetime(2026, 8, 11, 14, 0, tzinfo=timezone.utc),
        actor="admin@example.com",
        attributes={"role": "administrator", "change_ticket": "CHG-1234"},
    )
    assert DetectionPipeline(rules).evaluate(event) == []


def test_cidr_modifier_matches_source_ip(base_event) -> None:  # type: ignore[no-untyped-def]
    rule = SigmaRule(
        id="TEST-CIDR",
        title="Test CIDR",
        detection={"selection": {"source_ip|cidr": "203.0.113.0/24"}, "condition": "selection"},
    )
    assert SigmaSubsetEvaluator().evaluate(rule, base_event) is not None


def test_one_of_condition_matches(base_event) -> None:  # type: ignore[no-untyped-def]
    rule = SigmaRule(
        id="TEST-ONE",
        title="Test one of",
        detection={
            "selection_a": {"event_type": "authentication_failure"},
            "selection_b": {"actor": "analyst@example.com"},
            "condition": "1 of selection_*",
        },
    )
    assert SigmaSubsetEvaluator().evaluate(rule, base_event) is not None


def test_unsupported_modifier_is_rejected(base_event) -> None:  # type: ignore[no-untyped-def]
    rule = SigmaRule(
        id="TEST-BAD",
        title="Bad modifier",
        detection={"selection": {"actor|unknown": "x"}, "condition": "selection"},
    )
    with pytest.raises(ValueError, match="unsupported Sigma modifier"):
        SigmaSubsetEvaluator().evaluate(rule, base_event)


def test_bulk_access_detector_alerts_on_threshold() -> None:
    detector = BulkAccessDetector(event_threshold=3, byte_threshold=1_000_000)
    start = datetime(2026, 8, 11, 14, 0, tzinfo=timezone.utc)
    alerts = []
    for index in range(3):
        event = SecurityEvent(
            event_id=f"bulk-{index}",
            event_type="sensitive_data_access",
            timestamp=start + timedelta(minutes=index),
            actor="contractor@example.com",
            attributes={"bytes": 1000},
        )
        alerts.append(detector.evaluate(event))
    assert alerts[:2] == [None, None]
    assert alerts[2] is not None
    assert alerts[2].rule_id == "CF-INSIDER-001"


def test_bulk_access_detector_ignores_bad_byte_value(base_event) -> None:  # type: ignore[no-untyped-def]
    event = base_event.model_copy(
        update={"event_type": "sensitive_data_access", "attributes": {"bytes": "unknown"}}
    )
    assert BulkAccessDetector().evaluate(event) is None


def test_impossible_travel_detector_alerts() -> None:
    detector = ImpossibleTravelDetector(maximum_speed_kph=900)
    first = SecurityEvent(
        event_id="login-sfo",
        event_type="authentication_success",
        timestamp=datetime(2026, 8, 11, 14, 0, tzinfo=timezone.utc),
        actor="user@example.com",
        attributes={"latitude": 37.7749, "longitude": -122.4194},
    )
    second = first.model_copy(
        update={
            "event_id": "login-nyc",
            "timestamp": first.timestamp + timedelta(minutes=30),
            "attributes": {"latitude": 40.7128, "longitude": -74.0060},
        }
    )
    assert detector.evaluate(first) is None
    alert = detector.evaluate(second)
    assert alert is not None
    assert alert.rule_id == "CF-IDENTITY-001"


def test_impossible_travel_ignores_missing_coordinates(base_event) -> None:  # type: ignore[no-untyped-def]
    event = base_event.model_copy(update={"event_type": "authentication_success"})
    assert ImpossibleTravelDetector().evaluate(event) is None
