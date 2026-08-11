from __future__ import annotations

from datetime import datetime, timedelta, timezone
from pathlib import Path

from controlforge.detections import evaluate_stateful_event
from controlforge.models import SecurityEvent
from controlforge.standalone import (
    StandaloneDatabase,
    StandaloneSettings,
    StandaloneStore,
)

NOW = datetime(2026, 8, 22, 20, 0, tzinfo=timezone.utc)
TENANT_ONE = "00000000-0000-4000-8000-000000000101"
TENANT_TWO = "00000000-0000-4000-8000-000000000102"


def bulk_event(event_id: str, offset_seconds: int, value: object = 1_000) -> SecurityEvent:
    return SecurityEvent(
        event_id=event_id,
        event_type="sensitive_data_access",
        timestamp=NOW + timedelta(seconds=offset_seconds),
        actor="contractor@example.com",
        attributes={"bytes": value},
    )


def test_stateful_contract_deduplicates_retries_and_excludes_future_events() -> None:
    current = bulk_event("bulk-current", 9)
    prior = [bulk_event(f"bulk-{index}", index) for index in range(7)]
    prior.extend(
        [
            bulk_event("bulk-duplicate", 8),
            bulk_event("bulk-duplicate", 8),
            bulk_event("bulk-future", 60),
            current,
        ]
    )

    assert evaluate_stateful_event(current, prior) == []

    alert = evaluate_stateful_event(current, [*prior, bulk_event("bulk-ninth", 8)])
    assert [item.rule_id for item in alert] == ["CF-INSIDER-001"]
    assert alert[0].reasons == ["10 access events within 15m", "10000 bytes accessed"]


def test_stateful_contract_rejects_boolean_byte_telemetry() -> None:
    malformed = bulk_event("bulk-boolean", 9, True)
    prior = [bulk_event(f"bulk-{index}", index, 10_000_000) for index in range(9)]

    assert evaluate_stateful_event(malformed, prior) == []


def test_stateful_contract_covers_all_correlation_decisions_exactly() -> None:
    login_one = SecurityEvent(
        event_id="login-sfo",
        event_type="authentication_success",
        timestamp=NOW,
        actor="user@example.com",
        attributes={"latitude": 37.7749, "longitude": -122.4194},
    )
    login_two = login_one.model_copy(
        update={
            "event_id": "login-nyc",
            "timestamp": NOW + timedelta(minutes=30),
            "attributes": {"latitude": 40.7128, "longitude": -74.0060},
        }
    )
    travel = evaluate_stateful_event(login_two, [login_one])
    assert travel[0].rule_id == "CF-IDENTITY-001"
    assert travel[0].reasons == [
        "calculated travel velocity 8258 km/h",
        "distance 4129 km over 0.50h",
    ]

    failures = [
        SecurityEvent(
            event_id=f"failure-{index}",
            event_type="edge_auth_failure",
            timestamp=NOW + timedelta(seconds=index),
            actor=f"account-{index % 10}@example.com",
            source_ip="198.51.100.44",
        )
        for index in range(20)
    ]
    stuffing = evaluate_stateful_event(failures[-1], failures[:-1])
    assert stuffing[0].rule_id == "CF-EDGE-002"
    assert stuffing[0].reasons == [
        "20 failed authentications from 198.51.100.44",
        "10 distinct accounts within 5m",
    ]

    first_session = SecurityEvent(
        event_id="session-first",
        event_type="edge_session_use",
        timestamp=NOW,
        actor="user@example.com",
        source_ip="198.51.100.10",
        attributes={"session_id_hash": "a" * 64},
    )
    second_session = first_session.model_copy(
        update={
            "event_id": "session-second",
            "timestamp": NOW + timedelta(minutes=2),
            "source_ip": "203.0.113.20",
        }
    )
    replay = evaluate_stateful_event(second_session, [first_session])
    assert replay[0].rule_id == "CF-EDGE-003"
    assert replay[0].reasons == [
        "session hash reused from 198.51.100.10 and 203.0.113.20",
        "reuse occurred within 10m",
    ]


def test_standalone_history_is_retry_safe_ordered_and_tenant_scoped(tmp_path: Path) -> None:
    database = StandaloneDatabase(StandaloneSettings(database_path=tmp_path / "history.db"))
    database.initialize()
    store = StandaloneStore(database)
    store.create_tenant(TENANT_ONE, "tenant-one", "Tenant one", NOW)
    store.create_tenant(TENANT_TWO, "tenant-two", "Tenant two", NOW)

    current = bulk_event("bulk-current", 9)
    first_tenant = [bulk_event(f"one-{index}", index) for index in range(9)]
    second_tenant = [bulk_event(f"two-{index}", index) for index in range(20)]
    future = bulk_event("one-future", 60)
    store.ingest_events(TENANT_ONE, [*first_tenant, current, future], NOW)
    store.ingest_events(TENANT_TWO, second_tenant, NOW)
    retry = store.ingest_event(TENANT_ONE, first_tenant[0], NOW + timedelta(seconds=1))

    history = store.load_detection_history(TENANT_ONE, current)

    assert retry.accepted is False
    assert [event.event_id for event in history] == [event.event_id for event in first_tenant]
    assert all(not event.event_id.startswith("two-") for event in history)
    assert evaluate_stateful_event(current, history)[0].reasons[0] == "10 access events within 15m"
