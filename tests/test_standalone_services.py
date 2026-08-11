from __future__ import annotations

import hashlib
import hmac
import json
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from controlforge.detections import DetectionPipeline, canonical_non_sigma_provenance, load_rules
from controlforge.models import DetectionAlert, SecurityEvent
from controlforge.standalone import (
    CollectorAuthenticationError,
    CollectorIngestionService,
    CollectorReplayError,
    DeviceBindingError,
    DeviceHmacAuthenticator,
    EventIdentityConflict,
    SignedCollectorRequest,
    StandaloneDatabase,
    StandaloneDetectionWorker,
    StandaloneSettings,
    StandaloneStore,
)

NOW = datetime(2026, 8, 22, 18, 0, tzinfo=timezone.utc)
TENANT_ID = "00000000-0000-4000-8000-000000000010"
CREDENTIAL_ID = "credential-mac-1"
SECRET = b"standalone-test-collector-secret-material-0001"


class StubSecretResolver:
    def resolve(
        self,
        credential_id: str,
        secret_ciphertext: str,
        secret_iv: str,
    ) -> bytes:
        assert credential_id == CREDENTIAL_ID
        assert secret_ciphertext.startswith("encrypted-")
        assert secret_iv.startswith("test-")
        return SECRET


class FailingDetector:
    def evaluate(self, event: SecurityEvent) -> list[DetectionAlert]:
        raise RuntimeError("temporary detector failure")


class HealthyDetector:
    def evaluate(self, event: SecurityEvent) -> list[DetectionAlert]:
        return []


def service_fixture(
    tmp_path: Path,
) -> tuple[
    StandaloneDatabase,
    StandaloneStore,
    CollectorIngestionService,
    StandaloneSettings,
]:
    settings = StandaloneSettings(
        database_path=tmp_path / "services.db",
        worker_lease_seconds=5,
        worker_max_attempts=3,
    )
    database = StandaloneDatabase(settings)
    database.initialize()
    store = StandaloneStore(database)
    store.create_tenant(TENANT_ID, "test-tenant", "Test tenant", NOW)
    store.register_device(TENANT_ID, "mac-1", "Primary Mac", "macos", NOW)
    store.register_device_credential(
        CREDENTIAL_ID,
        TENANT_ID,
        "mac-1",
        "primary",
        "encrypted-test-secret",
        "test-iv",
        NOW,
        NOW + timedelta(days=30),
    )
    authenticator = DeviceHmacAuthenticator(database, StubSecretResolver())
    return database, store, CollectorIngestionService(authenticator, store), settings


def event_payload(
    event_id: str,
    *,
    device_id: str = "mac-1",
    encoded_powershell: bool = False,
) -> dict[str, object]:
    attributes: dict[str, object] = {"status": "healthy"}
    event_type = "endpoint_control_status"
    if encoded_powershell:
        event_type = "process_start"
        attributes = {
            "process_name": "powershell.exe",
            "command_line": "powershell.exe -enc SQBFAFgA",
        }
    return {
        "event_id": event_id,
        "event_type": event_type,
        "timestamp": NOW.isoformat(),
        "actor": f"device:{device_id}",
        "device_id": device_id,
        "attributes": attributes,
    }


def signed_request(
    body: bytes,
    *,
    nonce: str = "nonce-0000000000000001",
    timestamp: datetime = NOW,
    method: str = "POST",
    path: str = "/v1/ingest/events",
) -> SignedCollectorRequest:
    timestamp_text = timestamp.isoformat().replace("+00:00", "Z")
    unsigned = SignedCollectorRequest(
        method=method,
        path=path,
        body=body,
        credential_id=CREDENTIAL_ID,
        timestamp=timestamp_text,
        nonce=nonce,
        signature="0" * 64,
    )
    signature = hmac.new(
        SECRET,
        DeviceHmacAuthenticator.canonical_request(unsigned),
        hashlib.sha256,
    ).hexdigest()
    return SignedCollectorRequest(
        method=method,
        path=path,
        body=body,
        credential_id=CREDENTIAL_ID,
        timestamp=timestamp_text,
        nonce=nonce,
        signature=signature,
    )


def encoded_body(*events: dict[str, object]) -> bytes:
    return json.dumps({"events": events}, separators=(",", ":"), sort_keys=True).encode()


def test_signed_ingestion_is_device_bound_and_replay_safe(tmp_path: Path) -> None:
    database, _, ingestion, _ = service_fixture(tmp_path)
    request = signed_request(encoded_body(event_payload("event-1")))

    result = ingestion.ingest(request, NOW)

    assert result.tenant_id == TENANT_ID
    assert result.device_id == "mac-1"
    assert result.accepted == 1
    assert result.duplicates == 0
    with pytest.raises(CollectorReplayError):
        ingestion.ingest(request, NOW)
    duplicate = ingestion.ingest(
        signed_request(request.body, nonce="nonce-0000000000000099"),
        NOW,
    )
    assert duplicate.accepted == 0
    assert duplicate.duplicates == 1
    with database.connect() as connection:
        assert connection.execute("SELECT COUNT(*) FROM device_auth_nonces").fetchone()[0] == 2
        assert connection.execute("SELECT COUNT(*) FROM detection_jobs").fetchone()[0] == 1


def test_wrong_device_is_rejected_before_event_persistence(tmp_path: Path) -> None:
    database, _, ingestion, _ = service_fixture(tmp_path)
    request = signed_request(
        encoded_body(event_payload("wrong-device", device_id="mac-2")),
        nonce="nonce-0000000000000002",
    )

    with pytest.raises(DeviceBindingError):
        ingestion.ingest(request, NOW)

    with database.connect() as connection:
        assert connection.execute("SELECT COUNT(*) FROM events").fetchone()[0] == 0
        assert connection.execute("SELECT COUNT(*) FROM detection_jobs").fetchone()[0] == 0


@pytest.mark.parametrize("credential_state", ["expired", "revoked"])
def test_expired_or_revoked_credential_fails_closed(
    tmp_path: Path,
    credential_state: str,
) -> None:
    database, _, ingestion, _ = service_fixture(tmp_path)
    with database.connect() as connection:
        if credential_state == "expired":
            connection.execute(
                "UPDATE device_credentials SET expires_at = ? WHERE credential_id = ?",
                ((NOW - timedelta(seconds=1)).isoformat(), CREDENTIAL_ID),
            )
        else:
            connection.execute(
                "UPDATE device_credentials SET revoked_at = ? WHERE credential_id = ?",
                (NOW.isoformat(), CREDENTIAL_ID),
            )
    request = signed_request(
        encoded_body(event_payload(f"event-{credential_state}")),
        nonce=f"nonce-{credential_state}-00000001",
    )

    with pytest.raises(CollectorAuthenticationError):
        ingestion.ingest(request, NOW)


def test_signature_binds_body_and_fixed_request_semantics(tmp_path: Path) -> None:
    _, _, ingestion, _ = service_fixture(tmp_path)
    original = signed_request(
        encoded_body(event_payload("event-original")),
        nonce="nonce-0000000000000003",
    )
    modified = SignedCollectorRequest(
        method=original.method,
        path=original.path,
        body=encoded_body(event_payload("event-modified")),
        credential_id=original.credential_id,
        timestamp=original.timestamp,
        nonce=original.nonce,
        signature=original.signature,
    )
    wrong_path = signed_request(
        original.body,
        nonce="nonce-0000000000000004",
        path="/v1/agent/actions",
    )

    with pytest.raises(CollectorAuthenticationError):
        ingestion.ingest(modified, NOW)
    with pytest.raises(CollectorAuthenticationError):
        ingestion.ingest(wrong_path, NOW)


def test_ingestion_batch_rolls_back_on_event_identity_conflict(tmp_path: Path) -> None:
    database, store, ingestion, _ = service_fixture(tmp_path)
    original = SecurityEvent.model_validate(event_payload("collision"))
    store.ingest_event(TENANT_ID, original, NOW)
    conflicting = event_payload("collision")
    conflicting["actor"] = "different-actor"
    request = signed_request(
        encoded_body(event_payload("must-roll-back"), conflicting),
        nonce="nonce-0000000000000005",
    )

    with pytest.raises(EventIdentityConflict):
        ingestion.ingest(request, NOW)

    with database.connect() as connection:
        rolled_back = connection.execute(
            "SELECT 1 FROM events WHERE event_id = 'must-roll-back'"
        ).fetchone()
    assert rolled_back is None


def test_worker_restart_reclaims_job_and_persists_alert_case_once(
    tmp_path: Path,
    project_root: Path,
) -> None:
    database, store, ingestion, settings = service_fixture(tmp_path)
    request = signed_request(
        encoded_body(event_payload("powershell-1", encoded_powershell=True)),
        nonce="nonce-0000000000000006",
    )
    ingestion.ingest(request, NOW)
    abandoned = store.lease_jobs(TENANT_ID, "crashed-worker", 1, NOW, 5)
    assert len(abandoned) == 1

    rules = load_rules(project_root / "rules")
    restarted = StandaloneDetectionWorker(
        store,
        DetectionPipeline(rules),
        settings,
        {rule.id: str(rule.rule_version) for rule in rules},
        detector_version="python-canonical-v1",
    )
    result = restarted.run_once(TENANT_ID, "replacement-worker", NOW + timedelta(seconds=5))
    second_run = restarted.run_once(TENANT_ID, "replacement-worker", NOW + timedelta(minutes=1))

    assert result.leased == 1
    assert result.succeeded == 1
    assert result.alerts_inserted == 1
    assert second_run.leased == 0
    with database.connect() as connection:
        assert connection.execute("SELECT COUNT(*) FROM alerts").fetchone()[0] == 1
        assert connection.execute("SELECT COUNT(*) FROM cases").fetchone()[0] == 1
        assert connection.execute("SELECT COUNT(*) FROM case_alerts").fetchone()[0] == 1
        alert = connection.execute(
            "SELECT rule_id, rule_version, detector_version FROM alerts"
        ).fetchone()
    assert tuple(alert) == ("CF-ENDPOINT-001", "1", "python-canonical-v1")


def test_recurring_alerts_aggregate_by_rule_and_device_into_one_active_case(
    tmp_path: Path,
    project_root: Path,
) -> None:
    database, store, _, settings = service_fixture(tmp_path)
    store.register_device(TENANT_ID, "mac-2", "Secondary Mac", "macos", NOW)
    events = [
        SecurityEvent.model_validate(
            event_payload("powershell-aggregate-1", encoded_powershell=True)
        ),
        SecurityEvent.model_validate(
            event_payload("powershell-aggregate-2", encoded_powershell=True)
        ),
        SecurityEvent.model_validate(
            event_payload(
                "powershell-other-device",
                device_id="mac-2",
                encoded_powershell=True,
            )
        ),
    ]
    store.ingest_events(TENANT_ID, events, NOW)
    rules = load_rules(project_root / "rules")
    worker = StandaloneDetectionWorker(
        store,
        DetectionPipeline(rules),
        settings,
        {rule.id: str(rule.rule_version) for rule in rules},
        detector_version="python-canonical-v1",
    )

    result = worker.run_once(TENANT_ID, "semantic-case-worker", NOW, limit=10)

    assert result.succeeded == 3
    assert result.alerts_inserted == 3
    with database.connect() as connection:
        cases = connection.execute(
            """
            SELECT c.case_id, c.semantic_key, COUNT(ca.alert_id) AS alert_count
            FROM cases c
            JOIN case_alerts ca
              ON ca.tenant_id = c.tenant_id AND ca.case_id = c.case_id
            GROUP BY c.tenant_id, c.case_id
            ORDER BY alert_count DESC
            """
        ).fetchall()
    assert len(cases) == 2
    assert [int(case["alert_count"]) for case in cases] == [2, 1]
    assert all(case["semantic_key"] is not None for case in cases)
    assert len({str(case["semantic_key"]) for case in cases}) == 2

    closed_case_id = str(cases[0]["case_id"])
    with database.connect() as connection:
        connection.execute(
            """
            INSERT INTO dispositions(
                tenant_id, disposition_id, case_id, status, rationale, rule_version,
                created_by, created_at, false_positive_reason, investigation_cycle
            ) VALUES (?, 'aggregate-disposition', ?, 'true_positive', ?, '1', ?, ?, NULL, 1)
            """,
            (
                TENANT_ID,
                closed_case_id,
                "Confirmed recurring behavior",
                "analyst-a",
                NOW.isoformat(),
            ),
        )
        connection.execute(
            """
            UPDATE cases
            SET status = 'closed', closed_at = ?, updated_at = ?, version = version + 1
            WHERE tenant_id = ? AND case_id = ?
            """,
            (NOW.isoformat(), NOW.isoformat(), TENANT_ID, closed_case_id),
        )
    successor = SecurityEvent.model_validate(
        event_payload("powershell-after-close", encoded_powershell=True)
    )
    store.ingest_event(TENANT_ID, successor, NOW + timedelta(seconds=1))
    worker.run_once(
        TENANT_ID,
        "semantic-case-worker",
        NOW + timedelta(seconds=1),
        limit=10,
    )
    with database.connect() as connection:
        active_same_semantic = connection.execute(
            """
            SELECT COUNT(*) FROM cases
            WHERE tenant_id = ? AND semantic_key = ? AND status != 'closed'
            """,
            (TENANT_ID, cases[0]["semantic_key"]),
        ).fetchone()[0]
        total_cases = connection.execute("SELECT COUNT(*) FROM cases").fetchone()[0]
    assert active_same_semantic == 1
    assert total_cases == 3


def test_worker_restart_rehydrates_tenant_scoped_stateful_history(
    tmp_path: Path,
    project_root: Path,
) -> None:
    database, store, _, settings = service_fixture(tmp_path)
    events = [
        SecurityEvent(
            event_id=f"bulk-{index}",
            event_type="sensitive_data_access",
            timestamp=NOW + timedelta(seconds=index),
            actor="contractor@example.com",
            attributes={"bytes": 1_000},
        )
        for index in range(10)
    ]
    store.ingest_events(TENANT_ID, events, NOW)
    rules = load_rules(project_root / "rules")
    versions = {rule.id: str(rule.rule_version) for rule in rules}
    provenance = canonical_non_sigma_provenance()
    versions.update({rule_id: values[0] for rule_id, values in provenance.items()})
    digests = {rule_id: values[1] for rule_id, values in provenance.items()}
    snapshots = {rule_id: values[2] for rule_id, values in provenance.items()}
    before_restart = StandaloneDetectionWorker(
        store,
        DetectionPipeline(rules),
        settings,
        versions,
        detector_version="python-canonical-v1",
        rule_digests=digests,
        rule_snapshots=snapshots,
    )
    first = before_restart.run_once(TENANT_ID, "worker-before-state-restart", NOW, limit=9)

    after_restart = StandaloneDetectionWorker(
        store,
        DetectionPipeline(rules),
        settings,
        versions,
        detector_version="python-canonical-v1",
        rule_digests=digests,
        rule_snapshots=snapshots,
    )
    second = after_restart.run_once(TENANT_ID, "worker-after-state-restart", NOW, limit=1)

    assert first.succeeded == 9
    assert first.alerts_inserted == 0
    assert second.succeeded == 1
    assert second.alerts_inserted == 1
    with database.connect() as connection:
        alert = connection.execute(
            """
            SELECT rule_id, rule_version, rule_digest, rule_snapshot_json, reasons_json
            FROM alerts WHERE tenant_id = ?
            """,
            (TENANT_ID,),
        ).fetchone()
    assert alert["rule_id"] == "CF-INSIDER-001"
    assert alert["rule_version"] == "1"
    assert alert["rule_digest"] == provenance["CF-INSIDER-001"][1]
    assert json.loads(alert["rule_snapshot_json"])["event_type"] == "sensitive_data_access"
    assert json.loads(alert["reasons_json"]) == [
        "10 access events within 15m",
        "10000 bytes accessed",
    ]


def test_worker_failure_retries_after_restart(tmp_path: Path) -> None:
    _, store, ingestion, settings = service_fixture(tmp_path)
    request = signed_request(
        encoded_body(event_payload("retry-event")),
        nonce="nonce-0000000000000007",
    )
    ingestion.ingest(request, NOW)
    first_worker = StandaloneDetectionWorker(
        store,
        FailingDetector(),
        settings,
        {},
        detector_version="test-detector-v1",
        retry_delay_seconds=5,
    )

    first = first_worker.run_once(TENANT_ID, "worker-before-restart", NOW)
    restarted_worker = StandaloneDetectionWorker(
        store,
        HealthyDetector(),
        settings,
        {},
        detector_version="test-detector-v1",
        retry_delay_seconds=5,
    )
    too_early = restarted_worker.run_once(
        TENANT_ID,
        "worker-after-restart",
        NOW + timedelta(seconds=4),
    )
    retried = restarted_worker.run_once(
        TENANT_ID,
        "worker-after-restart",
        NOW + timedelta(seconds=5),
    )

    assert first.retried == 1
    assert too_early.leased == 0
    assert retried.succeeded == 1
    assert store.job_counts(TENANT_ID)["succeeded"] == 1
