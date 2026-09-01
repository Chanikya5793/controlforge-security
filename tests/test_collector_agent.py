import hashlib
import hmac
import json
import stat
import subprocess
from datetime import datetime, timedelta, timezone

import pytest

from controlforge.collector_agent import (
    AgentContainmentStatusSummary,
    AgentControlStatusSummary,
    AgentDeliveryStatusSummary,
    AgentSpool,
    AgentStatusSnapshot,
    AgentStatusSnapshotStore,
    AgentTelemetryStatusSummary,
    CollectorDefinition,
    CollectorError,
    EndpointCollectorAgent,
    MacOSSystemKeychain,
    SignedControlForgeClient,
)
from controlforge.credential_rotation import (
    CredentialRotationMaterial,
    encrypt_rotation_material,
)
from controlforge.models import ControlFinding, ControlReport, ControlStatus, SecurityEvent
from controlforge.santa import SantaJsonLogReader, SantaLogDefinition


class FixtureTransport:
    def __init__(self, secret: str, responses: dict[tuple[str, str], tuple[int, bytes]]) -> None:
        self.secret = secret
        self.responses = responses
        self.requests: list[tuple[str, str, dict[str, str], bytes]] = []

    def request(self, method, path, headers, body, timeout_seconds):  # type: ignore[no-untyped-def]
        assert timeout_seconds == 15.0
        timestamp = headers["x-controlforge-timestamp"]
        nonce = headers["x-controlforge-nonce"]
        body_hash = hashlib.sha256(body).hexdigest()
        canonical_path = path.partition("?")[0]
        canonical = "\n".join([method, canonical_path, timestamp, nonce, body_hash]).encode()
        expected = hmac.new(self.secret.encode(), canonical, hashlib.sha256).hexdigest()
        assert hmac.compare_digest(headers["x-controlforge-signature"], expected)
        self.requests.append((method, path, dict(headers), body))
        return self.responses[(method, path)]


class RotationTransport:
    def __init__(
        self,
        credentials: dict[str, str],
        rotation_payload: bytes,
    ) -> None:
        self.credentials = credentials
        self.rotation_payload = rotation_payload
        self.requests: list[tuple[str, str, str]] = []

    def request(self, method, path, headers, body, timeout_seconds):  # type: ignore[no-untyped-def]
        credential_id = headers["x-controlforge-credential-id"]
        secret = self.credentials[credential_id]
        canonical = "\n".join(
            [
                method,
                path.partition("?")[0],
                headers["x-controlforge-timestamp"],
                headers["x-controlforge-nonce"],
                hashlib.sha256(body).hexdigest(),
            ]
        ).encode()
        assert hmac.compare_digest(
            headers["x-controlforge-signature"],
            hmac.new(secret.encode(), canonical, hashlib.sha256).hexdigest(),
        )
        self.requests.append((method, path, credential_id))
        if method == "GET":
            return 200, self.rotation_payload
        return 200, b'{"rotation_id":"rotation","status":"acknowledged","changed":true}'


class RecordingCredentialPairStore:
    def __init__(self, *, fail: bool = False) -> None:
        self.fail = fail
        self.replacements: list[tuple[str, str, str]] = []

    def replace_pair(
        self,
        expected_credential_id: str,
        credential_id: str,
        credential_secret: str,
    ) -> None:
        if self.fail:
            raise ValueError("keychain replacement failed")
        self.replacements.append((expected_credential_id, credential_id, credential_secret))


class FixedClock:
    def __init__(self, now: datetime) -> None:
        self.now = now

    def __call__(self) -> datetime:
        return self.now

    def advance(self, seconds: int) -> None:
        self.now += timedelta(seconds=seconds)


def definition(project_root, tmp_path) -> CollectorDefinition:  # type: ignore[no-untyped-def]
    return CollectorDefinition(
        api_host="controlforge-soc.example.workers.dev",
        device_id="device-test-1",
        controls_path=project_root / "config" / "agents.yml",
        spool_path=tmp_path / "spool.db",
        status_snapshot_path=tmp_path / "status" / "agent-status.json",
    )


def event() -> SecurityEvent:
    return SecurityEvent(
        event_id="event-1",
        event_type="endpoint_control_status",
        timestamp=datetime(2026, 8, 18, 6, 0, tzinfo=timezone.utc),
        actor="device:device-test-1",
        attributes={"status": "healthy"},
    )


def report(status: ControlStatus = ControlStatus.HEALTHY) -> ControlReport:
    return ControlReport(
        hostname="synthetic",
        platform="darwin",
        findings=[
            ControlFinding(
                agent_id="santa",
                display_name="Santa",
                status=status,
                installed=True,
                running=status != ControlStatus.FAILED,
                evidence=["synthetic"],
                recommended_action="Inspect the synthetic fixture.",
            )
        ],
    )


def test_signed_client_authenticates_body_and_query_path(project_root, tmp_path) -> None:  # type: ignore[no-untyped-def]
    secret = "s" * 48
    transport = FixtureTransport(
        secret,
        {
            ("POST", "/v1/ingest/events"): (202, b'{"accepted":1}'),
            ("GET", "/v1/agent/actions?device_id=device-test-1"): (200, b'{"actions":[]}'),
        },
    )
    client = SignedControlForgeClient(
        definition(project_root, tmp_path),
        "3970e11f-f87c-4e14-9a90-d574cd2bcd95",
        secret,
        transport=transport,
    )

    client.ingest([event()])
    assert client.pending_actions() == []
    assert [request[:2] for request in transport.requests] == [
        ("POST", "/v1/ingest/events"),
        ("GET", "/v1/agent/actions?device_id=device-test-1"),
    ]
    assert secret.encode() not in transport.requests[0][3]


def test_endpoint_rotation_swaps_then_acknowledges_without_persisting_secret(
    project_root,
    tmp_path,
) -> None:  # type: ignore[no-untyped-def]
    predecessor_id = "3970e11f-f87c-4e14-9a90-d574cd2bcd95"
    replacement_id = "4970e11f-f87c-4e14-9a90-d574cd2bcd96"
    predecessor_secret = "p" * 48
    replacement_secret = "r" * 48
    now = datetime.now(timezone.utc)
    material = CredentialRotationMaterial(
        rotation_id="5970e11f-f87c-4e14-9a90-d574cd2bcd97",
        device_id="device-test-1",
        predecessor_credential_id=predecessor_id,
        replacement_credential_id=replacement_id,
        replacement_secret=replacement_secret,
        replacement_expires_at=now + timedelta(days=30),
    )
    envelope = encrypt_rotation_material(
        material,
        predecessor_secret.encode(),
        now + timedelta(hours=1),
    )
    transport = RotationTransport(
        {predecessor_id: predecessor_secret, replacement_id: replacement_secret},
        json.dumps({"rotation": envelope.model_dump(mode="json")}).encode(),
    )
    collector_definition = definition(project_root, tmp_path).model_copy(
        update={"credential_rotation_enabled": True}
    )
    client = SignedControlForgeClient(
        collector_definition,
        predecessor_id,
        predecessor_secret,
        transport=transport,
    )
    spool = AgentSpool(tmp_path / "rotation-spool.db")
    pair_store = RecordingCredentialPairStore()
    agent = EndpointCollectorAgent(
        collector_definition,
        client,
        spool,
        credential_pair_store=pair_store,
    )

    assert agent._handle_credential_rotation() is True
    assert pair_store.replacements == [(predecessor_id, replacement_id, replacement_secret)]
    assert spool.pending_credential_rotation() is None
    assert transport.requests == [
        (
            "GET",
            "/v1/agent/credential-rotation?device_id=device-test-1",
            predecessor_id,
        ),
        ("POST", "/v1/agent/credential-rotation/ack", replacement_id),
    ]
    assert replacement_secret.encode() not in (tmp_path / "rotation-spool.db").read_bytes()


def test_endpoint_rotation_recovers_ack_after_process_restart(project_root, tmp_path) -> None:  # type: ignore[no-untyped-def]
    predecessor_id = "3970e11f-f87c-4e14-9a90-d574cd2bcd95"
    replacement_id = "4970e11f-f87c-4e14-9a90-d574cd2bcd96"
    replacement_secret = "r" * 48
    now = datetime.now(timezone.utc)
    material = CredentialRotationMaterial(
        rotation_id="5970e11f-f87c-4e14-9a90-d574cd2bcd97",
        device_id="device-test-1",
        predecessor_credential_id=predecessor_id,
        replacement_credential_id=replacement_id,
        replacement_secret=replacement_secret,
        replacement_expires_at=now + timedelta(days=30),
    )
    transport = RotationTransport(
        {replacement_id: replacement_secret},
        b'{"rotation":null}',
    )
    collector_definition = definition(project_root, tmp_path).model_copy(
        update={"credential_rotation_enabled": True}
    )
    spool = AgentSpool(tmp_path / "restart-spool.db")
    spool.record_credential_rotation(material)
    agent = EndpointCollectorAgent(
        collector_definition,
        SignedControlForgeClient(
            collector_definition,
            replacement_id,
            replacement_secret,
            transport=transport,
        ),
        spool,
        credential_pair_store=RecordingCredentialPairStore(),
    )

    assert agent._handle_credential_rotation() is True
    assert spool.pending_credential_rotation() is None
    assert transport.requests == [("POST", "/v1/agent/credential-rotation/ack", replacement_id)]


def test_signed_client_adds_validated_access_service_headers(project_root, tmp_path) -> None:  # type: ignore[no-untyped-def]
    secret = "s" * 48
    access_id = f"{'a' * 32}.access"
    access_secret = "b" * 64
    transport = FixtureTransport(
        secret,
        {("POST", "/v1/ingest/events"): (202, b'{"accepted":1}')},
    )
    client = SignedControlForgeClient(
        definition(project_root, tmp_path),
        "3970e11f-f87c-4e14-9a90-d574cd2bcd95",
        secret,
        access_client_id=access_id,
        access_client_secret=access_secret,
        transport=transport,
    )

    client.ingest([event()])

    request_headers = transport.requests[0][2]
    assert request_headers["cf-access-client-id"] == access_id
    assert request_headers["cf-access-client-secret"] == access_secret
    with pytest.raises(ValueError, match="provided together"):
        SignedControlForgeClient(
            definition(project_root, tmp_path),
            "3970e11f-f87c-4e14-9a90-d574cd2bcd95",
            secret,
            access_client_id=access_id,
        )


def test_signed_client_hides_provider_body_on_failure(project_root, tmp_path) -> None:  # type: ignore[no-untyped-def]
    secret = "s" * 48
    transport = FixtureTransport(
        secret,
        {("POST", "/v1/ingest/events"): (401, b"sensitive provider response")},
    )
    client = SignedControlForgeClient(
        definition(project_root, tmp_path),
        "3970e11f-f87c-4e14-9a90-d574cd2bcd95",
        secret,
        transport=transport,
    )
    with pytest.raises(CollectorError, match="HTTP 401") as error:
        client.ingest([event()])
    assert "sensitive provider response" not in str(error.value)


def test_spool_retries_without_persisting_credentials(tmp_path) -> None:  # type: ignore[no-untyped-def]
    spool_path = tmp_path / "spool.db"
    spool = AgentSpool(spool_path)
    batch_id = spool.enqueue([event()])
    spool.fail(batch_id, "temporary network error")

    pending = spool.pending()
    assert pending[0][0] == batch_id
    assert pending[0][1][0].event_id == "event-1"
    assert b"collector-secret" not in spool_path.read_bytes()

    spool.acknowledge(batch_id)
    assert spool.pending() == []


def test_retry_circuit_is_persistent_exponential_jittered_and_bounded(tmp_path) -> None:  # type: ignore[no-untyped-def]
    spool_path = tmp_path / "spool.db"
    spool = AgentSpool(spool_path)
    now = datetime(2026, 8, 31, 12, 0, tzinfo=timezone.utc)

    first = spool.record_retry_failure(
        "delivery",
        now=now,
        initial_seconds=60,
        maximum_seconds=3600,
        jitter_ratio=0.2,
        jitter_key="device-test-1",
    )
    assert first.consecutive_failures == 1
    assert now + timedelta(seconds=48) <= first.retry_after <= now + timedelta(seconds=72)
    assert AgentSpool(spool_path).retry_state("delivery") == first
    assert spool.retry_ready("delivery", first.retry_after - timedelta(seconds=1)) is False
    assert spool.retry_ready("delivery", first.retry_after) is True

    current = first
    for _ in range(20):
        failure_time = current.retry_after
        current = spool.record_retry_failure(
            "delivery",
            now=failure_time,
            initial_seconds=60,
            maximum_seconds=3600,
            jitter_ratio=0.2,
            jitter_key="device-test-1",
        )
        assert timedelta(seconds=1) <= current.retry_after - failure_time
        assert current.retry_after - failure_time <= timedelta(seconds=3600)
    assert current.consecutive_failures == 21

    spool.clear_retry_state("delivery")
    assert AgentSpool(spool_path).retry_state("delivery") is None


def test_outage_circuits_isolate_delivery_and_action_polling_across_restarts(
    project_root, tmp_path, monkeypatch
) -> None:  # type: ignore[no-untyped-def]
    secret = "s" * 48
    now = datetime(2026, 8, 31, 12, 0, tzinfo=timezone.utc)
    clock = FixedClock(now)
    collector_definition = definition(project_root, tmp_path).model_copy(
        update={
            "retry_backoff_initial_seconds": 60,
            "retry_backoff_max_seconds": 3600,
            "retry_backoff_jitter_ratio": 0.0,
        }
    )
    spool = AgentSpool(collector_definition.spool_path)
    failing_transport = FixtureTransport(
        secret,
        {
            ("POST", "/v1/ingest/events"): (500, b'{"detail":"database full"}'),
            ("GET", "/v1/agent/actions?device_id=device-test-1"): (
                500,
                b'{"detail":"database full"}',
            ),
        },
    )
    first_agent = EndpointCollectorAgent(
        collector_definition,
        SignedControlForgeClient(
            collector_definition,
            "3970e11f-f87c-4e14-9a90-d574cd2bcd95",
            secret,
            transport=failing_transport,
        ),
        spool,
        clock=clock,
    )
    monkeypatch.setattr(first_agent, "_control_report", report)

    first = first_agent.run_once()

    assert first["batches_pending"] == 1
    assert [request[:2] for request in failing_transport.requests] == [
        ("POST", "/v1/ingest/events"),
        ("GET", "/v1/agent/actions?device_id=device-test-1"),
    ]
    assert spool.retry_state("delivery").retry_after == now + timedelta(seconds=60)  # type: ignore[union-attr]
    assert spool.retry_state("action_polling").retry_after == now + timedelta(seconds=60)  # type: ignore[union-attr]

    clock.advance(30)
    deferred_transport = FixtureTransport(secret, {})
    second_agent = EndpointCollectorAgent(
        collector_definition,
        SignedControlForgeClient(
            collector_definition,
            "3970e11f-f87c-4e14-9a90-d574cd2bcd95",
            secret,
            transport=deferred_transport,
        ),
        AgentSpool(collector_definition.spool_path),
        clock=clock,
    )
    monkeypatch.setattr(second_agent, "_control_report", report)
    second = second_agent.run_once()

    assert deferred_transport.requests == []
    assert second["events_collected"] == 0
    assert second["batches_pending"] == 1
    stored = json.loads(collector_definition.status_snapshot_path.read_text())
    assert stored["run_status"] == "failed"
    assert stored["failure_stage"] == "action_polling"
    assert stored["delivery"]["status"] == "backlogged"

    clock.advance(31)
    recovered_transport = FixtureTransport(
        secret,
        {
            ("POST", "/v1/ingest/events"): (202, b'{"accepted":1}'),
            ("GET", "/v1/agent/actions?device_id=device-test-1"): (
                200,
                b'{"actions":[]}',
            ),
        },
    )
    recovered_agent = EndpointCollectorAgent(
        collector_definition,
        SignedControlForgeClient(
            collector_definition,
            "3970e11f-f87c-4e14-9a90-d574cd2bcd95",
            secret,
            transport=recovered_transport,
        ),
        AgentSpool(collector_definition.spool_path),
        clock=clock,
    )
    monkeypatch.setattr(recovered_agent, "_control_report", report)
    recovered = recovered_agent.run_once()

    assert recovered["batches_delivered"] == 1
    assert recovered["batches_pending"] == 0
    assert spool.retry_state("delivery") is None
    assert spool.retry_state("action_polling") is None
    stored = json.loads(collector_definition.status_snapshot_path.read_text())
    assert stored["run_status"] == "completed"
    assert stored["failure_stage"] is None


def test_unchanged_control_snapshot_does_not_grow_spool_but_transition_is_retained(
    project_root, tmp_path, monkeypatch
) -> None:  # type: ignore[no-untyped-def]
    secret = "s" * 48
    clock = FixedClock(datetime(2026, 8, 31, 12, 0, tzinfo=timezone.utc))
    collector_definition = definition(project_root, tmp_path).model_copy(
        update={
            "action_polling_enabled": False,
            "retry_backoff_initial_seconds": 3600,
            "retry_backoff_max_seconds": 3600,
            "retry_backoff_jitter_ratio": 0.0,
        }
    )
    transport = FixtureTransport(
        secret,
        {("POST", "/v1/ingest/events"): (503, b'{"error":"unavailable"}')},
    )
    spool = AgentSpool(collector_definition.spool_path)
    agent = EndpointCollectorAgent(
        collector_definition,
        SignedControlForgeClient(
            collector_definition,
            "3970e11f-f87c-4e14-9a90-d574cd2bcd95",
            secret,
            transport=transport,
        ),
        spool,
        clock=clock,
    )
    monkeypatch.setattr(agent, "_control_report", report)
    agent.run_once()

    for _ in range(10):
        clock.advance(60)
        agent.run_once()
    assert spool.pending_summary() == (1, False)
    assert len(transport.requests) == 1

    monkeypatch.setattr(agent, "_control_report", lambda: report(ControlStatus.FAILED))
    changed = agent.run_once()

    assert changed["events_collected"] == 1
    assert spool.pending_summary() == (2, False)
    statuses = [
        batch_events[0].attributes["status"] for _, batch_events in spool.pending(limit=100)
    ]
    assert statuses == ["healthy", "failed"]


def test_control_snapshot_fingerprint_ignores_clock_drift_but_retains_evidence_changes() -> None:
    baseline = report()
    first_finding = baseline.findings[0].model_copy(
        update={
            "heartbeat_age_seconds": 10,
            "evidence": ["installed path: /one", "heartbeat age: 10s"],
        }
    )
    later_finding = first_finding.model_copy(
        update={
            "heartbeat_age_seconds": 20,
            "evidence": ["installed path: /one", "heartbeat age: 20s"],
        }
    )
    changed_finding = later_finding.model_copy(
        update={"evidence": ["installed path: /two", "heartbeat age: 20s"]}
    )

    first = baseline.model_copy(update={"findings": [first_finding]})
    later = baseline.model_copy(update={"findings": [later_finding]})
    changed = baseline.model_copy(update={"findings": [changed_finding]})

    assert EndpointCollectorAgent._control_snapshot_fingerprint(first) == (
        EndpointCollectorAgent._control_snapshot_fingerprint(later)
    )
    assert EndpointCollectorAgent._control_snapshot_fingerprint(later) != (
        EndpointCollectorAgent._control_snapshot_fingerprint(changed)
    )


def test_network_failure_is_redacted_and_does_not_escape_the_delivery_boundary(
    project_root, tmp_path, monkeypatch
) -> None:  # type: ignore[no-untyped-def]
    class NetworkFailureTransport:
        def request(self, method, path, headers, body, timeout_seconds):  # type: ignore[no-untyped-def]
            raise OSError("sensitive-network-detail")

    secret = "s" * 48
    collector_definition = definition(project_root, tmp_path).model_copy(
        update={"action_polling_enabled": False}
    )
    spool = AgentSpool(collector_definition.spool_path)
    agent = EndpointCollectorAgent(
        collector_definition,
        SignedControlForgeClient(
            collector_definition,
            "3970e11f-f87c-4e14-9a90-d574cd2bcd95",
            secret,
            transport=NetworkFailureTransport(),
        ),
        spool,
    )
    monkeypatch.setattr(agent, "_control_report", report)

    result = agent.run_once()

    assert result["batches_pending"] == 1
    stored = collector_definition.status_snapshot_path.read_bytes()
    assert b"sensitive-network-detail" not in stored
    assert b"sensitive-network-detail" not in collector_definition.spool_path.read_bytes()


def test_flush_limit_is_configurable_and_hard_capped(project_root, tmp_path) -> None:  # type: ignore[no-untyped-def]
    secret = "s" * 48
    collector_definition = definition(project_root, tmp_path).model_copy(
        update={"delivery_flush_batch_limit": 25}
    )
    spool = AgentSpool(collector_definition.spool_path)
    for _ in range(30):
        spool.enqueue([event()])
    transport = FixtureTransport(
        secret,
        {("POST", "/v1/ingest/events"): (202, b'{"accepted":1}')},
    )
    agent = EndpointCollectorAgent(
        collector_definition,
        SignedControlForgeClient(
            collector_definition,
            "3970e11f-f87c-4e14-9a90-d574cd2bcd95",
            secret,
            transport=transport,
        ),
        spool,
    )

    flushed = agent._flush(datetime(2026, 8, 31, 12, 0, tzinfo=timezone.utc))

    assert flushed.delivered == 25
    assert flushed.pending == 5
    assert len(transport.requests) == 25
    with pytest.raises(ValueError, match="less than or equal to 100"):
        CollectorDefinition(
            api_host="soc.example.com",
            device_id="device-test-1",
            delivery_flush_batch_limit=101,
        )


def test_status_v3_projects_real_component_failures_without_private_evidence(
    project_root, tmp_path, monkeypatch
):
    config = definition(project_root, tmp_path).model_copy(update={"action_polling_enabled": False})
    secret = "s" * 48
    transport = FixtureTransport(secret, {("POST", "/v1/ingest/events"): (202, b'{"accepted":4}')})
    agent = EndpointCollectorAgent(
        config,
        SignedControlForgeClient(
            config, "3970e11f-f87c-4e14-9a90-d574cd2bcd95", secret, transport=transport
        ),
    )
    report = ControlReport(
        hostname="synthetic",
        platform="darwin",
        findings=[
            ControlFinding(
                agent_id=f"component-{index}",
                display_name="PRIVATE-COMPONENT-NAME",
                status=status,
                installed=installed,
                running=running,
                evidence=["PRIVATE-PATH-AND-PROCESS"],
                recommended_action="PRIVATE-RECOMMENDATION",
            )
            for index, (status, installed, running) in enumerate(
                [
                    (ControlStatus.HEALTHY, True, True),
                    (ControlStatus.DEGRADED, True, True),
                    (ControlStatus.FAILED, False, False),
                    (ControlStatus.FAILED, True, False),
                ]
            )
        ],
    )
    monkeypatch.setattr(agent, "_control_report", lambda: report)
    agent.run_once()
    content = config.status_snapshot_path.read_text()
    snapshot = json.loads(content)
    assert snapshot["schema_version"] == "controlforge-agent-status-v3"
    assert snapshot["controls"] == {
        "evaluated": True,
        "total": 4,
        "failed": 2,
        "degraded": 1,
        "missing": 1,
        "not_running": 1,
    }
    assert "PRIVATE-" not in content and secret not in content


@pytest.mark.parametrize(
    "changes",
    [
        {"degraded": 4},
        {"failed": 3, "degraded": 1},
        {"missing": 2},
        {"missing": 1, "not_running": 1},
        {"not_running": -1},
        {"evaluated": False},
        {"degraded": None},
    ],
)
def test_status_v3_rejects_inconsistent_component_detail_counts(changes):
    with pytest.raises(ValueError):
        AgentControlStatusSummary.model_validate(
            {
                "evaluated": True,
                "total": 3,
                "failed": 1,
                "degraded": 0,
                "missing": 0,
                "not_running": 0,
                **changes,
            }
        )
    with pytest.raises(ValueError):
        AgentControlStatusSummary(evaluated=True, total=1, failed=0)


def test_status_store_atomically_replaces_a_strict_redacted_snapshot(tmp_path) -> None:  # type: ignore[no-untyped-def]
    status_path = tmp_path / "status" / "agent-status.json"
    store = AgentStatusSnapshotStore(status_path)
    first = AgentStatusSnapshot(
        generated_at=datetime(2026, 8, 22, 12, 0, tzinfo=timezone.utc),
        device_id="device-test-1",
        agent_version="0.3.0",
        run_status="completed",
        controls=AgentControlStatusSummary(
            evaluated=True, total=3, failed=1, degraded=0, missing=0, not_running=0
        ),
        delivery=AgentDeliveryStatusSummary(
            status="backlogged",
            batches_delivered=10,
            batches_pending=100,
            batches_pending_is_lower_bound=True,
        ),
        telemetry=AgentTelemetryStatusSummary(
            events_collected=503,
            santa_events_collected=500,
            santa_lines_rejected=0,
        ),
        actions_processed=0,
    )
    store.write(first)
    store.write(first.model_copy(update={"run_status": "completed"}))

    stored = json.loads(status_path.read_text(encoding="utf-8"))
    assert stored["schema_version"] == "controlforge-agent-status-v3"
    assert stored["containment"] == {"state": "not_configured", "expires_at": None}
    assert stored["delivery"] == {
        "status": "backlogged",
        "batches_delivered": 10,
        "batches_pending": 100,
        "batches_pending_is_lower_bound": True,
    }
    assert stat.S_IMODE(status_path.stat().st_mode) == 0o644
    assert list(status_path.parent.glob(".agent-status.json.*")) == []

    with pytest.raises(ValueError, match="Extra inputs are not permitted"):
        AgentStatusSnapshot.model_validate(
            {**first.model_dump(), "credential_secret": "must-never-be-serialized"}
        )
    with pytest.raises(ValueError, match="only isolated containment"):
        AgentContainmentStatusSummary(state="isolated")
    with pytest.raises(ValueError, match="only isolated containment"):
        AgentContainmentStatusSummary(
            state="released",
            expires_at=datetime(2026, 8, 22, 12, 15, tzinfo=timezone.utc),
        )


@pytest.mark.parametrize(
    ("payload", "message"),
    [
        (
            {
                "status": "backlogged",
                "batches_delivered": 0,
                "batches_pending": 0,
                "batches_pending_is_lower_bound": False,
            },
            "backlogged delivery requires a pending batch",
        ),
        (
            {
                "status": "succeeded",
                "batches_delivered": 1,
                "batches_pending": 1,
                "batches_pending_is_lower_bound": False,
            },
            "succeeded delivery cannot retain pending batches",
        ),
        (
            {
                "status": "failed",
                "batches_delivered": 0,
                "batches_pending": 99,
                "batches_pending_is_lower_bound": True,
            },
            "pending lower bound is valid only at the reporting cap",
        ),
        (
            {
                "status": "not_attempted",
                "batches_delivered": 1,
                "batches_pending": 0,
                "batches_pending_is_lower_bound": False,
            },
            "unattempted delivery cannot report delivered batches",
        ),
    ],
)
def test_status_delivery_summary_rejects_inconsistent_states(
    payload: dict[str, object],
    message: str,
) -> None:
    with pytest.raises(ValueError, match=message):
        AgentDeliveryStatusSummary.model_validate(payload)


def test_status_snapshot_requires_aware_time_and_consistent_telemetry() -> None:
    with pytest.raises(ValueError, match="timezone-aware"):
        AgentStatusSnapshot(
            generated_at=datetime(2026, 8, 22, 12, 0),
            device_id="device-test-1",
            agent_version="0.3.0",
            run_status="completed",
            controls=AgentControlStatusSummary(
                evaluated=True, total=3, failed=0, degraded=0, missing=0, not_running=0
            ),
            delivery=AgentDeliveryStatusSummary(
                status="succeeded",
                batches_delivered=1,
                batches_pending=0,
                batches_pending_is_lower_bound=False,
            ),
            telemetry=AgentTelemetryStatusSummary(
                events_collected=3,
                santa_events_collected=1,
                santa_lines_rejected=0,
            ),
            actions_processed=0,
        )
    with pytest.raises(ValueError, match="cannot exceed total"):
        AgentTelemetryStatusSummary(
            events_collected=1,
            santa_events_collected=2,
            santa_lines_rejected=0,
        )


def test_status_snapshot_reports_honest_pending_lower_bound(project_root, tmp_path) -> None:  # type: ignore[no-untyped-def]
    secret = "s" * 48
    collector_definition = definition(project_root, tmp_path)
    spool = AgentSpool(collector_definition.spool_path)
    for _ in range(101):
        spool.enqueue([event()])
    transport = FixtureTransport(
        secret,
        {
            ("POST", "/v1/ingest/events"): (503, b'{"error":"unavailable"}'),
            ("GET", "/v1/agent/actions?device_id=device-test-1"): (200, b'{"actions":[]}'),
        },
    )
    client = SignedControlForgeClient(
        collector_definition,
        "3970e11f-f87c-4e14-9a90-d574cd2bcd95",
        secret,
        transport=transport,
    )

    result = EndpointCollectorAgent(collector_definition, client, spool).run_once()
    status_path = collector_definition.status_snapshot_path
    assert status_path is not None
    stored = json.loads(status_path.read_text(encoding="utf-8"))

    assert result["batches_pending"] == 100
    assert result["batches_pending_is_lower_bound"] is True
    assert stored["delivery"] == {
        "status": "failed",
        "batches_delivered": 0,
        "batches_pending": 100,
        "batches_pending_is_lower_bound": True,
    }


def test_action_polling_failure_is_isolated_and_persists_redacted_status(
    project_root, tmp_path
) -> None:  # type: ignore[no-untyped-def]
    secret = "s" * 48
    collector_definition = definition(project_root, tmp_path)
    transport = FixtureTransport(
        secret,
        {
            ("POST", "/v1/ingest/events"): (202, b'{"accepted":3}'),
            ("GET", "/v1/agent/actions?device_id=device-test-1"): (
                503,
                b'{"provider_detail":"must-not-be-persisted"}',
            ),
        },
    )
    client = SignedControlForgeClient(
        collector_definition,
        "3970e11f-f87c-4e14-9a90-d574cd2bcd95",
        secret,
        transport=transport,
    )

    result = EndpointCollectorAgent(collector_definition, client).run_once()

    status_path = collector_definition.status_snapshot_path
    assert status_path is not None
    stored = json.loads(status_path.read_text(encoding="utf-8"))
    assert result["actions_processed"] == 0
    assert stored["run_status"] == "failed"
    assert stored["failure_stage"] == "action_polling"
    assert stored["delivery"]["status"] == "succeeded"
    serialized_status = status_path.read_bytes()
    assert secret.encode() not in serialized_status
    assert b"must-not-be-persisted" not in serialized_status


def test_standalone_agent_skips_unsupported_action_polling(project_root, tmp_path) -> None:  # type: ignore[no-untyped-def]
    secret = "s" * 48
    collector_definition = definition(project_root, tmp_path).model_copy(
        update={
            "api_port": 8443,
            "access_proxy_required": False,
            "action_polling_enabled": False,
        }
    )
    transport = FixtureTransport(
        secret,
        {("POST", "/v1/ingest/events"): (202, b'{"accepted":3}')},
    )
    client = SignedControlForgeClient(
        collector_definition,
        "3970e11f-f87c-4e14-9a90-d574cd2bcd95",
        secret,
        transport=transport,
    )

    result = EndpointCollectorAgent(collector_definition, client).run_once()

    assert result["actions_processed"] == 0
    assert [request[:2] for request in transport.requests] == [("POST", "/v1/ingest/events")]
    status_path = collector_definition.status_snapshot_path
    assert status_path is not None
    stored = json.loads(status_path.read_text(encoding="utf-8"))
    assert stored["run_status"] == "completed"
    assert stored["failure_stage"] is None


def test_system_keychain_uses_fixed_signed_reader_and_accounts(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    requests: list[list[str]] = []

    def fixture_run(arguments, **options):  # type: ignore[no-untyped-def]
        requests.append(arguments)
        assert options == {"check": True, "capture_output": True, "timeout": 5}
        return subprocess.CompletedProcess(arguments, 0, stdout=b"keychain-value\n", stderr=b"")

    monkeypatch.setattr("controlforge.collector_agent.platform.system", lambda: "Darwin")
    monkeypatch.setattr("controlforge.collector_agent.subprocess.run", fixture_run)

    secrets = MacOSSystemKeychain("com.controlforge.collector").load()

    assert secrets.credential_id == "keychain-value"
    assert requests == [
        ["/Library/ControlForge/bin/controlforge", "keychain-read", "credential-id"],
        ["/Library/ControlForge/bin/controlforge", "keychain-read", "credential-secret"],
        ["/Library/ControlForge/bin/controlforge", "keychain-read", "access-client-id"],
        ["/Library/ControlForge/bin/controlforge", "keychain-read", "access-client-secret"],
    ]

    requests.clear()
    standalone_secrets = MacOSSystemKeychain("com.controlforge.collector").load(
        require_access=False
    )
    assert standalone_secrets.access_client_id is None
    assert standalone_secrets.access_client_secret is None
    assert requests == [
        ["/Library/ControlForge/bin/controlforge", "keychain-read", "credential-id"],
        ["/Library/ControlForge/bin/controlforge", "keychain-read", "credential-secret"],
    ]


def test_system_keychain_fails_closed_without_leaking_provider_output(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    def fixture_run(*arguments, **options):  # type: ignore[no-untyped-def]
        raise subprocess.CalledProcessError(71, arguments[0], stderr=b"sensitive-keychain-output")

    monkeypatch.setattr("controlforge.collector_agent.platform.system", lambda: "Darwin")
    monkeypatch.setattr("controlforge.collector_agent.subprocess.run", fixture_run)

    with pytest.raises(ValueError, match="credential-id") as error:
        MacOSSystemKeychain("com.controlforge.collector").load()
    assert "sensitive-keychain-output" not in str(error.value)


def test_system_keychain_atomically_imports_standalone_pair(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    calls: list[tuple[list[str], dict[str, object]]] = []

    def fixture_run(arguments, **options):  # type: ignore[no-untyped-def]
        calls.append((arguments, options))
        return subprocess.CompletedProcess(arguments, 0, stdout=b"", stderr=b"")

    monkeypatch.setattr("controlforge.collector_agent.platform.system", lambda: "Darwin")
    monkeypatch.setattr("controlforge.collector_agent.subprocess.run", fixture_run)
    credential_id = "3970e11f-f87c-4e14-9a90-d574cd2bcd95"
    credential_secret = "s" * 48

    MacOSSystemKeychain("com.controlforge.collector").store_initial(
        credential_id,
        credential_secret,
    )

    assert calls[0][0] == [
        "/Library/ControlForge/bin/controlforge",
        "keychain-import-pair",
    ]
    options = calls[0][1]
    assert options["check"] is True
    assert options["capture_output"] is True
    assert options["timeout"] == 10
    assert json.loads(options["input"]) == {
        "credential-id": credential_id,
        "credential-secret": credential_secret,
    }


def test_system_keychain_replaces_only_the_expected_effective_pair(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    calls: list[tuple[list[str], dict[str, object]]] = []

    def fixture_run(arguments, **options):  # type: ignore[no-untyped-def]
        calls.append((arguments, options))
        return subprocess.CompletedProcess(arguments, 0, stdout=b"", stderr=b"")

    monkeypatch.setattr("controlforge.collector_agent.platform.system", lambda: "Darwin")
    monkeypatch.setattr("controlforge.collector_agent.subprocess.run", fixture_run)
    predecessor = "3970e11f-f87c-4e14-9a90-d574cd2bcd95"
    replacement = "4970e11f-f87c-4e14-9a90-d574cd2bcd96"

    MacOSSystemKeychain("com.controlforge.collector").replace_pair(
        predecessor,
        replacement,
        "r" * 48,
    )

    assert calls[0][0] == [
        "/Library/ControlForge/bin/controlforge",
        "keychain-replace-pair",
    ]
    assert json.loads(calls[0][1]["input"]) == {
        "expected-credential-id": predecessor,
        "credential-id": replacement,
        "credential-secret": "r" * 48,
    }
    assert calls[0][1]["timeout"] == 10


def test_system_keychain_preflights_before_grant_consumption(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    calls: list[tuple[list[str], dict[str, object]]] = []

    def fixture_run(arguments, **options):  # type: ignore[no-untyped-def]
        calls.append((arguments, options))
        return subprocess.CompletedProcess(arguments, 0, stdout=b"", stderr=b"")

    monkeypatch.setattr("controlforge.collector_agent.platform.system", lambda: "Darwin")
    monkeypatch.setattr("controlforge.collector_agent.subprocess.run", fixture_run)

    MacOSSystemKeychain("com.controlforge.collector").require_initial_empty()

    assert calls == [
        (
            ["/Library/ControlForge/bin/controlforge", "keychain-require-empty"],
            {"check": True, "capture_output": True, "timeout": 5},
        )
    ]


def test_system_keychain_import_error_does_not_leak_secret(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    def fixture_run(*arguments, **options):  # type: ignore[no-untyped-def]
        raise subprocess.CalledProcessError(74, arguments[0], stderr=b"provider-secret")

    monkeypatch.setattr("controlforge.collector_agent.platform.system", lambda: "Darwin")
    monkeypatch.setattr("controlforge.collector_agent.subprocess.run", fixture_run)
    with pytest.raises(ValueError, match="could not be stored") as error:
        MacOSSystemKeychain("com.controlforge.collector").store_initial(
            "3970e11f-f87c-4e14-9a90-d574cd2bcd95",
            "s" * 48,
        )
    assert "provider-secret" not in str(error.value)


def test_agent_fails_closed_for_active_action_without_adapter(project_root, tmp_path) -> None:  # type: ignore[no-untyped-def]
    secret = "s" * 48
    action_id = "2cda0154-59b1-4a66-8955-b8068fb0c33c"
    actions = {
        "actions": [
            {
                "action_id": action_id,
                "action_type": "isolate_endpoint",
                "target_type": "device",
                "target_id": "device-test-1",
                "rationale": "Approved containment for confirmed credential dumping.",
                "risk_level": "active",
                "expires_at": "2026-08-19T06:00:00Z",
            }
        ]
    }
    transport = FixtureTransport(
        secret,
        {
            ("POST", "/v1/ingest/events"): (202, b'{"accepted":3}'),
            ("GET", "/v1/agent/actions?device_id=device-test-1"): (
                200,
                json.dumps(actions).encode(),
            ),
            ("POST", f"/v1/agent/actions/{action_id}/result"): (200, b'{"status":"failed"}'),
        },
    )
    collector_definition = definition(project_root, tmp_path)
    client = SignedControlForgeClient(
        collector_definition,
        "3970e11f-f87c-4e14-9a90-d574cd2bcd95",
        secret,
        transport=transport,
    )
    result = EndpointCollectorAgent(
        collector_definition,
        client,
        AgentSpool(collector_definition.spool_path),
    ).run_once()

    assert result == {
        "events_collected": 3,
        "batches_delivered": 1,
        "batches_pending": 0,
        "batches_pending_is_lower_bound": False,
        "actions_processed": 1,
        "santa_events_collected": 0,
        "santa_lines_rejected": 0,
    }
    result_body = json.loads(transport.requests[-1][3])
    assert result_body["status"] == "failed"
    assert "no active change" in result_body["summary"]
    status_path = collector_definition.status_snapshot_path
    assert status_path is not None
    status_payload = json.loads(status_path.read_text(encoding="utf-8"))
    assert set(status_payload) == {
        "schema_version",
        "generated_at",
        "device_id",
        "agent_version",
        "run_status",
        "failure_stage",
        "controls",
        "delivery",
        "telemetry",
        "containment",
        "actions_processed",
    }
    assert status_payload["containment"] == {
        "state": "not_configured",
        "expires_at": None,
    }
    assert set(status_payload["controls"]) == {
        "evaluated",
        "total",
        "failed",
        "degraded",
        "missing",
        "not_running",
    }
    assert set(status_payload["delivery"]) == {
        "status",
        "batches_delivered",
        "batches_pending",
        "batches_pending_is_lower_bound",
    }
    assert set(status_payload["telemetry"]) == {
        "events_collected",
        "santa_events_collected",
        "santa_lines_rejected",
    }
    serialized_status = status_path.read_bytes()
    assert secret.encode() not in serialized_status
    assert b"Approved containment for confirmed credential dumping" not in serialized_status
    assert b"/Applications/Falcon.app" not in serialized_status


def test_agent_spools_santa_events_and_persists_cursor(project_root, tmp_path) -> None:  # type: ignore[no-untyped-def]
    santa_path = tmp_path / "santa.log"
    santa_path.write_text(
        json.dumps(
            {
                "event_time": "2026-08-18T12:00:00Z",
                "event_id": "a" * 32,
                "boot_session_uuid": "boot-1",
                "gatekeeper_override": {
                    "instigator": {"executable": {"path": "/usr/bin/xattr"}},
                    "target": {"path": "/Applications/Unknown.app"},
                },
            }
        )
        + "\n",
        encoding="utf-8",
    )
    santa_path.chmod(0o600)
    secret = "s" * 48
    transport = FixtureTransport(
        secret,
        {
            ("POST", "/v1/ingest/events"): (202, b'{"accepted":4}'),
            ("GET", "/v1/agent/actions?device_id=device-test-1"): (200, b'{"actions":[]}'),
        },
    )
    collector_definition = definition(project_root, tmp_path).model_copy(
        update={"santa": SantaLogDefinition(enabled=True, log_path=santa_path)}
    )
    client = SignedControlForgeClient(
        collector_definition,
        "3970e11f-f87c-4e14-9a90-d574cd2bcd95",
        secret,
        transport=transport,
    )
    spool = AgentSpool(collector_definition.spool_path)
    santa_reader = SantaJsonLogReader(collector_definition.santa, collector_definition.device_id)

    first = EndpointCollectorAgent(
        collector_definition,
        client,
        spool,
        santa_reader,
    ).run_once()

    assert first["events_collected"] == 4
    assert first["santa_events_collected"] == 1
    assert first["santa_lines_rejected"] == 0
    assert spool.source_cursor(santa_reader.source_id) is not None
    event_body = json.loads(transport.requests[0][3])
    assert event_body["events"][-1]["event_type"] == "santa_gatekeeper_override"
    assert {event["device_id"] for event in event_body["events"]} == {"device-test-1"}

    second = EndpointCollectorAgent(
        collector_definition,
        client,
        spool,
        santa_reader,
    ).run_once()
    assert second["events_collected"] == 0
    assert second["santa_events_collected"] == 0
    assert [request[:2] for request in transport.requests].count(("POST", "/v1/ingest/events")) == 1
