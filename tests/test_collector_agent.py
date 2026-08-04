import hashlib
import hmac
import json
import subprocess
from datetime import datetime, timezone

import pytest

from controlforge.collector_agent import (
    AgentSpool,
    CollectorDefinition,
    CollectorError,
    EndpointCollectorAgent,
    MacOSSystemKeychain,
    SignedControlForgeClient,
)
from controlforge.models import SecurityEvent
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


def definition(project_root, tmp_path) -> CollectorDefinition:  # type: ignore[no-untyped-def]
    return CollectorDefinition(
        api_host="controlforge-soc.example.workers.dev",
        device_id="device-test-1",
        controls_path=project_root / "config" / "agents.yml",
        spool_path=tmp_path / "spool.db",
    )


def event() -> SecurityEvent:
    return SecurityEvent(
        event_id="event-1",
        event_type="endpoint_control_status",
        timestamp=datetime(2026, 8, 18, 6, 0, tzinfo=timezone.utc),
        actor="device:device-test-1",
        attributes={"status": "healthy"},
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


def test_system_keychain_fails_closed_without_leaking_provider_output(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    def fixture_run(*arguments, **options):  # type: ignore[no-untyped-def]
        raise subprocess.CalledProcessError(71, arguments[0], stderr=b"sensitive-keychain-output")

    monkeypatch.setattr("controlforge.collector_agent.platform.system", lambda: "Darwin")
    monkeypatch.setattr("controlforge.collector_agent.subprocess.run", fixture_run)

    with pytest.raises(ValueError, match="credential-id") as error:
        MacOSSystemKeychain("com.controlforge.collector").load()
    assert "sensitive-keychain-output" not in str(error.value)


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
        "actions_processed": 1,
        "santa_events_collected": 0,
        "santa_lines_rejected": 0,
    }
    result_body = json.loads(transport.requests[-1][3])
    assert result_body["status"] == "failed"
    assert "no active change" in result_body["summary"]


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
    assert second["events_collected"] == 3
    assert second["santa_events_collected"] == 0
