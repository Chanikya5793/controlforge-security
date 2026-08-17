from __future__ import annotations

import json
import stat
from pathlib import Path

import pytest

from controlforge.collector_agent import CollectorDefinition, load_collector_definition
from controlforge.endpoint_enrollment import (
    EndpointEnrollmentError,
    StandaloneEndpointEnrollmentClient,
    credentials_from_enrollment,
    install_collector_definition,
    standalone_collector_definition,
)


class FixtureEnrollmentTransport:
    def __init__(self, status: int, payload: object) -> None:
        self.status = status
        self.payload = payload
        self.calls: list[tuple[str, int, bytes, float]] = []

    def claim(
        self,
        host: str,
        port: int,
        body: bytes,
        timeout_seconds: float,
    ) -> tuple[int, bytes]:
        self.calls.append((host, port, body, timeout_seconds))
        return self.status, json.dumps(self.payload).encode()


def valid_payload() -> dict[str, str]:
    return {
        "tenant_id": "00000000-0000-4000-8000-000000000020",
        "device_id": "mac-primary",
        "credential_id": "3970e11f-f87c-4e14-9a90-d574cd2bcd95",
        "credential_secret": "s" * 48,
        "expires_at": "2026-11-20T19:00:00+00:00",
    }


def test_claim_is_fixed_host_https_contract_and_returns_standalone_secrets() -> None:
    transport = FixtureEnrollmentTransport(201, valid_payload())
    result = StandaloneEndpointEnrollmentClient(
        "standalone.example.com",
        transport=transport,
    ).claim("t" * 43, "mac-primary", " Primary Mac ")

    assert result.device_id == "mac-primary"
    host, port, body, timeout = transport.calls[0]
    assert host == "standalone.example.com"
    assert port == 8443
    assert timeout == 15
    assert json.loads(body) == {
        "token": "t" * 43,
        "device_id": "mac-primary",
        "display_name": "Primary Mac",
        "platform": "macos",
    }
    secrets = credentials_from_enrollment(result)
    assert secrets.credential_id == result.credential_id
    assert secrets.access_client_id is None


@pytest.mark.parametrize(
    ("status", "mutate", "message"),
    [
        (409, {}, "HTTP 409"),
        (201, {"extra": "field"}, "invalid credentials"),
        (201, {"credential_id": "device-not-a-uuid"}, "invalid credentials"),
        (201, {"device_id": "different-device"}, "different device"),
    ],
)
def test_claim_fails_closed_for_http_and_response_contract_drift(
    status: int,
    mutate: dict[str, str],
    message: str,
) -> None:
    payload = {**valid_payload(), **mutate}
    transport = FixtureEnrollmentTransport(status, payload)
    with pytest.raises(EndpointEnrollmentError, match=message):
        StandaloneEndpointEnrollmentClient(
            "standalone.example.com",
            transport=transport,
        ).claim("t" * 43, "mac-primary", "Primary Mac")


def test_host_token_and_name_are_validated_before_network() -> None:
    transport = FixtureEnrollmentTransport(201, valid_payload())
    with pytest.raises(ValueError):
        StandaloneEndpointEnrollmentClient("https://attacker.example/path", transport=transport)
    client = StandaloneEndpointEnrollmentClient("standalone.example.com", transport=transport)
    StandaloneEndpointEnrollmentClient("localhost", transport=transport)
    with pytest.raises(EndpointEnrollmentError, match="grant"):
        client.claim("short", "mac-primary", "Primary Mac")
    with pytest.raises(ValueError, match="display name"):
        client.claim("t" * 43, "mac-primary", "   ")
    assert transport.calls == []


def test_account_context_is_explicit_and_legacy_shape_is_preserved() -> None:
    payload = {**valid_payload(), "account_id": "alex", "network_name": "Alpha School"}
    transport = FixtureEnrollmentTransport(201, payload)
    result = StandaloneEndpointEnrollmentClient(
        "standalone.example.com", transport=transport, account_context=True
    ).claim("t" * 43, "mac-primary", "Primary Mac")
    assert result.model_dump()["account_id"] == "alex"
    assert json.loads(transport.calls[0][2])["include_account_context"] is True
    with pytest.raises(EndpointEnrollmentError, match="invalid credentials"):
        StandaloneEndpointEnrollmentClient(
            "standalone.example.com",
            transport=FixtureEnrollmentTransport(201, valid_payload()),
            account_context=True,
        ).claim("t" * 43, "mac-primary", "Primary Mac")


def test_install_definition_preserves_paths_and_disables_cloud_access(
    tmp_path: Path,
) -> None:
    path = tmp_path / "config" / "collector.yml"
    current = CollectorDefinition(
        api_host="soc.example.com",
        device_id="old-device",
        controls_path=Path("/Library/Application Support/ControlForge/agents.yml"),
        spool_path=Path("/Library/Application Support/ControlForge/spool.db"),
        status_snapshot_path=Path("/Library/ControlForge/status/agent-status.json"),
        credential_source="macos_system_keychain",
        access_proxy_required=True,
    )
    standalone = standalone_collector_definition(
        current,
        "standalone.example.com",
        8443,
        "mac-primary",
    )
    install_collector_definition(path, standalone)

    installed = load_collector_definition(path)
    assert installed.api_host == "standalone.example.com"
    assert installed.api_port == 8443
    assert installed.device_id == "mac-primary"
    assert installed.access_proxy_required is False
    assert installed.action_polling_enabled is True
    assert installed.credential_rotation_enabled is True
    assert installed.spool_path == current.spool_path
    assert stat.S_IMODE(path.stat().st_mode) == 0o600


def test_install_definition_rejects_symlink(tmp_path: Path) -> None:
    target = tmp_path / "real.yml"
    target.write_text("do not overwrite", encoding="utf-8")
    path = tmp_path / "collector.yml"
    path.symlink_to(target)
    definition = CollectorDefinition(api_host="standalone.example.com", device_id="mac")

    with pytest.raises(EndpointEnrollmentError, match="regular file"):
        install_collector_definition(path, definition)
    assert target.read_text(encoding="utf-8") == "do not overwrite"
