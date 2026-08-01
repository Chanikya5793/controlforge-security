import json
from datetime import datetime, timezone

import pytest

from controlforge.exposure import (
    ExposureKind,
    ExposureRecord,
    ExposureService,
    HibpClient,
    HibpError,
)
from controlforge.store import AuditStore


class FixtureTransport:
    def __init__(self, responses: dict[str, tuple[int, bytes]]) -> None:
        self.responses = responses
        self.requests: list[tuple[str, dict[str, str]]] = []

    def get(self, path: str, headers: dict[str, str], timeout_seconds: float) -> tuple[int, bytes]:
        assert timeout_seconds == 10.0
        self.requests.append((path, headers))
        return self.responses[path]


def test_hibp_domain_scan_hashes_aliases_and_collects_breaches() -> None:
    transport = FixtureTransport(
        {
            "/api/v3/breacheddomain/example.com": (
                200,
                json.dumps({"alice": ["Adobe", "ExampleBreach"]}).encode(),
            )
        }
    )
    records = HibpClient("0" * 32, transport=transport).scan_verified_domain("Example.com")

    assert [record.source_name for record in records] == ["Adobe", "ExampleBreach"]
    assert all(record.kind == ExposureKind.BREACH for record in records)
    serialized = "".join(record.model_dump_json() for record in records)
    assert "alice" not in serialized
    assert transport.requests[0][1]["hibp-api-key"] == "0" * 32


def test_hibp_scan_can_include_infostealer_results() -> None:
    transport = FixtureTransport(
        {
            "/api/v3/breacheddomain/example.com": (404, b""),
            "/api/v3/stealerlogsbyemaildomain/example.com": (
                200,
                json.dumps({"analyst": ["finance.example", "mail.example"]}).encode(),
            ),
        }
    )
    records = HibpClient("0" * 32, transport=transport).scan_verified_domain(
        "example.com", include_stealer_logs=True
    )

    assert len(records) == 2
    assert {record.kind for record in records} == {ExposureKind.INFOSTEALER}


@pytest.mark.parametrize("domain", ["localhost", "https://example.com", "../example.com"])
def test_hibp_scan_rejects_invalid_domains(domain: str) -> None:
    client = HibpClient("0" * 32, transport=FixtureTransport({}))
    with pytest.raises(ValueError, match="valid DNS name"):
        client.scan_verified_domain(domain)


def test_hibp_scan_rejects_provider_failures_without_leaking_body() -> None:
    transport = FixtureTransport(
        {"/api/v3/breacheddomain/example.com": (401, b"secret provider response")}
    )
    with pytest.raises(HibpError, match="HTTP 401") as error:
        HibpClient("0" * 32, transport=transport).scan_verified_domain("example.com")
    assert "secret provider response" not in str(error.value)


def test_exposure_service_persists_deduplicated_privacy_safe_alert(tmp_path) -> None:  # type: ignore[no-untyped-def]
    record = ExposureRecord(
        exposure_id="f" * 24,
        identity_sha256="a" * 64,
        monitored_domain="example.com",
        source_name="ExampleBreach",
        kind=ExposureKind.BREACH,
        observed_at=datetime(2026, 8, 12, 15, 0, tzinfo=timezone.utc),
    )
    store = AuditStore(tmp_path / "exposure.db")
    service = ExposureService(store)

    first = service.process([record])
    service.process([record])

    assert first.alerts[0].rule_id == "CF-EXPOSURE-001"
    assert first.alerts[0].actor == "identity:aaaaaaaaaaaa"
    assert len(store.recent_alerts()) == 1
