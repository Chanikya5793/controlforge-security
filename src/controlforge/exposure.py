"""Privacy-preserving breach and infostealer exposure monitoring."""

from __future__ import annotations

import hashlib
import http.client
import json
import re
from collections.abc import Mapping
from datetime import datetime
from enum import Enum
from typing import Optional, Protocol
from urllib.parse import quote

from pydantic import BaseModel, Field

from .models import DetectionAlert, SecurityEvent, Severity, utc_now
from .store import AuditStore


class ExposureKind(str, Enum):
    BREACH = "breach"
    INFOSTEALER = "infostealer"


class ExposureRecord(BaseModel):
    """Normalized exposure without plaintext account aliases or credentials."""

    exposure_id: str = Field(min_length=20)
    identity_sha256: str = Field(pattern=r"^[a-f0-9]{64}$")
    monitored_domain: str = Field(min_length=3)
    source_name: str = Field(min_length=1)
    kind: ExposureKind
    observed_at: datetime = Field(default_factory=utc_now)
    provider: str = "Have I Been Pwned"


class ExposureScanResult(BaseModel):
    exposures_processed: int
    alerts: list[DetectionAlert]
    generated_at: datetime = Field(default_factory=utc_now)


class HibpError(RuntimeError):
    """Raised when a sanctioned HIBP request cannot be completed safely."""


class HibpTransport(Protocol):
    def get(
        self, path: str, headers: Mapping[str, str], timeout_seconds: float
    ) -> tuple[int, bytes]:
        """Perform one request against the fixed HIBP API host."""


class HttpsHibpTransport:
    """Small fixed-host HTTPS transport that avoids arbitrary outbound URLs."""

    def get(
        self, path: str, headers: Mapping[str, str], timeout_seconds: float
    ) -> tuple[int, bytes]:
        connection = http.client.HTTPSConnection(
            "haveibeenpwned.com",
            port=443,
            timeout=timeout_seconds,
        )
        try:
            connection.request("GET", path, headers=dict(headers))
            response = connection.getresponse()
            return response.status, response.read()
        finally:
            connection.close()


class HibpClient:
    """Fetch verified-domain breach intelligence without retaining plaintext aliases."""

    _DOMAIN = re.compile(r"^(?=.{3,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$")
    _API_KEY = re.compile(r"^[a-fA-F0-9]{32}$")
    _MAX_RECORDS = 10_000

    def __init__(
        self,
        api_key: str,
        transport: Optional[HibpTransport] = None,
        user_agent: str = "ControlForge-Security/0.2",
        timeout_seconds: float = 10.0,
    ) -> None:
        if self._API_KEY.fullmatch(api_key) is None:
            raise ValueError("HIBP API key must be a 32-character hexadecimal value")
        self._api_key = api_key
        self._transport = transport or HttpsHibpTransport()
        self._user_agent = user_agent
        self._timeout_seconds = timeout_seconds

    def scan_verified_domain(
        self,
        domain: str,
        include_stealer_logs: bool = False,
    ) -> list[ExposureRecord]:
        normalized_domain = domain.strip().casefold().rstrip(".")
        if self._DOMAIN.fullmatch(normalized_domain) is None:
            raise ValueError("domain must be a valid DNS name")

        records = self._fetch_alias_map(
            f"/api/v3/breacheddomain/{quote(normalized_domain, safe='')}",
            normalized_domain,
            ExposureKind.BREACH,
        )
        if include_stealer_logs:
            records.extend(
                self._fetch_alias_map(
                    f"/api/v3/stealerlogsbyemaildomain/{quote(normalized_domain, safe='')}",
                    normalized_domain,
                    ExposureKind.INFOSTEALER,
                )
            )
        return sorted(
            records, key=lambda item: (item.kind.value, item.identity_sha256, item.source_name)
        )

    def _fetch_alias_map(
        self,
        path: str,
        domain: str,
        kind: ExposureKind,
    ) -> list[ExposureRecord]:
        status, payload = self._transport.get(
            path,
            {
                "accept": "application/json",
                "hibp-api-key": self._api_key,
                "user-agent": self._user_agent,
            },
            self._timeout_seconds,
        )
        if status == 404:
            return []
        if status != 200:
            raise HibpError(f"HIBP request failed with HTTP {status}")

        try:
            raw = json.loads(payload)
        except (json.JSONDecodeError, UnicodeDecodeError) as exc:
            raise HibpError("HIBP returned malformed JSON") from exc
        if not isinstance(raw, dict):
            raise HibpError("HIBP alias response must be an object")

        records: list[ExposureRecord] = []
        for alias, source_names in raw.items():
            if not isinstance(alias, str) or not isinstance(source_names, list):
                raise HibpError("HIBP alias response has an invalid shape")
            identity_hash = hashlib.sha256(f"{alias.casefold()}@{domain}".encode()).hexdigest()
            for source_name in source_names:
                if not isinstance(source_name, str) or not source_name.strip():
                    raise HibpError("HIBP exposure source must be a non-empty string")
                fingerprint = f"{kind.value}:{identity_hash}:{source_name.casefold()}".encode()
                records.append(
                    ExposureRecord(
                        exposure_id=hashlib.sha256(fingerprint).hexdigest()[:24],
                        identity_sha256=identity_hash,
                        monitored_domain=domain,
                        source_name=source_name.strip(),
                        kind=kind,
                    )
                )
                if len(records) > self._MAX_RECORDS:
                    raise HibpError("HIBP response exceeds the 10,000-record safety limit")
        return records


class ExposureMonitor:
    """Turn normalized external exposure records into explainable alerts."""

    def evaluate(self, record: ExposureRecord) -> DetectionAlert:
        rule_id = (
            "CF-EXPOSURE-002" if record.kind == ExposureKind.INFOSTEALER else "CF-EXPOSURE-001"
        )
        title = (
            "Infostealer exposure associated with a monitored domain"
            if record.kind == ExposureKind.INFOSTEALER
            else "Breach exposure associated with a monitored domain"
        )
        severity = Severity.HIGH if record.kind == ExposureKind.INFOSTEALER else Severity.MEDIUM
        fingerprint = f"{rule_id}:{record.exposure_id}".encode()
        return DetectionAlert(
            alert_id=hashlib.sha256(fingerprint).hexdigest()[:20],
            rule_id=rule_id,
            title=title,
            severity=severity,
            event_id=record.exposure_id,
            actor=f"identity:{record.identity_sha256[:12]}",
            reasons=[
                f"{record.kind.value} exposure reported by {record.provider}",
                f"{record.source_name} includes an account on {record.monitored_domain}",
                "account alias retained only as a SHA-256 digest",
            ],
            tags=["exposure-intelligence", record.kind.value, "credential-risk"],
            created_at=record.observed_at,
        )


class ExposureService:
    def __init__(self, store: AuditStore, monitor: Optional[ExposureMonitor] = None) -> None:
        self._store = store
        self._monitor = monitor or ExposureMonitor()

    def process(self, records: list[ExposureRecord]) -> ExposureScanResult:
        alerts: list[DetectionAlert] = []
        for record in records:
            event = SecurityEvent(
                event_id=record.exposure_id,
                event_type=f"external_{record.kind.value}_exposure",
                timestamp=record.observed_at,
                actor=f"identity:{record.identity_sha256[:12]}",
                target=record.monitored_domain,
                attributes={
                    "provider": record.provider,
                    "source_name": record.source_name,
                    "identity_sha256": record.identity_sha256,
                },
            )
            alert = self._monitor.evaluate(record)
            self._store.save_event(event)
            self._store.save_alerts([alert])
            alerts.append(alert)
        return ExposureScanResult(exposures_processed=len(records), alerts=alerts)
