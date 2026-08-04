"""Signed endpoint collector with durable delivery and structured action handling."""

from __future__ import annotations

import hashlib
import hmac
import http.client
import json
import platform
import re
import sqlite3
import subprocess  # nosec B404 -- fixed signed ControlForge helper only
import uuid
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Literal, Optional, Protocol

import yaml
from pydantic import BaseModel, Field

from .config import load_control_config
from .controls import EndpointAssuranceEngine
from .models import ControlReport, SecurityEvent
from .probes import LocalSystemProbe
from .santa import SantaJsonLogReader, SantaLogDefinition, SantaLogError, SourceCursor


class CollectorError(RuntimeError):
    """Raised when the collector cannot complete a signed control-plane request."""


class CollectorDefinition(BaseModel):
    """Non-secret, version-controlled endpoint collector configuration."""

    api_host: str = Field(
        min_length=4,
        max_length=253,
        pattern=r"^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$",
    )
    device_id: str = Field(min_length=1, max_length=128, pattern=r"^[A-Za-z0-9._:-]+$")
    controls_path: Path = Path("config/agents.yml")
    spool_path: Path = Path("controlforge-agent-spool.db")
    santa: SantaLogDefinition = Field(default_factory=SantaLogDefinition)
    credential_source: Literal["environment", "macos_system_keychain"] = "environment"
    keychain_service: str = Field(
        default="com.controlforge.collector",
        pattern=r"^[A-Za-z0-9.-]{3,128}$",
    )


def load_collector_definition(path: Path) -> CollectorDefinition:
    raw = yaml.safe_load(path.read_text(encoding="utf-8"))
    if not isinstance(raw, dict):
        raise ValueError("collector configuration must be a YAML mapping")
    return CollectorDefinition.model_validate(raw)


@dataclass(frozen=True)
class CollectorSecrets:
    credential_id: str
    credential_secret: str
    access_client_id: Optional[str]
    access_client_secret: Optional[str]


class MacOSSystemKeychain:
    """Load fixed collector accounts from the macOS System keychain."""

    _READER = "/Library/ControlForge/bin/controlforge"
    _SYSTEM_KEYCHAIN = "/Library/Keychains/System.keychain"

    def __init__(self, service: str) -> None:
        if re.fullmatch(r"[A-Za-z0-9.-]{3,128}", service) is None:
            raise ValueError("invalid collector keychain service")
        self._service = service

    def _read(self, account: str) -> str:
        if platform.system() != "Darwin":
            raise ValueError("macOS System keychain secret source requires macOS")
        try:
            result = subprocess.run(  # noqa: S603  # nosec B603
                [self._READER, "keychain-read", account],
                check=True,
                capture_output=True,
                timeout=5,
            )
            secret = result.stdout.decode("utf-8")
        except (
            OSError,
            UnicodeDecodeError,
            subprocess.CalledProcessError,
            subprocess.TimeoutExpired,
        ) as exc:
            raise ValueError(f"collector keychain item is unavailable: {account}") from exc
        secret = secret.rstrip("\r\n")
        if not secret:
            raise ValueError(f"collector keychain item is empty: {account}")
        return secret

    def load(self) -> CollectorSecrets:
        return CollectorSecrets(
            credential_id=self._read("credential-id"),
            credential_secret=self._read("credential-secret"),
            access_client_id=self._read("access-client-id"),
            access_client_secret=self._read("access-client-secret"),
        )


class AgentAction(BaseModel):
    action_id: str = Field(min_length=1, max_length=128)
    action_type: str = Field(min_length=1, max_length=64)
    target_type: str = Field(min_length=1, max_length=32)
    target_id: str = Field(min_length=1, max_length=320)
    rationale: str = Field(min_length=1, max_length=2000)
    risk_level: str = Field(min_length=1, max_length=32)
    expires_at: datetime


class ActionBatch(BaseModel):
    actions: list[AgentAction] = Field(max_length=20)


class CollectorTransport(Protocol):
    def request(
        self,
        method: str,
        path: str,
        headers: Mapping[str, str],
        body: bytes,
        timeout_seconds: float,
    ) -> tuple[int, bytes]:
        """Send one request to the configured fixed control-plane host."""


class FixedHostHttpsTransport:
    def __init__(self, host: str) -> None:
        self._host = host

    def request(
        self,
        method: str,
        path: str,
        headers: Mapping[str, str],
        body: bytes,
        timeout_seconds: float,
    ) -> tuple[int, bytes]:
        connection = http.client.HTTPSConnection(self._host, port=443, timeout=timeout_seconds)
        try:
            connection.request(method, path, body=body, headers=dict(headers))
            response = connection.getresponse()
            payload = response.read(2_000_001)
            if len(payload) > 2_000_000:
                raise CollectorError("control-plane response exceeds 2 MB")
            return response.status, payload
        finally:
            connection.close()


class SignedControlForgeClient:
    """Authenticate endpoint requests with a timestamped, nonce-bound HMAC."""

    _CREDENTIAL_ID = re.compile(r"^[0-9a-f-]{36}$", flags=re.IGNORECASE)
    _ACCESS_CLIENT_ID = re.compile(r"^[a-f0-9]{32}\.access$")
    _ACCESS_CLIENT_SECRET = re.compile(r"^[a-f0-9]{64}$")

    def __init__(
        self,
        definition: CollectorDefinition,
        credential_id: str,
        credential_secret: str,
        access_client_id: Optional[str] = None,
        access_client_secret: Optional[str] = None,
        transport: Optional[CollectorTransport] = None,
        timeout_seconds: float = 15.0,
    ) -> None:
        if self._CREDENTIAL_ID.fullmatch(credential_id) is None:
            raise ValueError("collector credential ID must be a UUID")
        if len(credential_secret) < 32:
            raise ValueError("collector credential secret is too short")
        if (access_client_id is None) != (access_client_secret is None):
            raise ValueError("Cloudflare Access client ID and secret must be provided together")
        if (
            access_client_id is not None
            and self._ACCESS_CLIENT_ID.fullmatch(access_client_id) is None
        ):
            raise ValueError("Cloudflare Access client ID is invalid")
        if (
            access_client_secret is not None
            and self._ACCESS_CLIENT_SECRET.fullmatch(access_client_secret) is None
        ):
            raise ValueError("Cloudflare Access client secret is invalid")
        self._definition = definition
        self._credential_id = credential_id
        self._credential_secret = credential_secret
        self._access_client_id = access_client_id
        self._access_client_secret = access_client_secret
        self._transport = transport or FixedHostHttpsTransport(definition.api_host)
        self._timeout_seconds = timeout_seconds

    def _request(self, method: str, path: str, payload: object) -> object:
        if not path.startswith("/v1/") or ".." in path:
            raise ValueError("collector request path is not allowlisted")
        body = (
            b""
            if method == "GET"
            else json.dumps(payload, separators=(",", ":"), sort_keys=True).encode()
        )
        timestamp = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
        nonce = uuid.uuid4().hex
        request_path = path.partition("?")[0]
        body_hash = hashlib.sha256(body).hexdigest()
        canonical = "\n".join([method, request_path, timestamp, nonce, body_hash]).encode()
        signature = hmac.new(
            self._credential_secret.encode(), canonical, hashlib.sha256
        ).hexdigest()
        headers = {
            "accept": "application/json",
            "content-type": "application/json",
            "user-agent": "ControlForge-Endpoint-Agent/0.3",
            "x-controlforge-credential-id": self._credential_id,
            "x-controlforge-timestamp": timestamp,
            "x-controlforge-nonce": nonce,
            "x-controlforge-signature": signature,
        }
        if self._access_client_id is not None and self._access_client_secret is not None:
            headers["cf-access-client-id"] = self._access_client_id
            headers["cf-access-client-secret"] = self._access_client_secret
        status, response_payload = self._transport.request(
            method,
            path,
            headers,
            body,
            self._timeout_seconds,
        )
        if status < 200 or status >= 300:
            raise CollectorError(f"control-plane request failed with HTTP {status}")
        try:
            return json.loads(response_payload)
        except (json.JSONDecodeError, UnicodeDecodeError) as exc:
            raise CollectorError("control-plane returned malformed JSON") from exc

    def ingest(self, events: list[SecurityEvent]) -> None:
        self._request(
            "POST",
            "/v1/ingest/events",
            {"events": [event.model_dump(mode="json", exclude_none=True) for event in events]},
        )

    def pending_actions(self) -> list[AgentAction]:
        raw = self._request("GET", f"/v1/agent/actions?device_id={self._definition.device_id}", {})
        return ActionBatch.model_validate(raw).actions

    def submit_action_result(
        self,
        action_id: str,
        succeeded: bool,
        summary: str,
        evidence: list[str],
    ) -> None:
        self._request(
            "POST",
            f"/v1/agent/actions/{action_id}/result",
            {
                "status": "succeeded" if succeeded else "failed",
                "summary": summary,
                "evidence": evidence,
            },
        )


class AgentSpool:
    """SQLite-backed at-least-once buffer that never persists credentials."""

    def __init__(self, path: Path) -> None:
        self._path = path
        with self._connect() as connection:
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS outbound_batches (
                    batch_id TEXT PRIMARY KEY,
                    payload_json TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    attempts INTEGER NOT NULL DEFAULT 0,
                    last_error TEXT
                )
                """
            )
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS source_cursors (
                    source_id TEXT PRIMARY KEY,
                    device INTEGER NOT NULL,
                    inode INTEGER NOT NULL,
                    byte_offset INTEGER NOT NULL,
                    updated_at TEXT NOT NULL
                )
                """
            )

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self._path)
        connection.row_factory = sqlite3.Row
        return connection

    def enqueue(self, events: list[SecurityEvent]) -> str:
        batch_id = str(uuid.uuid4())
        payload = json.dumps([event.model_dump(mode="json") for event in events])
        with self._connect() as connection:
            connection.execute(
                "INSERT INTO outbound_batches(batch_id, payload_json, created_at) VALUES (?, ?, ?)",
                (batch_id, payload, datetime.now(timezone.utc).isoformat()),
            )
        return batch_id

    def pending(self, limit: int = 10) -> list[tuple[str, list[SecurityEvent]]]:
        if limit < 1 or limit > 100:
            raise ValueError("spool limit must be between 1 and 100")
        with self._connect() as connection:
            rows = connection.execute(
                "SELECT batch_id, payload_json FROM outbound_batches ORDER BY created_at LIMIT ?",
                (limit,),
            ).fetchall()
        return [
            (
                row["batch_id"],
                [SecurityEvent.model_validate(item) for item in json.loads(row["payload_json"])],
            )
            for row in rows
        ]

    def acknowledge(self, batch_id: str) -> None:
        with self._connect() as connection:
            connection.execute("DELETE FROM outbound_batches WHERE batch_id = ?", (batch_id,))

    def fail(self, batch_id: str, error: str) -> None:
        with self._connect() as connection:
            connection.execute(
                """
                UPDATE outbound_batches
                   SET attempts = attempts + 1, last_error = ?
                 WHERE batch_id = ?
                """,
                (error[:500], batch_id),
            )

    def source_cursor(self, source_id: str) -> Optional[SourceCursor]:
        with self._connect() as connection:
            row = connection.execute(
                "SELECT device, inode, byte_offset FROM source_cursors WHERE source_id = ?",
                (source_id,),
            ).fetchone()
        if row is None:
            return None
        return SourceCursor(
            device=int(row["device"]),
            inode=int(row["inode"]),
            byte_offset=int(row["byte_offset"]),
        )

    def save_source_cursor(self, source_id: str, cursor: SourceCursor) -> None:
        with self._connect() as connection:
            connection.execute(
                """
                INSERT INTO source_cursors(source_id, device, inode, byte_offset, updated_at)
                VALUES (?, ?, ?, ?, ?)
                ON CONFLICT(source_id) DO UPDATE SET
                    device = excluded.device,
                    inode = excluded.inode,
                    byte_offset = excluded.byte_offset,
                    updated_at = excluded.updated_at
                """,
                (
                    source_id,
                    cursor.device,
                    cursor.inode,
                    cursor.byte_offset,
                    datetime.now(timezone.utc).isoformat(),
                ),
            )


class EndpointCollectorAgent:
    """Collect endpoint control evidence and process allowlisted structured actions."""

    def __init__(
        self,
        definition: CollectorDefinition,
        client: SignedControlForgeClient,
        spool: Optional[AgentSpool] = None,
        santa_reader: Optional[SantaJsonLogReader] = None,
    ) -> None:
        self._definition = definition
        self._client = client
        self._spool = spool or AgentSpool(definition.spool_path)
        self._santa_reader = santa_reader
        if self._santa_reader is None and definition.santa.enabled:
            self._santa_reader = SantaJsonLogReader(definition.santa, definition.device_id)

    def _control_report(self) -> ControlReport:
        config = load_control_config(self._definition.controls_path)
        return EndpointAssuranceEngine(config.agents, LocalSystemProbe()).run()

    def _control_events(self, report: ControlReport) -> list[SecurityEvent]:
        return [
            SecurityEvent(
                event_id=str(uuid.uuid4()),
                event_type="endpoint_control_status",
                timestamp=finding.checked_at,
                actor=f"device:{self._definition.device_id}",
                target=finding.agent_id,
                device_id=self._definition.device_id,
                attributes={
                    "status": finding.status.value,
                    "installed": finding.installed,
                    "running": finding.running,
                    "heartbeat_age_seconds": finding.heartbeat_age_seconds,
                    "evidence": finding.evidence,
                    "recommended_action": finding.recommended_action,
                    "hostname": report.hostname,
                    "platform": report.platform,
                },
            )
            for finding in report.findings
        ]

    def _flush(self) -> tuple[int, int]:
        delivered = 0
        for batch_id, events in self._spool.pending():
            try:
                self._client.ingest(events)
            except CollectorError as exc:
                self._spool.fail(batch_id, str(exc))
                break
            self._spool.acknowledge(batch_id)
            delivered += 1
        return delivered, len(self._spool.pending(limit=100))

    def _handle_action(self, action: AgentAction, report: ControlReport) -> None:
        if action.action_type != "collect_diagnostics" or action.risk_level != "read_only":
            self._client.submit_action_result(
                action.action_id,
                False,
                "Endpoint action adapter is not installed; no active change was performed.",
                ["fail-closed structured-action boundary"],
            )
            return
        evidence = [
            f"{finding.agent_id}:{finding.status.value}:running={finding.running}"
            for finding in report.findings
        ]
        self._client.submit_action_result(
            action.action_id,
            True,
            "Read-only endpoint control diagnostics collected.",
            evidence,
        )

    def run_once(self) -> dict[str, int]:
        report = self._control_report()
        events = self._control_events(report)
        santa_events_collected = 0
        santa_lines_rejected = 0
        santa_cursor: Optional[tuple[str, SourceCursor]] = None
        if self._santa_reader is not None:
            try:
                santa_batch = self._santa_reader.read(
                    self._spool.source_cursor(self._santa_reader.source_id)
                )
            except SantaLogError:
                santa_lines_rejected = 1
            else:
                events.extend(santa_batch.events)
                santa_events_collected = len(santa_batch.events)
                santa_lines_rejected = santa_batch.rejected_lines
                santa_cursor = (self._santa_reader.source_id, santa_batch.cursor)
        self._spool.enqueue(events)
        if santa_cursor is not None:
            self._spool.save_source_cursor(*santa_cursor)
        batches_delivered, batches_pending = self._flush()
        actions = self._client.pending_actions()
        for action in actions:
            self._handle_action(action, report)
        return {
            "events_collected": len(events),
            "batches_delivered": batches_delivered,
            "batches_pending": batches_pending,
            "actions_processed": len(actions),
            "santa_events_collected": santa_events_collected,
            "santa_lines_rejected": santa_lines_rejected,
        }
