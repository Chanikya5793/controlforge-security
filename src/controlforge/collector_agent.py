"""Signed endpoint collector with durable delivery and structured action handling."""

from __future__ import annotations

import hashlib
import hmac
import http.client
import json
import os
import platform
import re
import sqlite3
import subprocess  # nosec B404 -- fixed signed ControlForge helper only
import tempfile
import uuid
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Literal, Optional, Protocol

import yaml
from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from . import __version__
from .config import load_control_config
from .controls import EndpointAssuranceEngine
from .credential_rotation import (
    CredentialRotationEnvelope,
    CredentialRotationMaterial,
    decrypt_rotation_envelope,
)
from .macos_response import (
    MacOSContainmentStatus,
    MacOSPfResponseAdapter,
    MacOSReconciliationEvent,
    MacOSResponseAction,
    MacOSResponseAdapter,
    MacOSResponseError,
)
from .models import ControlReport, SecurityEvent
from .probes import LocalSystemProbe
from .santa import SantaJsonLogReader, SantaLogDefinition, SantaLogError, SourceCursor


class CollectorError(RuntimeError):
    """Raised when the collector cannot complete a signed control-plane request."""


class CollectorDefinition(BaseModel):
    """Non-secret, version-controlled endpoint collector configuration."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    api_host: str = Field(
        min_length=4,
        max_length=253,
        pattern=(
            r"^(?:localhost|"
            r"(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63})$"
        ),
    )
    api_port: int = Field(default=443, ge=1, le=65_535)
    device_id: str = Field(min_length=1, max_length=128, pattern=r"^[A-Za-z0-9._:-]+$")
    controls_path: Path = Path("config/agents.yml")
    spool_path: Path = Path("controlforge-agent-spool.db")
    status_snapshot_path: Optional[Path] = None
    santa: SantaLogDefinition = Field(default_factory=SantaLogDefinition)
    credential_source: Literal["environment", "macos_system_keychain"] = "environment"
    access_proxy_required: bool = True
    action_polling_enabled: bool = True
    credential_rotation_enabled: bool = False
    response_adapter_enabled: bool = False
    response_state_path: Path = Path(
        "/Library/Application Support/ControlForge/response/pf-state.json"
    )
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

    def load(self, *, require_access: bool = True) -> CollectorSecrets:
        return CollectorSecrets(
            credential_id=self._read("credential-id"),
            credential_secret=self._read("credential-secret"),
            access_client_id=self._read("access-client-id") if require_access else None,
            access_client_secret=self._read("access-client-secret") if require_access else None,
        )

    def store_initial(self, credential_id: str, credential_secret: str) -> None:
        """Atomically provision a new standalone collector credential pair."""

        if platform.system() != "Darwin":
            raise ValueError("macOS System keychain secret source requires macOS")
        if SignedControlForgeClient._CREDENTIAL_ID.fullmatch(credential_id) is None:
            raise ValueError("collector credential ID must be a UUID")
        if len(credential_secret) < 32:
            raise ValueError("collector credential secret is too short")
        payload = bytearray(
            json.dumps(
                {
                    "credential-id": credential_id,
                    "credential-secret": credential_secret,
                },
                separators=(",", ":"),
                sort_keys=True,
            ).encode()
        )
        try:
            subprocess.run(  # noqa: S603  # nosec B603
                [self._READER, "keychain-import-pair"],
                input=bytes(payload),
                check=True,
                capture_output=True,
                timeout=10,
            )
        except (OSError, subprocess.CalledProcessError, subprocess.TimeoutExpired) as exc:
            raise ValueError("collector credential pair could not be stored") from exc
        finally:
            for index in range(len(payload)):
                payload[index] = 0

    def require_initial_empty(self) -> None:
        """Refuse enrollment before a one-use grant is consumed if credentials exist."""

        if platform.system() != "Darwin":
            raise ValueError("macOS System keychain secret source requires macOS")
        try:
            subprocess.run(  # noqa: S603  # nosec B603
                [self._READER, "keychain-require-empty"],
                check=True,
                capture_output=True,
                timeout=5,
            )
        except (OSError, subprocess.CalledProcessError, subprocess.TimeoutExpired) as exc:
            raise ValueError(
                "collector credentials already exist or Keychain preflight failed"
            ) from exc

    def replace_pair(
        self,
        expected_credential_id: str,
        credential_id: str,
        credential_secret: str,
    ) -> None:
        """Atomically replace the effective credential pair after binding validation."""

        if platform.system() != "Darwin":
            raise ValueError("macOS System keychain secret source requires macOS")
        if (
            SignedControlForgeClient._CREDENTIAL_ID.fullmatch(expected_credential_id) is None
            or SignedControlForgeClient._CREDENTIAL_ID.fullmatch(credential_id) is None
        ):
            raise ValueError("collector credential ID must be a UUID")
        if len(credential_secret) < 32:
            raise ValueError("collector credential secret is too short")
        payload = bytearray(
            json.dumps(
                {
                    "expected-credential-id": expected_credential_id,
                    "credential-id": credential_id,
                    "credential-secret": credential_secret,
                },
                separators=(",", ":"),
                sort_keys=True,
            ).encode()
        )
        try:
            subprocess.run(  # noqa: S603  # nosec B603
                [self._READER, "keychain-replace-pair"],
                input=bytes(payload),
                check=True,
                capture_output=True,
                timeout=10,
            )
        except (OSError, subprocess.CalledProcessError, subprocess.TimeoutExpired) as exc:
            raise ValueError("collector credential pair could not be rotated") from exc
        finally:
            for index in range(len(payload)):
                payload[index] = 0


class CredentialPairStore(Protocol):
    def replace_pair(
        self,
        expected_credential_id: str,
        credential_id: str,
        credential_secret: str,
    ) -> None:
        """Atomically replace one device-bound credential pair."""


class AgentAction(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    action_id: str = Field(
        min_length=36,
        max_length=36,
        pattern=r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-"
        r"[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$",
    )
    action_type: Literal["collect_diagnostics", "isolate_endpoint", "release_endpoint"]
    target_type: Literal["device"]
    target_id: str = Field(min_length=1, max_length=128, pattern=r"^[A-Za-z0-9._:-]+$")
    rationale: str = Field(min_length=1, max_length=2000)
    risk_level: Literal["read_only", "active"]
    expires_at: datetime

    @field_validator("expires_at")
    @classmethod
    def require_timezone(cls, value: datetime) -> datetime:
        if value.tzinfo is None:
            raise ValueError("action expiry must be timezone-aware")
        return value.astimezone(timezone.utc)

    @model_validator(mode="after")
    def validate_risk(self) -> AgentAction:
        expected = "read_only" if self.action_type == "collect_diagnostics" else "active"
        if self.risk_level != expected:
            raise ValueError("action type and risk level do not match")
        return self


class ActionBatch(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    actions: list[AgentAction] = Field(max_length=20)


class CredentialRotationPoll(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    rotation: Optional[CredentialRotationEnvelope]


_RESPONSE_FAILURES: dict[str, tuple[str, str]] = {
    "action_expired": (
        "Active response authorization expired; no change was performed.",
        "expired",
    ),
    "adapter_disabled": (
        "Endpoint response adapter is disabled; no change was performed.",
        "disabled",
    ),
    "management_resolution_failed": (
        "Management host resolution failed; no containment was applied.",
        "management-unreachable",
    ),
    "release_failed": (
        "Endpoint containment release did not complete; local state was retained.",
        "release-failed",
    ),
    "root_required": ("Endpoint response requires the root launch daemon.", "root-required"),
    "state_malformed": (
        "Endpoint response state is malformed; no change was performed.",
        "state-invalid",
    ),
    "state_unsafe": (
        "Endpoint response state permissions are unsafe; no change was performed.",
        "state-invalid",
    ),
    "state_unavailable": (
        "Endpoint response state is unavailable; no change was performed.",
        "state-unavailable",
    ),
    "target_mismatch": (
        "Active response targeted another endpoint; no change was performed.",
        "target-mismatch",
    ),
    "unsupported_platform": ("Endpoint response is supported only on macOS.", "platform-rejected"),
}


def _response_failure_summary(code: str) -> str:
    return _RESPONSE_FAILURES.get(
        code,
        ("Endpoint response failed closed; no successful change was reported.", "failed-closed"),
    )[0]


def _response_failure_evidence(code: str) -> str:
    return _RESPONSE_FAILURES.get(
        code,
        ("Endpoint response failed closed; no successful change was reported.", "failed-closed"),
    )[1]


class AgentControlStatusSummary(BaseModel):
    """Non-sensitive aggregate control state exposed to a local user application."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    evaluated: bool
    total: int = Field(ge=0, le=10_000)
    failed: int = Field(ge=0, le=10_000)

    @model_validator(mode="after")
    def validate_counts(self) -> AgentControlStatusSummary:
        if self.failed > self.total:
            raise ValueError("failed control count cannot exceed total control count")
        if not self.evaluated and (self.total != 0 or self.failed != 0):
            raise ValueError("unevaluated control status must not contain counts")
        return self


class AgentDeliveryStatusSummary(BaseModel):
    """Bounded delivery counters with explicit lower-bound semantics."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    status: Literal["not_attempted", "succeeded", "backlogged", "failed"]
    batches_delivered: int = Field(ge=0, le=100)
    batches_pending: int = Field(ge=0, le=100)
    batches_pending_is_lower_bound: bool

    @model_validator(mode="after")
    def validate_delivery_state(self) -> AgentDeliveryStatusSummary:
        if self.batches_pending_is_lower_bound and self.batches_pending != 100:
            raise ValueError("pending lower bound is valid only at the reporting cap")
        if self.status == "succeeded" and self.batches_pending != 0:
            raise ValueError("succeeded delivery cannot retain pending batches")
        if self.status == "backlogged" and self.batches_pending == 0:
            raise ValueError("backlogged delivery requires a pending batch")
        if self.status == "not_attempted" and self.batches_delivered != 0:
            raise ValueError("unattempted delivery cannot report delivered batches")
        return self


class AgentTelemetryStatusSummary(BaseModel):
    """Aggregate collection counts that contain no raw telemetry."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    events_collected: int = Field(ge=0, le=10_000)
    santa_events_collected: int = Field(ge=0, le=10_000)
    santa_lines_rejected: int = Field(ge=0, le=10_000)

    @model_validator(mode="after")
    def validate_counts(self) -> AgentTelemetryStatusSummary:
        if self.santa_events_collected > self.events_collected:
            raise ValueError("Santa event count cannot exceed total collected events")
        return self


class AgentContainmentStatusSummary(BaseModel):
    """Enum-only endpoint containment posture safe for an unprivileged user app."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    state: Literal["not_configured", "released", "isolated", "needs_attention"]
    expires_at: Optional[datetime] = None

    @field_validator("expires_at")
    @classmethod
    def require_timezone(cls, value: Optional[datetime]) -> Optional[datetime]:
        if value is None:
            return None
        if value.tzinfo is None:
            raise ValueError("containment expiry must be timezone-aware")
        return value.astimezone(timezone.utc)

    @model_validator(mode="after")
    def validate_state(self) -> AgentContainmentStatusSummary:
        if (self.state == "isolated") != (self.expires_at is not None):
            raise ValueError("only isolated containment must include an expiry")
        return self


class AgentStatusSnapshot(BaseModel):
    """Strict redacted contract consumed by the unprivileged local dashboard."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    schema_version: Literal["controlforge-agent-status-v2"] = "controlforge-agent-status-v2"
    generated_at: datetime
    device_id: str = Field(min_length=1, max_length=128, pattern=r"^[A-Za-z0-9._:-]+$")
    agent_version: str = Field(min_length=1, max_length=64)
    run_status: Literal["completed", "failed"]
    failure_stage: Optional[
        Literal[
            "credential_rotation",
            "control_collection",
            "telemetry_collection",
            "delivery",
            "action_polling",
        ]
    ] = None
    controls: AgentControlStatusSummary
    delivery: AgentDeliveryStatusSummary
    telemetry: AgentTelemetryStatusSummary
    containment: AgentContainmentStatusSummary = Field(
        default_factory=lambda: AgentContainmentStatusSummary(state="not_configured")
    )
    actions_processed: int = Field(ge=0, le=20)

    @field_validator("generated_at")
    @classmethod
    def require_timezone(cls, value: datetime) -> datetime:
        if value.tzinfo is None:
            raise ValueError("status generation time must be timezone-aware")
        return value.astimezone(timezone.utc)

    @model_validator(mode="after")
    def validate_run_status(self) -> AgentStatusSnapshot:
        if (self.run_status == "failed") != (self.failure_stage is not None):
            raise ValueError("failure_stage must be present exactly when the run failed")
        return self


class AgentStatusSnapshotStore:
    """Atomically replace the root-written, redacted local status snapshot."""

    def __init__(self, path: Path) -> None:
        self._path = path

    def write(self, snapshot: AgentStatusSnapshot) -> None:
        self._path.parent.mkdir(mode=0o755, parents=True, exist_ok=True)
        descriptor, temporary_name = tempfile.mkstemp(
            dir=self._path.parent,
            prefix=f".{self._path.name}.",
        )
        temporary_path = Path(temporary_name)
        try:
            with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
                stream.write(snapshot.model_dump_json(indent=2))
                stream.write("\n")
                stream.flush()
                os.fsync(stream.fileno())
            temporary_path.chmod(0o644)
            os.replace(temporary_path, self._path)
        finally:
            temporary_path.unlink(missing_ok=True)


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
    def __init__(self, host: str, port: int = 443) -> None:
        self._host = host
        self._port = port

    def request(
        self,
        method: str,
        path: str,
        headers: Mapping[str, str],
        body: bytes,
        timeout_seconds: float,
    ) -> tuple[int, bytes]:
        connection = http.client.HTTPSConnection(
            self._host,
            port=self._port,
            timeout=timeout_seconds,
        )
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
        self._transport = transport or FixedHostHttpsTransport(
            definition.api_host,
            definition.api_port,
        )
        self._timeout_seconds = timeout_seconds

    @property
    def credential_id(self) -> str:
        return self._credential_id

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

    def pending_credential_rotation(self) -> Optional[CredentialRotationEnvelope]:
        raw = self._request(
            "GET",
            f"/v1/agent/credential-rotation?device_id={self._definition.device_id}",
            {},
        )
        return CredentialRotationPoll.model_validate(raw).rotation

    def decrypt_credential_rotation(
        self,
        envelope: CredentialRotationEnvelope,
        now: datetime,
    ) -> CredentialRotationMaterial:
        return decrypt_rotation_envelope(
            envelope,
            self._credential_secret.encode(),
            expected_device_id=self._definition.device_id,
            expected_credential_id=self._credential_id,
            now=now,
        )

    def with_credentials(
        self,
        credential_id: str,
        credential_secret: str,
    ) -> SignedControlForgeClient:
        return SignedControlForgeClient(
            self._definition,
            credential_id,
            credential_secret,
            self._access_client_id,
            self._access_client_secret,
            self._transport,
            self._timeout_seconds,
        )

    def acknowledge_credential_rotation(self) -> None:
        self._request("POST", "/v1/agent/credential-rotation/ack", {})

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
                CREATE TABLE IF NOT EXISTS pending_credential_rotation (
                    singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
                    rotation_id TEXT NOT NULL,
                    predecessor_credential_id TEXT NOT NULL,
                    replacement_credential_id TEXT NOT NULL,
                    recorded_at TEXT NOT NULL
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

    def pending_summary(self, cap: int = 100) -> tuple[int, bool]:
        """Return a bounded count and whether that count is only a lower bound."""

        if cap < 1 or cap > 100:
            raise ValueError("spool count cap must be between 1 and 100")
        with self._connect() as connection:
            row = connection.execute(
                "SELECT COUNT(*) AS count FROM "
                "(SELECT 1 FROM outbound_batches ORDER BY created_at LIMIT ?)",
                (cap + 1,),
            ).fetchone()
        observed = int(row["count"])
        return min(observed, cap), observed > cap

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

    def pending_credential_rotation(self) -> Optional[tuple[str, str, str]]:
        with self._connect() as connection:
            row = connection.execute(
                """
                SELECT rotation_id, predecessor_credential_id, replacement_credential_id
                FROM pending_credential_rotation WHERE singleton = 1
                """
            ).fetchone()
        if row is None:
            return None
        return (
            str(row["rotation_id"]),
            str(row["predecessor_credential_id"]),
            str(row["replacement_credential_id"]),
        )

    def record_credential_rotation(self, material: CredentialRotationMaterial) -> None:
        with self._connect() as connection:
            connection.execute(
                """
                INSERT INTO pending_credential_rotation(
                    singleton, rotation_id, predecessor_credential_id,
                    replacement_credential_id, recorded_at
                ) VALUES (1, ?, ?, ?, ?)
                ON CONFLICT(singleton) DO UPDATE SET
                    rotation_id = excluded.rotation_id,
                    predecessor_credential_id = excluded.predecessor_credential_id,
                    replacement_credential_id = excluded.replacement_credential_id,
                    recorded_at = excluded.recorded_at
                """,
                (
                    material.rotation_id,
                    material.predecessor_credential_id,
                    material.replacement_credential_id,
                    datetime.now(timezone.utc).isoformat(),
                ),
            )

    def clear_credential_rotation(self, rotation_id: str) -> None:
        with self._connect() as connection:
            connection.execute(
                """
                DELETE FROM pending_credential_rotation
                WHERE singleton = 1 AND rotation_id = ?
                """,
                (rotation_id,),
            )


class EndpointCollectorAgent:
    """Collect endpoint control evidence and process allowlisted structured actions."""

    def __init__(
        self,
        definition: CollectorDefinition,
        client: SignedControlForgeClient,
        spool: Optional[AgentSpool] = None,
        santa_reader: Optional[SantaJsonLogReader] = None,
        status_store: Optional[AgentStatusSnapshotStore] = None,
        response_adapter: Optional[MacOSResponseAdapter] = None,
        credential_pair_store: Optional[CredentialPairStore] = None,
    ) -> None:
        self._definition = definition
        self._client = client
        self._spool = spool or AgentSpool(definition.spool_path)
        self._status_store = status_store
        if self._status_store is None and definition.status_snapshot_path is not None:
            self._status_store = AgentStatusSnapshotStore(definition.status_snapshot_path)
        self._santa_reader = santa_reader
        if self._santa_reader is None and definition.santa.enabled:
            self._santa_reader = SantaJsonLogReader(definition.santa, definition.device_id)
        self._response_adapter = response_adapter
        self._credential_pair_store = credential_pair_store
        try:
            response_state_exists = (
                definition.response_state_path.exists()
                or definition.response_state_path.is_symlink()
            )
        except OSError:
            # A non-root interactive collector cannot inspect the root-only state
            # directory. The production launch daemon runs as root and can reconcile it.
            response_state_exists = False
        if self._response_adapter is None and (
            definition.response_adapter_enabled or response_state_exists
        ):
            self._response_adapter = MacOSPfResponseAdapter(
                enabled=definition.response_adapter_enabled,
                device_id=definition.device_id,
                api_host=definition.api_host,
                api_port=definition.api_port,
                state_path=definition.response_state_path,
            )

    def _handle_credential_rotation(self) -> bool:
        if not self._definition.credential_rotation_enabled or self._credential_pair_store is None:
            return False
        pending = self._spool.pending_credential_rotation()
        if pending is not None and self._client.credential_id == pending[2]:
            self._client.acknowledge_credential_rotation()
            self._spool.clear_credential_rotation(pending[0])
            return True
        envelope = self._client.pending_credential_rotation()
        if envelope is None:
            return False
        material = self._client.decrypt_credential_rotation(
            envelope,
            datetime.now(timezone.utc),
        )
        if pending is not None and pending != (
            material.rotation_id,
            material.predecessor_credential_id,
            material.replacement_credential_id,
        ):
            raise CollectorError("credential rotation state conflicts with control plane")
        self._spool.record_credential_rotation(material)
        self._credential_pair_store.replace_pair(
            material.predecessor_credential_id,
            material.replacement_credential_id,
            material.replacement_secret,
        )
        replacement_client = self._client.with_credentials(
            material.replacement_credential_id,
            material.replacement_secret,
        )
        replacement_client.acknowledge_credential_rotation()
        self._client = replacement_client
        self._spool.clear_credential_rotation(material.rotation_id)
        return True

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

    def _flush(self) -> tuple[int, int, bool, bool]:
        delivered = 0
        delivery_failed = False
        for batch_id, events in self._spool.pending():
            try:
                self._client.ingest(events)
            except CollectorError as exc:
                self._spool.fail(batch_id, str(exc))
                delivery_failed = True
                break
            self._spool.acknowledge(batch_id)
            delivered += 1
        pending, pending_is_lower_bound = self._spool.pending_summary()
        return delivered, pending, pending_is_lower_bound, delivery_failed

    def _handle_action(self, action: AgentAction, report: ControlReport) -> None:
        if action.target_id != self._definition.device_id or action.expires_at <= datetime.now(
            timezone.utc
        ):
            self._client.submit_action_result(
                action.action_id,
                False,
                "Action was expired or targeted another endpoint; no active change was performed.",
                ["endpoint-action:rejected"],
            )
            return
        if action.action_type == "collect_diagnostics":
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
            return
        if self._response_adapter is None:
            self._client.submit_action_result(
                action.action_id,
                False,
                "Endpoint response adapter is disabled; no active change was performed.",
                ["macos-pf-adapter:disabled"],
            )
            return
        try:
            result = self._response_adapter.execute(
                MacOSResponseAction.model_validate(action.model_dump())
            )
        except MacOSResponseError as exc:
            self._client.submit_action_result(
                action.action_id,
                False,
                _response_failure_summary(exc.code),
                [f"macos-pf-adapter:{_response_failure_evidence(exc.code)}"],
            )
            return
        self._client.submit_action_result(
            action.action_id,
            result.succeeded,
            result.summary,
            list(result.evidence),
        )

    def _reconciliation_event(
        self,
        transition: MacOSReconciliationEvent,
    ) -> SecurityEvent:
        return SecurityEvent(
            event_id=str(uuid.uuid4()),
            event_type="endpoint_containment_state",
            timestamp=transition.occurred_at,
            actor=f"device:{self._definition.device_id}",
            device_id=self._definition.device_id,
            attributes={
                "state": transition.state,
                "reason": transition.reason,
                "adapter": "macos_pf",
            },
        )

    def _containment_status(self) -> AgentContainmentStatusSummary:
        if self._response_adapter is None:
            return AgentContainmentStatusSummary(state="not_configured")
        status: MacOSContainmentStatus = self._response_adapter.containment_status()
        return AgentContainmentStatusSummary(
            state=status.state,
            expires_at=status.expires_at,
        )

    def _write_status(
        self,
        *,
        run_status: Literal["completed", "failed"],
        failure_stage: Optional[
            Literal[
                "credential_rotation",
                "control_collection",
                "telemetry_collection",
                "delivery",
                "action_polling",
            ]
        ],
        report: Optional[ControlReport],
        delivery_status: Literal["not_attempted", "succeeded", "backlogged", "failed"],
        batches_delivered: int,
        batches_pending: int,
        batches_pending_is_lower_bound: bool,
        events_collected: int,
        santa_events_collected: int,
        santa_lines_rejected: int,
        actions_processed: int,
    ) -> None:
        if self._status_store is None:
            return
        self._status_store.write(
            AgentStatusSnapshot(
                generated_at=datetime.now(timezone.utc),
                device_id=self._definition.device_id,
                agent_version=__version__,
                run_status=run_status,
                failure_stage=failure_stage,
                controls=AgentControlStatusSummary(
                    evaluated=report is not None,
                    total=len(report.findings) if report is not None else 0,
                    failed=report.failed_count if report is not None else 0,
                ),
                delivery=AgentDeliveryStatusSummary(
                    status=delivery_status,
                    batches_delivered=batches_delivered,
                    batches_pending=batches_pending,
                    batches_pending_is_lower_bound=batches_pending_is_lower_bound,
                ),
                telemetry=AgentTelemetryStatusSummary(
                    events_collected=events_collected,
                    santa_events_collected=santa_events_collected,
                    santa_lines_rejected=santa_lines_rejected,
                ),
                containment=self._containment_status(),
                actions_processed=actions_processed,
            )
        )

    def run_once(self) -> dict[str, int | bool]:
        report: Optional[ControlReport] = None
        failure_stage: Literal[
            "credential_rotation",
            "control_collection",
            "telemetry_collection",
            "delivery",
            "action_polling",
        ] = "credential_rotation"
        events: list[SecurityEvent] = []
        santa_events_collected = 0
        santa_lines_rejected = 0
        batches_delivered = 0
        batches_pending = 0
        batches_pending_is_lower_bound = False
        delivery_status: Literal["not_attempted", "succeeded", "backlogged", "failed"] = (
            "not_attempted"
        )
        actions_processed = 0
        reconciliation_events_collected = 0
        try:
            self._handle_credential_rotation()
            failure_stage = "control_collection"
            if self._response_adapter is not None:
                transition = self._response_adapter.reconcile()
                if transition is not None:
                    # Persist the transition before unrelated endpoint probes can fail.
                    # A successful automatic release deletes its PF state, so this event
                    # must already be durable before the collector continues.
                    self._spool.enqueue([self._reconciliation_event(transition)])
                    reconciliation_events_collected = 1
            report = self._control_report()
            events.extend(self._control_events(report))
            failure_stage = "telemetry_collection"
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
            failure_stage = "delivery"
            (
                batches_delivered,
                batches_pending,
                batches_pending_is_lower_bound,
                delivery_failed,
            ) = self._flush()
            if delivery_failed:
                delivery_status = "failed"
            elif batches_pending > 0:
                delivery_status = "backlogged"
            else:
                delivery_status = "succeeded"
            if self._definition.action_polling_enabled:
                failure_stage = "action_polling"
                actions = self._client.pending_actions()
                for action in actions:
                    self._handle_action(action, report)
                actions_processed = len(actions)
        except Exception:
            try:
                batches_pending, batches_pending_is_lower_bound = self._spool.pending_summary()
                self._write_status(
                    run_status="failed",
                    failure_stage=failure_stage,
                    report=report,
                    delivery_status=("failed" if failure_stage == "delivery" else delivery_status),
                    batches_delivered=batches_delivered,
                    batches_pending=batches_pending,
                    batches_pending_is_lower_bound=batches_pending_is_lower_bound,
                    events_collected=len(events) + reconciliation_events_collected,
                    santa_events_collected=santa_events_collected,
                    santa_lines_rejected=santa_lines_rejected,
                    actions_processed=actions_processed,
                )
            except OSError:
                pass
            raise

        self._write_status(
            run_status="completed",
            failure_stage=None,
            report=report,
            delivery_status=delivery_status,
            batches_delivered=batches_delivered,
            batches_pending=batches_pending,
            batches_pending_is_lower_bound=batches_pending_is_lower_bound,
            events_collected=len(events) + reconciliation_events_collected,
            santa_events_collected=santa_events_collected,
            santa_lines_rejected=santa_lines_rejected,
            actions_processed=actions_processed,
        )
        return {
            "events_collected": len(events) + reconciliation_events_collected,
            "batches_delivered": batches_delivered,
            "batches_pending": batches_pending,
            "batches_pending_is_lower_bound": batches_pending_is_lower_bound,
            "actions_processed": actions_processed,
            "santa_events_collected": santa_events_collected,
            "santa_lines_rejected": santa_lines_rejected,
        }
