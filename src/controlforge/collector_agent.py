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
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Callable, Literal, Optional, Protocol

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
from .models import ControlReport, ControlStatus, SecurityEvent
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
    control_snapshot_interval_seconds: int = Field(default=3600, ge=60, le=86_400)
    delivery_flush_batch_limit: int = Field(default=10, ge=1, le=100)
    retry_backoff_initial_seconds: int = Field(default=60, ge=1, le=3600)
    retry_backoff_max_seconds: int = Field(default=3600, ge=1, le=86_400)
    retry_backoff_jitter_ratio: float = Field(default=0.2, ge=0.0, le=0.5)
    response_adapter_enabled: bool = False
    response_state_path: Path = Path(
        "/Library/Application Support/ControlForge/response/pf-state.json"
    )
    keychain_service: str = Field(
        default="com.controlforge.collector",
        pattern=r"^[A-Za-z0-9.-]{3,128}$",
    )

    @model_validator(mode="after")
    def validate_retry_window(self) -> CollectorDefinition:
        if self.retry_backoff_max_seconds < self.retry_backoff_initial_seconds:
            raise ValueError("retry backoff maximum must not be below its initial delay")
        return self


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

    def enrollment_state(self) -> Literal["empty", "present"]:
        """Read fixed-account existence only; never request or return secret values."""
        if platform.system() != "Darwin" or self._service != "com.controlforge.collector.v2":
            raise ValueError("collector enrollment state requires the current macOS helper")
        try:
            result = subprocess.run(  # noqa: S603  # nosec B603
                [self._READER, "keychain-enrollment-state"],
                check=True,
                capture_output=True,
                timeout=5,
            )
        except (OSError, subprocess.CalledProcessError, subprocess.TimeoutExpired) as exc:
            raise ValueError("collector enrollment state is unavailable") from exc
        if result.stdout == b"empty\n":
            return "empty"
        if result.stdout == b"present\n":
            return "present"
        raise ValueError("collector enrollment state is invalid")

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
    degraded: int = Field(ge=0, le=10_000)
    missing: int = Field(ge=0, le=10_000)
    not_running: int = Field(ge=0, le=10_000)

    @model_validator(mode="after")
    def validate_counts(self) -> AgentControlStatusSummary:
        if self.failed > self.total:
            raise ValueError("failed control count cannot exceed total control count")
        if self.failed + self.degraded > self.total:
            raise ValueError("failed and degraded counts cannot exceed total control count")
        if self.missing + self.not_running > self.failed:
            raise ValueError("missing and stopped counts cannot exceed failed control count")
        if not self.evaluated and any(
            (self.total, self.failed, self.degraded, self.missing, self.not_running)
        ):
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

    schema_version: Literal["controlforge-agent-status-v3"] = "controlforge-agent-status-v3"
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


RetryOperation = Literal["delivery", "action_polling"]


@dataclass(frozen=True)
class OperationRetryState:
    """Durable, non-secret circuit state for one control-plane operation."""

    consecutive_failures: int
    retry_after: datetime


@dataclass(frozen=True)
class DeliveryAttempt:
    """One bounded spool flush without exposing a provider response."""

    delivered: int
    pending: int
    pending_is_lower_bound: bool
    failed: bool
    deferred: bool


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
        try:
            status, response_payload = self._transport.request(
                method,
                path,
                headers,
                body,
                self._timeout_seconds,
            )
        except (OSError, TimeoutError, http.client.HTTPException) as exc:
            raise CollectorError("control-plane request could not be completed") from exc
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
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS operation_retry_state (
                    operation TEXT PRIMARY KEY,
                    consecutive_failures INTEGER NOT NULL,
                    retry_after TEXT NOT NULL,
                    updated_at TEXT NOT NULL
                )
                """
            )
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS control_snapshot_state (
                    singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
                    fingerprint TEXT NOT NULL,
                    pending_batch_id TEXT,
                    last_enqueued_at TEXT NOT NULL
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

    def enqueue_collected(
        self,
        control_events: list[SecurityEvent],
        telemetry_events: list[SecurityEvent],
        *,
        control_fingerprint: str,
        control_snapshot_interval_seconds: int,
        now: datetime,
    ) -> tuple[Optional[str], bool]:
        """Durably enqueue telemetry and only a due or changed control snapshot.

        Raw telemetry is never coalesced. An unchanged control snapshot is omitted while
        its latest batch remains pending, then emitted periodically only after the latest
        snapshot was acknowledged.
        """

        if now.tzinfo is None:
            raise ValueError("collector spool time must be timezone-aware")
        if control_snapshot_interval_seconds < 60 or control_snapshot_interval_seconds > 86_400:
            raise ValueError("control snapshot interval must be between 60 and 86400 seconds")
        now = now.astimezone(timezone.utc)
        batch_id = str(uuid.uuid4())
        with self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            row = connection.execute(
                """
                SELECT fingerprint, pending_batch_id, last_enqueued_at
                FROM control_snapshot_state WHERE singleton = 1
                """
            ).fetchone()
            control_due = row is None or str(row["fingerprint"]) != control_fingerprint
            if row is not None and not control_due:
                pending_batch_id = row["pending_batch_id"]
                pending_exists = False
                if pending_batch_id is not None:
                    pending_exists = (
                        connection.execute(
                            "SELECT 1 FROM outbound_batches WHERE batch_id = ?",
                            (str(pending_batch_id),),
                        ).fetchone()
                        is not None
                    )
                last_enqueued_at = datetime.fromisoformat(str(row["last_enqueued_at"]))
                if last_enqueued_at.tzinfo is None:
                    raise ValueError("stored control snapshot time must be timezone-aware")
                control_due = not pending_exists and now >= last_enqueued_at + timedelta(
                    seconds=control_snapshot_interval_seconds
                )

            selected_events = (
                [*control_events, *telemetry_events] if control_due else telemetry_events
            )
            if not selected_events:
                return None, False
            payload = json.dumps([event.model_dump(mode="json") for event in selected_events])
            connection.execute(
                "INSERT INTO outbound_batches(batch_id, payload_json, created_at) VALUES (?, ?, ?)",
                (batch_id, payload, now.isoformat()),
            )
            if control_due:
                connection.execute(
                    """
                    INSERT INTO control_snapshot_state(
                        singleton, fingerprint, pending_batch_id, last_enqueued_at
                    ) VALUES (1, ?, ?, ?)
                    ON CONFLICT(singleton) DO UPDATE SET
                        fingerprint = excluded.fingerprint,
                        pending_batch_id = excluded.pending_batch_id,
                        last_enqueued_at = excluded.last_enqueued_at
                    """,
                    (control_fingerprint, batch_id, now.isoformat()),
                )
        return batch_id, control_due

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
            connection.execute("BEGIN IMMEDIATE")
            connection.execute(
                """
                UPDATE control_snapshot_state SET pending_batch_id = NULL
                WHERE singleton = 1 AND pending_batch_id = ?
                """,
                (batch_id,),
            )
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

    @staticmethod
    def _validate_retry_operation(operation: RetryOperation) -> None:
        if operation not in {"delivery", "action_polling"}:
            raise ValueError("invalid collector retry operation")

    def retry_state(self, operation: RetryOperation) -> Optional[OperationRetryState]:
        self._validate_retry_operation(operation)
        with self._connect() as connection:
            row = connection.execute(
                """
                SELECT consecutive_failures, retry_after
                FROM operation_retry_state WHERE operation = ?
                """,
                (operation,),
            ).fetchone()
        if row is None:
            return None
        retry_after = datetime.fromisoformat(str(row["retry_after"]))
        if retry_after.tzinfo is None:
            raise ValueError("stored retry time must be timezone-aware")
        return OperationRetryState(
            consecutive_failures=int(row["consecutive_failures"]),
            retry_after=retry_after.astimezone(timezone.utc),
        )

    def retry_ready(self, operation: RetryOperation, now: datetime) -> bool:
        if now.tzinfo is None:
            raise ValueError("collector retry time must be timezone-aware")
        state = self.retry_state(operation)
        return state is None or now.astimezone(timezone.utc) >= state.retry_after

    def record_retry_failure(
        self,
        operation: RetryOperation,
        *,
        now: datetime,
        initial_seconds: int,
        maximum_seconds: int,
        jitter_ratio: float,
        jitter_key: str,
    ) -> OperationRetryState:
        """Open a bounded exponential retry circuit with deterministic jitter."""

        self._validate_retry_operation(operation)
        if now.tzinfo is None:
            raise ValueError("collector retry time must be timezone-aware")
        if initial_seconds < 1 or maximum_seconds < initial_seconds:
            raise ValueError("invalid collector retry delay bounds")
        if jitter_ratio < 0.0 or jitter_ratio > 0.5:
            raise ValueError("collector retry jitter must be between 0 and 0.5")
        now = now.astimezone(timezone.utc)
        current = self.retry_state(operation)
        failures = min(31, (current.consecutive_failures if current is not None else 0) + 1)
        base_delay = min(maximum_seconds, initial_seconds * (2 ** min(failures - 1, 30)))
        digest = hashlib.sha256(f"{jitter_key}:{operation}:{failures}".encode()).digest()
        unit_interval = int.from_bytes(digest[:8], "big") / float(2**64 - 1)
        jittered_delay = round(
            base_delay * (1.0 - jitter_ratio + (2.0 * jitter_ratio * unit_interval))
        )
        delay_seconds = min(maximum_seconds, max(1, jittered_delay))
        retry_after = now + timedelta(seconds=delay_seconds)
        with self._connect() as connection:
            connection.execute(
                """
                INSERT INTO operation_retry_state(
                    operation, consecutive_failures, retry_after, updated_at
                ) VALUES (?, ?, ?, ?)
                ON CONFLICT(operation) DO UPDATE SET
                    consecutive_failures = excluded.consecutive_failures,
                    retry_after = excluded.retry_after,
                    updated_at = excluded.updated_at
                """,
                (operation, failures, retry_after.isoformat(), now.isoformat()),
            )
        return OperationRetryState(
            consecutive_failures=failures,
            retry_after=retry_after,
        )

    def clear_retry_state(self, operation: RetryOperation) -> None:
        self._validate_retry_operation(operation)
        with self._connect() as connection:
            connection.execute(
                "DELETE FROM operation_retry_state WHERE operation = ?",
                (operation,),
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
        clock: Optional[Callable[[], datetime]] = None,
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
        self._clock = clock or (lambda: datetime.now(timezone.utc))
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

    def _now(self) -> datetime:
        now = self._clock()
        if now.tzinfo is None:
            raise ValueError("collector clock must be timezone-aware")
        return now.astimezone(timezone.utc)

    def _record_retry_failure(self, operation: RetryOperation, now: datetime) -> None:
        self._spool.record_retry_failure(
            operation,
            now=now,
            initial_seconds=self._definition.retry_backoff_initial_seconds,
            maximum_seconds=self._definition.retry_backoff_max_seconds,
            jitter_ratio=self._definition.retry_backoff_jitter_ratio,
            jitter_key=self._definition.device_id,
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
            self._now(),
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

    @staticmethod
    def _control_snapshot_fingerprint(report: ControlReport) -> str:
        snapshot = {
            "hostname": report.hostname,
            "platform": report.platform,
            "findings": [
                {
                    "agent_id": finding.agent_id,
                    "status": finding.status.value,
                    "installed": finding.installed,
                    "running": finding.running,
                    "heartbeat_observed": finding.heartbeat_age_seconds is not None,
                    "stable_evidence": sorted(
                        item for item in finding.evidence if not item.startswith("heartbeat age:")
                    ),
                    "recommended_action": finding.recommended_action,
                }
                for finding in sorted(report.findings, key=lambda finding: finding.agent_id)
            ],
        }
        payload = json.dumps(snapshot, separators=(",", ":"), sort_keys=True).encode()
        return hashlib.sha256(payload).hexdigest()

    def _flush(self, now: datetime) -> DeliveryAttempt:
        delivered = 0
        pending, pending_is_lower_bound = self._spool.pending_summary()
        if pending == 0:
            self._spool.clear_retry_state("delivery")
            return DeliveryAttempt(0, 0, False, False, False)
        if not self._spool.retry_ready("delivery", now):
            return DeliveryAttempt(0, pending, pending_is_lower_bound, False, True)
        for batch_id, events in self._spool.pending(
            limit=self._definition.delivery_flush_batch_limit
        ):
            try:
                self._client.ingest(events)
            except CollectorError as exc:
                self._spool.fail(batch_id, str(exc))
                self._record_retry_failure("delivery", now)
                pending, pending_is_lower_bound = self._spool.pending_summary()
                return DeliveryAttempt(
                    delivered,
                    pending,
                    pending_is_lower_bound,
                    True,
                    False,
                )
            self._spool.acknowledge(batch_id)
            delivered += 1
        self._spool.clear_retry_state("delivery")
        pending, pending_is_lower_bound = self._spool.pending_summary()
        return DeliveryAttempt(delivered, pending, pending_is_lower_bound, False, False)

    def _handle_action(self, action: AgentAction, report: ControlReport) -> None:
        if action.target_id != self._definition.device_id or action.expires_at <= self._now():
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
                generated_at=self._now(),
                device_id=self._definition.device_id,
                agent_version=__version__,
                run_status=run_status,
                failure_stage=failure_stage,
                controls=AgentControlStatusSummary(
                    evaluated=report is not None,
                    total=len(report.findings) if report is not None else 0,
                    failed=report.failed_count if report is not None else 0,
                    degraded=report.degraded_count if report is not None else 0,
                    missing=sum(
                        finding.status == ControlStatus.FAILED and not finding.installed
                        for finding in report.findings
                    )
                    if report is not None
                    else 0,
                    not_running=sum(
                        finding.status == ControlStatus.FAILED
                        and finding.installed
                        and not finding.running
                        for finding in report.findings
                    )
                    if report is not None
                    else 0,
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
        run_failure_stage: Optional[
            Literal[
                "credential_rotation",
                "control_collection",
                "telemetry_collection",
                "delivery",
                "action_polling",
            ]
        ] = None
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
            control_events = self._control_events(report)
            failure_stage = "telemetry_collection"
            telemetry_events: list[SecurityEvent] = []
            santa_cursor: Optional[tuple[str, SourceCursor]] = None
            if self._santa_reader is not None:
                try:
                    santa_batch = self._santa_reader.read(
                        self._spool.source_cursor(self._santa_reader.source_id)
                    )
                except SantaLogError:
                    santa_lines_rejected = 1
                else:
                    telemetry_events.extend(santa_batch.events)
                    santa_events_collected = len(santa_batch.events)
                    santa_lines_rejected = santa_batch.rejected_lines
                    santa_cursor = (self._santa_reader.source_id, santa_batch.cursor)
            _, control_snapshot_enqueued = self._spool.enqueue_collected(
                control_events,
                telemetry_events,
                control_fingerprint=self._control_snapshot_fingerprint(report),
                control_snapshot_interval_seconds=(
                    self._definition.control_snapshot_interval_seconds
                ),
                now=self._now(),
            )
            if control_snapshot_enqueued:
                events.extend(control_events)
            events.extend(telemetry_events)
            if santa_cursor is not None:
                self._spool.save_source_cursor(*santa_cursor)
            failure_stage = "delivery"
            delivery = self._flush(self._now())
            batches_delivered = delivery.delivered
            batches_pending = delivery.pending
            batches_pending_is_lower_bound = delivery.pending_is_lower_bound
            if delivery.failed:
                delivery_status = "failed"
                run_failure_stage = "delivery"
            elif batches_pending > 0:
                delivery_status = "backlogged"
                if delivery.deferred:
                    run_failure_stage = "delivery"
            elif batches_delivered == 0:
                delivery_status = "not_attempted"
            else:
                delivery_status = "succeeded"
            if self._definition.action_polling_enabled:
                failure_stage = "action_polling"
                now = self._now()
                if self._spool.retry_ready("action_polling", now):
                    try:
                        actions = self._client.pending_actions()
                        for action in actions:
                            self._handle_action(action, report)
                            actions_processed += 1
                    except (CollectorError, ValueError):
                        self._record_retry_failure("action_polling", now)
                        run_failure_stage = "action_polling"
                    else:
                        self._spool.clear_retry_state("action_polling")
                else:
                    run_failure_stage = "action_polling"
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
            run_status="failed" if run_failure_stage is not None else "completed",
            failure_stage=run_failure_stage,
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
