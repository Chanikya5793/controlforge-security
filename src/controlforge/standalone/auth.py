"""Device-bound authentication for fixed collector request semantics."""

from __future__ import annotations

import hashlib
import hmac
import re
import sqlite3
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Protocol

from .database import StandaloneDatabase
from .store import _utc_text


class CollectorAuthenticationError(RuntimeError):
    """Raised when a collector request cannot be authenticated."""


class CollectorReplayError(CollectorAuthenticationError):
    """Raised when a valid signed nonce has already been consumed."""


class CredentialSecretResolver(Protocol):
    """Decrypt credential material without exposing key management to persistence."""

    def resolve(
        self,
        credential_id: str,
        secret_ciphertext: str,
        secret_iv: str,
    ) -> bytes:
        """Return the credential secret for HMAC verification."""


@dataclass(frozen=True)
class SignedCollectorRequest:
    method: str
    path: str
    body: bytes
    credential_id: str
    timestamp: str
    nonce: str
    signature: str


@dataclass(frozen=True)
class AuthenticatedDevice:
    tenant_id: str
    device_id: str
    credential_id: str


class DeviceHmacAuthenticator:
    """Authenticate only fixed, nonce-bound ControlForge collector requests."""

    INGESTION_METHOD = "POST"
    INGESTION_PATH = "/v1/ingest/events"
    ACTION_POLL_METHOD = "GET"
    ACTION_POLL_PATH = "/v1/agent/actions"
    ACTION_RESULT_METHOD = "POST"
    ROTATION_POLL_METHOD = "GET"
    ROTATION_POLL_PATH = "/v1/agent/credential-rotation"
    ROTATION_ACK_METHOD = "POST"
    ROTATION_ACK_PATH = "/v1/agent/credential-rotation/ack"
    _ACTION_RESULT_PATH = re.compile(
        r"^/v1/agent/actions/[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-"
        r"[0-9a-f]{4}-[0-9a-f]{12}/result$"
    )
    _CREDENTIAL_ID = re.compile(r"^[A-Za-z0-9._:-]{1,128}$")
    _NONCE = re.compile(r"^[A-Za-z0-9_-]{16,128}$")
    _SIGNATURE = re.compile(r"^[a-f0-9]{64}$")

    def __init__(
        self,
        database: StandaloneDatabase,
        secret_resolver: CredentialSecretResolver,
        max_clock_skew_seconds: int = 300,
    ) -> None:
        if max_clock_skew_seconds < 30 or max_clock_skew_seconds > 900:
            raise ValueError("max_clock_skew_seconds must be between 30 and 900")
        self._database = database
        self._secret_resolver = secret_resolver
        self._max_clock_skew_seconds = max_clock_skew_seconds

    @classmethod
    def canonical_request(cls, request: SignedCollectorRequest) -> bytes:
        body_hash = hashlib.sha256(request.body).hexdigest()
        return "\n".join(
            [request.method, request.path, request.timestamp, request.nonce, body_hash]
        ).encode()

    def authenticate(
        self,
        request: SignedCollectorRequest,
        now: datetime,
    ) -> AuthenticatedDevice:
        """Verify a collector and consume its nonce exactly once."""

        if not self._request_semantics_allowed(request.method, request.path):
            raise CollectorAuthenticationError("collector request semantics are not allowed")
        if self._CREDENTIAL_ID.fullmatch(request.credential_id) is None:
            raise CollectorAuthenticationError("collector credential identity is invalid")
        if self._NONCE.fullmatch(request.nonce) is None:
            raise CollectorAuthenticationError("collector nonce is invalid")
        if self._SIGNATURE.fullmatch(request.signature) is None:
            raise CollectorAuthenticationError("collector signature is invalid")
        request_time = self._parse_timestamp(request.timestamp)
        if now.tzinfo is None:
            raise ValueError("authentication clock must be timezone-aware")
        utc_now = now.astimezone(timezone.utc)
        if abs((utc_now - request_time).total_seconds()) > self._max_clock_skew_seconds:
            raise CollectorAuthenticationError("collector timestamp is outside the allowed window")

        with self._database.connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            try:
                row = connection.execute(
                    """
                    SELECT c.credential_id, c.tenant_id, c.device_id,
                           c.secret_ciphertext, c.secret_iv, c.expires_at, c.revoked_at,
                           c.activated_at,
                           d.status AS device_status, t.status AS tenant_status
                    FROM device_credentials c
                    JOIN devices d
                      ON d.tenant_id = c.tenant_id AND d.device_id = c.device_id
                    JOIN tenants t ON t.tenant_id = c.tenant_id
                    WHERE c.credential_id = ?
                    """,
                    (request.credential_id,),
                ).fetchone()
                if row is None:
                    raise CollectorAuthenticationError("collector credential is not active")
                pending_ack = False
                if row["activated_at"] is None and request.path == self.ROTATION_ACK_PATH:
                    pending_ack = (
                        connection.execute(
                            """
                            SELECT 1 FROM device_credential_rotations
                            WHERE replacement_credential_id = ? AND tenant_id = ?
                              AND device_id = ? AND status = 'delivered'
                            """,
                            (request.credential_id, row["tenant_id"], row["device_id"]),
                        ).fetchone()
                        is not None
                    )
                if (
                    row["revoked_at"] is not None
                    or (row["activated_at"] is None and not pending_ack)
                    or row["device_status"] != "active"
                    or row["tenant_status"] != "active"
                    or self._parse_timestamp(str(row["expires_at"])) <= utc_now
                ):
                    raise CollectorAuthenticationError("collector credential is not active")
                try:
                    secret = self._secret_resolver.resolve(
                        str(row["credential_id"]),
                        str(row["secret_ciphertext"]),
                        str(row["secret_iv"]),
                    )
                except Exception as exc:
                    raise CollectorAuthenticationError(
                        "collector credential material is unavailable"
                    ) from exc
                if len(secret) < 32:
                    raise CollectorAuthenticationError("collector credential material is invalid")
                expected = hmac.new(
                    secret,
                    self.canonical_request(request),
                    hashlib.sha256,
                ).hexdigest()
                if not hmac.compare_digest(request.signature, expected):
                    raise CollectorAuthenticationError("collector signature is invalid")
                nonce_expiry = utc_now + timedelta(seconds=self._max_clock_skew_seconds * 2)
                connection.execute(
                    "DELETE FROM device_auth_nonces WHERE expires_at <= ?",
                    (_utc_text(utc_now),),
                )
                try:
                    connection.execute(
                        """
                        INSERT INTO device_auth_nonces(credential_id, nonce, expires_at)
                        VALUES (?, ?, ?)
                        """,
                        (request.credential_id, request.nonce, _utc_text(nonce_expiry)),
                    )
                except sqlite3.IntegrityError as exc:
                    raise CollectorReplayError("collector request nonce was replayed") from exc
                connection.execute(
                    """
                    UPDATE device_credentials SET last_used_at = ?
                    WHERE credential_id = ?
                    """,
                    (_utc_text(utc_now), request.credential_id),
                )
                connection.execute(
                    """
                    UPDATE devices SET last_seen_at = ?
                    WHERE tenant_id = ? AND device_id = ? AND status = 'active'
                    """,
                    (_utc_text(utc_now), row["tenant_id"], row["device_id"]),
                )
                connection.execute("COMMIT")
            except Exception:
                if connection.in_transaction:
                    connection.execute("ROLLBACK")
                raise
        return AuthenticatedDevice(
            tenant_id=str(row["tenant_id"]),
            device_id=str(row["device_id"]),
            credential_id=str(row["credential_id"]),
        )

    @classmethod
    def _request_semantics_allowed(cls, method: str, path: str) -> bool:
        return bool(
            (method == cls.INGESTION_METHOD and path == cls.INGESTION_PATH)
            or (method == cls.ACTION_POLL_METHOD and path == cls.ACTION_POLL_PATH)
            or (method == cls.ROTATION_POLL_METHOD and path == cls.ROTATION_POLL_PATH)
            or (method == cls.ROTATION_ACK_METHOD and path == cls.ROTATION_ACK_PATH)
            or (
                method == cls.ACTION_RESULT_METHOD
                and cls._ACTION_RESULT_PATH.fullmatch(path) is not None
            )
        )

    @staticmethod
    def _parse_timestamp(value: str) -> datetime:
        try:
            parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
        except ValueError as exc:
            raise CollectorAuthenticationError("collector timestamp is invalid") from exc
        if parsed.tzinfo is None:
            raise CollectorAuthenticationError("collector timestamp must include an offset")
        return parsed.astimezone(timezone.utc)
