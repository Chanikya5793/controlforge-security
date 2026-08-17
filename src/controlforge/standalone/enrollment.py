"""One-time endpoint enrollment and encrypted credential lifecycle services."""

from __future__ import annotations

import base64
import hashlib
import re
import secrets
import sqlite3
import uuid
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from .database import StandaloneDatabase
from .store import _utc_text


class EnrollmentError(RuntimeError):
    """Raised when an enrollment or credential transition must fail closed."""


@dataclass(frozen=True)
class EnrollmentGrant:
    token_id: str
    token: str
    expires_at: datetime
    expected_device_id: str | None


@dataclass(frozen=True)
class EnrolledDeviceCredential:
    tenant_id: str
    device_id: str
    credential_id: str
    secret: str
    expires_at: datetime


@dataclass(frozen=True)
class EncryptedCredential:
    ciphertext: str
    iv: str


@dataclass(frozen=True)
class DeviceSummary:
    device_id: str
    display_name: str
    platform: str
    status: str
    enrolled_at: datetime | None
    last_seen_at: datetime | None
    active_credentials: int


class AesGcmDeviceCredentialCipher:
    """Encrypt collector secrets with credential-bound AES-256-GCM."""

    def __init__(self, key: bytes) -> None:
        if len(key) != 32:
            raise ValueError("device credential encryption key must contain exactly 32 bytes")
        self._cipher = AESGCM(key)

    @staticmethod
    def _aad(credential_id: str) -> bytes:
        return f"controlforge-device-credential:v1:{credential_id}".encode()

    @staticmethod
    def _encode(value: bytes) -> str:
        return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")

    @staticmethod
    def _decode(value: str) -> bytes:
        try:
            return base64.b64decode(
                value + "=" * (-len(value) % 4),
                altchars=b"-_",
                validate=True,
            )
        except (ValueError, TypeError) as exc:
            raise EnrollmentError("device credential ciphertext is invalid") from exc

    def encrypt(self, credential_id: str, secret: bytes) -> EncryptedCredential:
        if len(secret) < 32:
            raise ValueError("device credential secret must contain at least 32 bytes")
        iv = secrets.token_bytes(12)
        ciphertext = self._cipher.encrypt(iv, secret, self._aad(credential_id))
        return EncryptedCredential(ciphertext=self._encode(ciphertext), iv=self._encode(iv))

    def resolve(
        self,
        credential_id: str,
        secret_ciphertext: str,
        secret_iv: str,
    ) -> bytes:
        """Resolve a stored collector secret for the HMAC authenticator."""

        try:
            return self._cipher.decrypt(
                self._decode(secret_iv),
                self._decode(secret_ciphertext),
                self._aad(credential_id),
            )
        except EnrollmentError:
            raise
        except Exception as exc:
            raise EnrollmentError("device credential decryption failed") from exc


class DeviceEnrollmentService:
    """Manage one-use enrollment grants and device-bound collector credentials."""

    _IDENTIFIER = re.compile(r"^[A-Za-z0-9._:-]{1,128}$")
    _PLATFORMS = frozenset({"macos"})

    def __init__(
        self,
        database: StandaloneDatabase,
        cipher: AesGcmDeviceCredentialCipher,
    ) -> None:
        self._database = database
        self._cipher = cipher

    def issue_grant(
        self,
        tenant_id: str,
        created_by: str,
        now: datetime,
        *,
        expires_in: timedelta = timedelta(minutes=15),
        expected_device_id: str | None = None,
    ) -> EnrollmentGrant:
        self._require_identifier(tenant_id, "tenant identity")
        self._require_identifier(created_by, "grant creator")
        if expected_device_id is not None:
            self._require_identifier(expected_device_id, "expected device identity")
        if expires_in < timedelta(minutes=5) or expires_in > timedelta(hours=24):
            raise ValueError("enrollment grants must expire between 5 minutes and 24 hours")
        utc_now = self._require_aware(now)
        expires_at = utc_now + expires_in
        token = secrets.token_urlsafe(32)
        token_hash = hashlib.sha256(token.encode()).hexdigest()
        token_id = str(uuid.uuid4())
        with self._database.connect() as connection:
            tenant = connection.execute(
                "SELECT status FROM tenants WHERE tenant_id = ?",
                (tenant_id,),
            ).fetchone()
            if tenant is None or tenant["status"] != "active":
                raise EnrollmentError("active organization not found")
            connection.execute(
                """
                INSERT INTO enrollment_tokens(
                    token_id, tenant_id, token_hash, expected_device_id, created_by,
                    created_at, expires_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    token_id,
                    tenant_id,
                    token_hash,
                    expected_device_id,
                    created_by,
                    _utc_text(utc_now),
                    _utc_text(expires_at),
                ),
            )
        return EnrollmentGrant(
            token_id=token_id,
            token=token,
            expires_at=expires_at,
            expected_device_id=expected_device_id,
        )

    def account_context_for_grant(self, token: str, now: datetime) -> dict[str, str]:
        """Return server-owned identity for an active account enrollment grant."""
        with self._database.connect() as connection:
            row = connection.execute(
                """SELECT a.account_id,a.tenant_id,t.display_name AS network_name
                   FROM enrollment_tokens e
                   JOIN account_enrollment_grants g ON g.token_id=e.token_id
                   JOIN endpoint_accounts a ON a.tenant_id=g.tenant_id AND a.account_id=g.account_id
                   JOIN tenants t ON t.tenant_id=a.tenant_id
                   WHERE e.token_hash=? AND e.expires_at>? AND e.revoked_at IS NULL
                     AND a.status='active' AND t.status='active'
                     AND a.setup_completed_at IS NOT NULL
                     AND a.password_version=g.password_version""",
                (hashlib.sha256(token.encode()).hexdigest(), _utc_text(now)),
            ).fetchone()
        if row is None:
            raise EnrollmentError("account enrollment context is unavailable")
        return {key: str(row[key]) for key in ("account_id", "tenant_id", "network_name")}

    def list_devices(self, tenant_id: str, now: datetime) -> list[DeviceSummary]:
        self._require_identifier(tenant_id, "tenant identity")
        timestamp = _utc_text(self._require_aware(now))
        with self._database.connect() as connection:
            rows = connection.execute(
                """
                SELECT d.device_id, d.display_name, d.platform, d.status,
                       d.enrolled_at, d.last_seen_at,
                       COUNT(c.credential_id) AS active_credentials
                FROM devices d
                LEFT JOIN device_credentials c
                 ON c.tenant_id = d.tenant_id AND c.device_id = d.device_id
                 AND c.activated_at IS NOT NULL
                 AND c.revoked_at IS NULL AND c.expires_at > ?
                WHERE d.tenant_id = ?
                GROUP BY d.tenant_id, d.device_id
                ORDER BY d.display_name COLLATE NOCASE, d.device_id
                """,
                (timestamp, tenant_id),
            ).fetchall()
        return [
            DeviceSummary(
                device_id=str(row["device_id"]),
                display_name=str(row["display_name"]),
                platform=str(row["platform"]),
                status=str(row["status"]),
                enrolled_at=self._parse_optional_utc(row["enrolled_at"]),
                last_seen_at=self._parse_optional_utc(row["last_seen_at"]),
                active_credentials=int(row["active_credentials"]),
            )
            for row in rows
        ]

    def claim_grant(
        self,
        token: str,
        device_id: str,
        display_name: str,
        platform: str,
        now: datetime,
        *,
        credential_lifetime: timedelta = timedelta(days=90),
    ) -> EnrolledDeviceCredential:
        self._require_identifier(device_id, "device identity")
        normalized_name = display_name.strip()
        if not normalized_name or len(normalized_name) > 100:
            raise ValueError("device display name must contain between 1 and 100 characters")
        if platform not in self._PLATFORMS:
            raise ValueError("device platform is not supported")
        if len(token) < 32 or len(token) > 128:
            raise EnrollmentError("enrollment grant is invalid")
        if credential_lifetime < timedelta(days=1) or credential_lifetime > timedelta(days=365):
            raise ValueError("device credential lifetime must be between 1 and 365 days")
        utc_now = self._require_aware(now)
        token_hash = hashlib.sha256(token.encode()).hexdigest()
        # Collector credentials use the same UUID contract in standalone and
        # hosted deployments so an enrolled credential is immediately usable
        # by the packaged endpoint client.
        credential_id = str(uuid.uuid4())
        secret = secrets.token_urlsafe(32)
        encrypted = self._cipher.encrypt(credential_id, secret.encode())
        expires_at = utc_now + credential_lifetime

        with self._database.connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            try:
                grant = connection.execute(
                    """
                    SELECT e.token_id, e.tenant_id, e.expected_device_id,
                           e.claimed_device_id, e.expires_at, e.used_at,
                           e.revoked_at, t.status AS tenant_status
                    FROM enrollment_tokens e
                    JOIN tenants t ON t.tenant_id = e.tenant_id
                    WHERE e.token_hash = ?
                    """,
                    (token_hash,),
                ).fetchone()
                if (
                    grant is None
                    or grant["tenant_status"] != "active"
                    or grant["revoked_at"] is not None
                    or self._parse_utc(str(grant["expires_at"])) <= utc_now
                    or (
                        grant["expected_device_id"] is not None
                        and grant["expected_device_id"] != device_id
                    )
                ):
                    raise EnrollmentError("enrollment grant is invalid or expired")
                if grant["used_at"] is not None:
                    self._require_account_grant(connection, str(grant["token_id"]))
                    resumed = self._resume_unchecked_grant(
                        connection,
                        grant,
                        device_id,
                        normalized_name,
                        platform,
                        utc_now,
                    )
                    connection.execute("COMMIT")
                    return resumed
                self._require_account_grant(connection, str(grant["token_id"]))
                existing = connection.execute(
                    "SELECT status FROM devices WHERE tenant_id = ? AND device_id = ?",
                    (grant["tenant_id"], device_id),
                ).fetchone()
                if existing is not None:
                    raise EnrollmentError("device identity is already registered")
                connection.execute(
                    """
                    INSERT INTO devices(
                        tenant_id, device_id, display_name, platform, status,
                        enrolled_at, last_seen_at
                    ) VALUES (?, ?, ?, ?, 'active', ?, NULL)
                    """,
                    (
                        grant["tenant_id"],
                        device_id,
                        normalized_name,
                        platform,
                        _utc_text(utc_now),
                    ),
                )
                connection.execute(
                    """
                    INSERT INTO device_credentials(
                        credential_id, tenant_id, device_id, name, secret_ciphertext,
                        secret_iv, created_at, expires_at, activated_at
                    ) VALUES (?, ?, ?, 'initial enrollment', ?, ?, ?, ?, ?)
                    """,
                    (
                        credential_id,
                        grant["tenant_id"],
                        device_id,
                        encrypted.ciphertext,
                        encrypted.iv,
                        _utc_text(utc_now),
                        _utc_text(expires_at),
                        _utc_text(utc_now),
                    ),
                )
                updated = connection.execute(
                    """
                    UPDATE enrollment_tokens SET used_at = ?, claimed_device_id = ?
                    WHERE token_id = ? AND used_at IS NULL AND revoked_at IS NULL
                    """,
                    (_utc_text(utc_now), device_id, grant["token_id"]),
                )
                if updated.rowcount != 1:
                    raise EnrollmentError("enrollment grant is no longer available")
                connection.execute("COMMIT")
            except Exception:
                if connection.in_transaction:
                    connection.execute("ROLLBACK")
                raise
        return EnrolledDeviceCredential(
            tenant_id=str(grant["tenant_id"]),
            device_id=device_id,
            credential_id=credential_id,
            secret=secret,
            expires_at=expires_at,
        )

    @staticmethod
    def _require_account_grant(connection: sqlite3.Connection, token_id: str) -> None:
        account = connection.execute(
            """SELECT a.status,a.setup_completed_at,a.password_version,g.password_version AS issued
               FROM account_enrollment_grants g JOIN endpoint_accounts a
                 ON a.tenant_id=g.tenant_id AND a.account_id=g.account_id
               WHERE g.token_id=?""",
            (token_id,),
        ).fetchone()
        if account is not None and (
            account["status"] != "active"
            or account["setup_completed_at"] is None
            or account["password_version"] != account["issued"]
        ):
            raise EnrollmentError("account enrollment authority is no longer active")

    def _resume_unchecked_grant(
        self,
        connection: sqlite3.Connection,
        grant: sqlite3.Row,
        device_id: str,
        display_name: str,
        platform: str,
        now: datetime,
    ) -> EnrolledDeviceCredential:
        """Return the original secret only until the endpoint's first authenticated use."""

        if grant["claimed_device_id"] != device_id:
            raise EnrollmentError("enrollment grant is invalid or expired")
        row = connection.execute(
            """
            SELECT d.display_name, d.platform, d.status, d.last_seen_at,
                   c.credential_id, c.secret_ciphertext, c.secret_iv,
                   c.expires_at, c.revoked_at, c.activated_at
            FROM devices d
            JOIN device_credentials c
              ON c.tenant_id = d.tenant_id AND c.device_id = d.device_id
            WHERE d.tenant_id = ? AND d.device_id = ?
              AND c.name = 'initial enrollment'
            ORDER BY c.created_at, c.credential_id
            LIMIT 1
            """,
            (grant["tenant_id"], device_id),
        ).fetchone()
        if (
            row is None
            or row["display_name"] != display_name
            or row["platform"] != platform
            or row["status"] != "active"
            or row["last_seen_at"] is not None
            or row["revoked_at"] is not None
            or row["activated_at"] is None
            or self._parse_utc(str(row["expires_at"])) <= now
        ):
            raise EnrollmentError("enrollment grant is invalid or expired")
        credential_id = str(row["credential_id"])
        secret = self._cipher.resolve(
            credential_id,
            str(row["secret_ciphertext"]),
            str(row["secret_iv"]),
        ).decode("utf-8")
        return EnrolledDeviceCredential(
            tenant_id=str(grant["tenant_id"]),
            device_id=device_id,
            credential_id=credential_id,
            secret=secret,
            expires_at=self._parse_utc(str(row["expires_at"])),
        )

    def revoke_grant(self, tenant_id: str, token_id: str, now: datetime) -> bool:
        utc_now = self._require_aware(now)
        with self._database.connect() as connection:
            result = connection.execute(
                """
                UPDATE enrollment_tokens SET revoked_at = ?
                WHERE tenant_id = ? AND token_id = ?
                  AND used_at IS NULL AND revoked_at IS NULL
                """,
                (_utc_text(utc_now), tenant_id, token_id),
            )
        return result.rowcount == 1

    def revoke_credential(
        self,
        tenant_id: str,
        device_id: str,
        credential_id: str,
        now: datetime,
    ) -> bool:
        """Retire one credential only when another active credential prevents lockout."""

        utc_now = self._require_aware(now)
        timestamp = _utc_text(utc_now)
        with self._database.connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            try:
                replacement = connection.execute(
                    """
                    SELECT COUNT(*) FROM device_credentials
                    WHERE tenant_id = ? AND device_id = ? AND credential_id != ?
                      AND activated_at IS NOT NULL
                      AND revoked_at IS NULL AND expires_at > ?
                    """,
                    (tenant_id, device_id, credential_id, timestamp),
                ).fetchone()[0]
                if replacement < 1:
                    raise EnrollmentError(
                        "credential cannot be retired without an active replacement"
                    )
                result = connection.execute(
                    """
                    UPDATE device_credentials SET revoked_at = ?
                    WHERE tenant_id = ? AND device_id = ? AND credential_id = ?
                      AND revoked_at IS NULL
                    """,
                    (timestamp, tenant_id, device_id, credential_id),
                )
                connection.execute("COMMIT")
            except Exception:
                if connection.in_transaction:
                    connection.execute("ROLLBACK")
                raise
        return result.rowcount == 1

    def revoke_device(self, tenant_id: str, device_id: str, now: datetime) -> bool:
        utc_now = self._require_aware(now)
        timestamp = _utc_text(utc_now)
        with self._database.connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            try:
                device = connection.execute(
                    """
                    UPDATE devices SET status = 'revoked', revoked_at = ?
                    WHERE tenant_id = ? AND device_id = ? AND status != 'revoked'
                    """,
                    (timestamp, tenant_id, device_id),
                )
                if device.rowcount == 1:
                    connection.execute(
                        """
                        UPDATE device_credentials SET revoked_at = ?
                        WHERE tenant_id = ? AND device_id = ? AND revoked_at IS NULL
                        """,
                        (timestamp, tenant_id, device_id),
                    )
                    connection.execute(
                        """
                        UPDATE device_credential_rotations
                        SET status = 'cancelled', cancelled_at = ?,
                            envelope_ciphertext = NULL, envelope_iv = NULL
                        WHERE tenant_id = ? AND device_id = ?
                          AND status IN ('pending', 'delivered')
                        """,
                        (timestamp, tenant_id, device_id),
                    )
                    connection.execute(
                        """
                        UPDATE enrollment_tokens SET revoked_at = ?
                        WHERE tenant_id = ? AND expected_device_id = ?
                          AND used_at IS NULL AND revoked_at IS NULL
                        """,
                        (timestamp, tenant_id, device_id),
                    )
                connection.execute("COMMIT")
            except Exception:
                if connection.in_transaction:
                    connection.execute("ROLLBACK")
                raise
        return device.rowcount == 1

    @classmethod
    def _require_identifier(cls, value: str, label: str) -> None:
        if cls._IDENTIFIER.fullmatch(value) is None:
            raise ValueError(f"{label} is invalid")

    @staticmethod
    def _require_aware(value: datetime) -> datetime:
        if value.tzinfo is None:
            raise ValueError("timestamps must be timezone-aware")
        return value.astimezone(timezone.utc)

    @staticmethod
    def _parse_utc(value: str) -> datetime:
        return datetime.fromisoformat(value.replace("Z", "+00:00")).astimezone(timezone.utc)

    @classmethod
    def _parse_optional_utc(cls, value: object) -> datetime | None:
        return None if value is None else cls._parse_utc(str(value))


__all__ = [
    "AesGcmDeviceCredentialCipher",
    "DeviceEnrollmentService",
    "DeviceSummary",
    "EnrolledDeviceCredential",
    "EnrollmentError",
    "EnrollmentGrant",
]
