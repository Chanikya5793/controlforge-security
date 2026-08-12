"""Endpoint-bound, encrypted, acknowledgment-gated credential rotation."""

from __future__ import annotations

import re
import secrets
import sqlite3
import uuid
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Optional

from controlforge.credential_rotation import (
    CredentialRotationEnvelope,
    CredentialRotationMaterial,
    encrypt_rotation_material,
)

from .auth import DeviceHmacAuthenticator, SignedCollectorRequest
from .database import StandaloneDatabase
from .enrollment import AesGcmDeviceCredentialCipher, EnrollmentError
from .store import _utc_text


@dataclass(frozen=True)
class CredentialRotationState:
    rotation_id: str
    device_id: str
    predecessor_credential_id: str
    replacement_credential_id: str
    status: str
    created_at: datetime
    delivery_expires_at: datetime
    changed: bool = True


class DeviceCredentialRotationService:
    """Stage one inactive replacement and deliver it only to its predecessor."""

    _IDENTIFIER = re.compile(r"^[A-Za-z0-9._:-]{1,128}$")
    _MAX_DELIVERIES = 10

    def __init__(
        self,
        database: StandaloneDatabase,
        cipher: AesGcmDeviceCredentialCipher,
        authenticator: DeviceHmacAuthenticator,
    ) -> None:
        self._database = database
        self._cipher = cipher
        self._authenticator = authenticator

    def initiate(
        self,
        tenant_id: str,
        device_id: str,
        created_by: str,
        now: datetime,
        *,
        credential_lifetime: timedelta = timedelta(days=90),
        delivery_window: timedelta = timedelta(hours=24),
    ) -> CredentialRotationState:
        self._require_identifier(tenant_id, "tenant identity")
        self._require_identifier(device_id, "device identity")
        self._require_identifier(created_by, "rotation creator")
        if credential_lifetime < timedelta(days=1) or credential_lifetime > timedelta(days=365):
            raise ValueError("device credential lifetime must be between 1 and 365 days")
        if delivery_window < timedelta(minutes=5) or delivery_window > timedelta(hours=24):
            raise ValueError("credential delivery window must be between 5 minutes and 24 hours")
        utc_now = self._aware(now)
        timestamp = _utc_text(utc_now)
        rotation_id = str(uuid.uuid4())
        replacement_id = str(uuid.uuid4())
        replacement_secret = secrets.token_urlsafe(32)
        encrypted = self._cipher.encrypt(replacement_id, replacement_secret.encode())
        replacement_expires_at = utc_now + credential_lifetime
        delivery_expires_at = utc_now + delivery_window
        with self._database.connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            try:
                device = connection.execute(
                    """
                    SELECT status FROM devices
                    WHERE tenant_id = ? AND device_id = ?
                    """,
                    (tenant_id, device_id),
                ).fetchone()
                if device is None or device["status"] != "active":
                    raise EnrollmentError("active device not found")
                active = connection.execute(
                    """
                    SELECT credential_id FROM device_credentials
                    WHERE tenant_id = ? AND device_id = ?
                      AND activated_at IS NOT NULL AND revoked_at IS NULL
                      AND expires_at > ?
                    ORDER BY COALESCE(last_used_at, created_at) DESC, credential_id
                    """,
                    (tenant_id, device_id, timestamp),
                ).fetchall()
                if len(active) != 1:
                    raise EnrollmentError(
                        "device must have exactly one active credential before rotation"
                    )
                live = connection.execute(
                    """
                    SELECT 1 FROM device_credential_rotations
                    WHERE tenant_id = ? AND device_id = ?
                      AND status IN ('pending', 'delivered')
                    """,
                    (tenant_id, device_id),
                ).fetchone()
                if live is not None:
                    raise EnrollmentError("device already has a pending credential rotation")
                predecessor_id = str(active[0]["credential_id"])
                connection.execute(
                    """
                    INSERT INTO device_credentials(
                        credential_id, tenant_id, device_id, name, secret_ciphertext,
                        secret_iv, created_at, expires_at, activated_at
                    ) VALUES (?, ?, ?, 'credential rotation', ?, ?, ?, ?, NULL)
                    """,
                    (
                        replacement_id,
                        tenant_id,
                        device_id,
                        encrypted.ciphertext,
                        encrypted.iv,
                        timestamp,
                        _utc_text(replacement_expires_at),
                    ),
                )
                connection.execute(
                    """
                    INSERT INTO device_credential_rotations(
                        rotation_id, tenant_id, device_id, predecessor_credential_id,
                        replacement_credential_id, status, created_by, created_at,
                        delivery_expires_at
                    ) VALUES (?, ?, ?, ?, ?, 'pending', ?, ?, ?)
                    """,
                    (
                        rotation_id,
                        tenant_id,
                        device_id,
                        predecessor_id,
                        replacement_id,
                        created_by,
                        timestamp,
                        _utc_text(delivery_expires_at),
                    ),
                )
                connection.execute("COMMIT")
            except Exception:
                if connection.in_transaction:
                    connection.execute("ROLLBACK")
                raise
        return CredentialRotationState(
            rotation_id,
            device_id,
            predecessor_id,
            replacement_id,
            "pending",
            utc_now,
            delivery_expires_at,
        )

    def poll(
        self,
        request: SignedCollectorRequest,
        device_id: str,
        now: datetime,
    ) -> Optional[CredentialRotationEnvelope]:
        utc_now = self._aware(now)
        device = self._authenticator.authenticate(request, utc_now)
        if device.device_id != device_id:
            raise EnrollmentError("credential rotation target does not match device")
        with self._database.connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            try:
                row = connection.execute(
                    """
                    SELECT r.*, c.secret_ciphertext AS replacement_ciphertext,
                           c.secret_iv AS replacement_iv, c.expires_at AS replacement_expires_at
                    FROM device_credential_rotations r
                    JOIN device_credentials c
                      ON c.credential_id = r.replacement_credential_id
                    WHERE r.tenant_id = ? AND r.device_id = ?
                      AND r.status IN ('pending', 'delivered')
                    """,
                    (device.tenant_id, device_id),
                ).fetchone()
                if row is None:
                    connection.execute("COMMIT")
                    return None
                if row["predecessor_credential_id"] != device.credential_id:
                    raise EnrollmentError("credential rotation is bound to another credential")
                if self._parse(str(row["delivery_expires_at"])) <= utc_now:
                    self._cancel_row(connection, row, utc_now)
                    connection.execute("COMMIT")
                    return None
                if int(row["delivery_count"]) >= self._MAX_DELIVERIES:
                    raise EnrollmentError("credential rotation delivery retry limit reached")
                if row["status"] == "pending":
                    predecessor = connection.execute(
                        """
                        SELECT secret_ciphertext, secret_iv FROM device_credentials
                        WHERE credential_id = ? AND activated_at IS NOT NULL
                          AND revoked_at IS NULL
                        """,
                        (device.credential_id,),
                    ).fetchone()
                    if predecessor is None:
                        raise EnrollmentError("rotation predecessor is no longer active")
                    predecessor_secret = self._cipher.resolve(
                        device.credential_id,
                        str(predecessor["secret_ciphertext"]),
                        str(predecessor["secret_iv"]),
                    )
                    replacement_secret = self._cipher.resolve(
                        str(row["replacement_credential_id"]),
                        str(row["replacement_ciphertext"]),
                        str(row["replacement_iv"]),
                    ).decode("utf-8")
                    envelope = encrypt_rotation_material(
                        CredentialRotationMaterial(
                            rotation_id=str(row["rotation_id"]),
                            device_id=device_id,
                            predecessor_credential_id=device.credential_id,
                            replacement_credential_id=str(row["replacement_credential_id"]),
                            replacement_secret=replacement_secret,
                            replacement_expires_at=self._parse(str(row["replacement_expires_at"])),
                        ),
                        predecessor_secret,
                        self._parse(str(row["delivery_expires_at"])),
                    )
                    connection.execute(
                        """
                        UPDATE device_credential_rotations
                        SET status = 'delivered', delivered_at = ?,
                            envelope_ciphertext = ?, envelope_iv = ?, delivery_count = 1
                        WHERE rotation_id = ? AND status = 'pending'
                        """,
                        (
                            _utc_text(utc_now),
                            envelope.ciphertext,
                            envelope.iv,
                            row["rotation_id"],
                        ),
                    )
                else:
                    envelope = self._envelope(row)
                    connection.execute(
                        """
                        UPDATE device_credential_rotations
                        SET delivery_count = delivery_count + 1
                        WHERE rotation_id = ? AND status = 'delivered'
                        """,
                        (row["rotation_id"],),
                    )
                connection.execute("COMMIT")
            except Exception:
                if connection.in_transaction:
                    connection.execute("ROLLBACK")
                raise
        return envelope

    def acknowledge(
        self,
        request: SignedCollectorRequest,
        now: datetime,
    ) -> CredentialRotationState | None:
        utc_now = self._aware(now)
        device = self._authenticator.authenticate(request, utc_now)
        with self._database.connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            try:
                row = connection.execute(
                    """
                    SELECT * FROM device_credential_rotations
                    WHERE replacement_credential_id = ?
                    """,
                    (device.credential_id,),
                ).fetchone()
                if row is None:
                    connection.execute("COMMIT")
                    return None
                if row["tenant_id"] != device.tenant_id or row["device_id"] != device.device_id:
                    raise EnrollmentError("credential rotation acknowledgment is not device-bound")
                if row["status"] == "acknowledged":
                    connection.execute("COMMIT")
                    return self._state(row, changed=False)
                if row["status"] != "delivered":
                    raise EnrollmentError("credential rotation is not awaiting acknowledgment")
                timestamp = _utc_text(utc_now)
                activated = connection.execute(
                    """
                    UPDATE device_credentials SET activated_at = ?
                    WHERE credential_id = ? AND activated_at IS NULL AND revoked_at IS NULL
                      AND expires_at > ?
                    """,
                    (timestamp, row["replacement_credential_id"], timestamp),
                )
                retired = connection.execute(
                    """
                    UPDATE device_credentials SET revoked_at = ?
                    WHERE credential_id = ? AND activated_at IS NOT NULL AND revoked_at IS NULL
                    """,
                    (timestamp, row["predecessor_credential_id"]),
                )
                changed = connection.execute(
                    """
                    UPDATE device_credential_rotations
                    SET status = 'acknowledged', acknowledged_at = ?,
                        envelope_ciphertext = NULL, envelope_iv = NULL
                    WHERE rotation_id = ? AND status = 'delivered'
                    """,
                    (timestamp, row["rotation_id"]),
                )
                if activated.rowcount != 1 or retired.rowcount != 1 or changed.rowcount != 1:
                    raise EnrollmentError("credential rotation acknowledgment conflicted")
                updated = connection.execute(
                    """
                    SELECT * FROM device_credential_rotations
                    WHERE rotation_id = ?
                    """,
                    (row["rotation_id"],),
                ).fetchone()
                if updated is None:
                    raise EnrollmentError("credential rotation acknowledgment was not retained")
                connection.execute("COMMIT")
            except Exception:
                if connection.in_transaction:
                    connection.execute("ROLLBACK")
                raise
        return self._state(updated)

    def cancel(
        self,
        tenant_id: str,
        rotation_id: str,
        now: datetime,
    ) -> bool:
        utc_now = self._aware(now)
        with self._database.connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            try:
                row = connection.execute(
                    """
                    SELECT * FROM device_credential_rotations
                    WHERE tenant_id = ? AND rotation_id = ?
                    """,
                    (tenant_id, rotation_id),
                ).fetchone()
                if row is None or row["status"] == "cancelled":
                    connection.execute("COMMIT")
                    return False
                if row["status"] != "pending":
                    raise EnrollmentError(
                        "delivered credential rotation cannot be cancelled before device recovery"
                    )
                self._cancel_row(connection, row, utc_now)
                connection.execute("COMMIT")
            except Exception:
                if connection.in_transaction:
                    connection.execute("ROLLBACK")
                raise
        return True

    def _cancel_row(
        self,
        connection: sqlite3.Connection,
        row: sqlite3.Row,
        now: datetime,
    ) -> None:
        timestamp = _utc_text(now)
        connection.execute(
            """
            UPDATE device_credentials SET revoked_at = ?
            WHERE credential_id = ? AND activated_at IS NULL AND revoked_at IS NULL
            """,
            (timestamp, row["replacement_credential_id"]),
        )
        connection.execute(
            """
            UPDATE device_credential_rotations
            SET status = 'cancelled', cancelled_at = ?,
                envelope_ciphertext = NULL, envelope_iv = NULL
            WHERE rotation_id = ? AND status IN ('pending', 'delivered')
            """,
            (timestamp, row["rotation_id"]),
        )

    @staticmethod
    def _envelope(row: sqlite3.Row) -> CredentialRotationEnvelope:
        return CredentialRotationEnvelope(
            schema_version="controlforge-credential-rotation-v1",
            algorithm="AES-256-GCM-HKDF-SHA256",
            rotation_id=str(row["rotation_id"]),
            device_id=str(row["device_id"]),
            predecessor_credential_id=str(row["predecessor_credential_id"]),
            delivery_expires_at=DeviceCredentialRotationService._parse(
                str(row["delivery_expires_at"])
            ),
            ciphertext=str(row["envelope_ciphertext"]),
            iv=str(row["envelope_iv"]),
        )

    @staticmethod
    def _state(row: sqlite3.Row, *, changed: bool = True) -> CredentialRotationState:
        return CredentialRotationState(
            rotation_id=str(row["rotation_id"]),
            device_id=str(row["device_id"]),
            predecessor_credential_id=str(row["predecessor_credential_id"]),
            replacement_credential_id=str(row["replacement_credential_id"]),
            status=str(row["status"]),
            created_at=DeviceCredentialRotationService._parse(str(row["created_at"])),
            delivery_expires_at=DeviceCredentialRotationService._parse(
                str(row["delivery_expires_at"])
            ),
            changed=changed,
        )

    @classmethod
    def _require_identifier(cls, value: str, label: str) -> None:
        if cls._IDENTIFIER.fullmatch(value) is None:
            raise ValueError(f"{label} is invalid")

    @staticmethod
    def _aware(value: datetime) -> datetime:
        if value.tzinfo is None:
            raise ValueError("timestamps must be timezone-aware")
        return value.astimezone(timezone.utc)

    @staticmethod
    def _parse(value: str) -> datetime:
        return datetime.fromisoformat(value.replace("Z", "+00:00")).astimezone(timezone.utc)


__all__ = ["CredentialRotationState", "DeviceCredentialRotationService"]
