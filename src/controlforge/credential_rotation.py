"""Strict endpoint-bound credential-rotation envelope contract."""

from __future__ import annotations

import base64
import hashlib
import json
import secrets
from datetime import datetime, timezone
from typing import Literal

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator


class CredentialRotationEnvelopeError(ValueError):
    """Raised when a rotation envelope is invalid, unbound, or unauthentic."""


class CredentialRotationMaterial(BaseModel):
    """Decrypted replacement material that must exist only in endpoint memory."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    rotation_id: str = Field(pattern=r"^[0-9a-f-]{36}$")
    device_id: str = Field(min_length=1, max_length=128, pattern=r"^[A-Za-z0-9._:-]+$")
    predecessor_credential_id: str = Field(pattern=r"^[0-9a-f-]{36}$")
    replacement_credential_id: str = Field(pattern=r"^[0-9a-f-]{36}$")
    replacement_secret: str = Field(min_length=32, max_length=256)
    replacement_expires_at: datetime

    @field_validator("replacement_expires_at")
    @classmethod
    def require_timezone(cls, value: datetime) -> datetime:
        if value.tzinfo is None:
            raise ValueError("replacement expiry must be timezone-aware")
        return value.astimezone(timezone.utc)

    @model_validator(mode="after")
    def require_distinct_credentials(self) -> CredentialRotationMaterial:
        if self.predecessor_credential_id == self.replacement_credential_id:
            raise ValueError("replacement credential must differ from predecessor")
        return self


class CredentialRotationEnvelope(BaseModel):
    """One generated ciphertext, safely redeliverable only to its predecessor."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    schema_version: Literal["controlforge-credential-rotation-v1"]
    algorithm: Literal["AES-256-GCM-HKDF-SHA256"]
    rotation_id: str = Field(pattern=r"^[0-9a-f-]{36}$")
    device_id: str = Field(min_length=1, max_length=128, pattern=r"^[A-Za-z0-9._:-]+$")
    predecessor_credential_id: str = Field(pattern=r"^[0-9a-f-]{36}$")
    delivery_expires_at: datetime
    ciphertext: str = Field(min_length=64, max_length=2048, pattern=r"^[A-Za-z0-9_-]+$")
    iv: str = Field(min_length=16, max_length=32, pattern=r"^[A-Za-z0-9_-]+$")

    @field_validator("delivery_expires_at")
    @classmethod
    def require_timezone(cls, value: datetime) -> datetime:
        if value.tzinfo is None:
            raise ValueError("delivery expiry must be timezone-aware")
        return value.astimezone(timezone.utc)


def encrypt_rotation_material(
    material: CredentialRotationMaterial,
    predecessor_secret: bytes,
    delivery_expires_at: datetime,
) -> CredentialRotationEnvelope:
    """Encrypt replacement material to one predecessor credential and device."""

    if len(predecessor_secret) < 32:
        raise CredentialRotationEnvelopeError("predecessor secret is invalid")
    if delivery_expires_at.tzinfo is None:
        raise CredentialRotationEnvelopeError("delivery expiry must be timezone-aware")
    normalized_expiry = delivery_expires_at.astimezone(timezone.utc)
    key, aad = _key_and_aad(
        material.rotation_id,
        material.device_id,
        material.predecessor_credential_id,
        predecessor_secret,
    )
    iv = secrets.token_bytes(12)
    plaintext = bytearray(
        json.dumps(
            material.model_dump(mode="json"),
            separators=(",", ":"),
            sort_keys=True,
        ).encode()
    )
    try:
        ciphertext = AESGCM(key).encrypt(iv, bytes(plaintext), aad)
    finally:
        for index in range(len(plaintext)):
            plaintext[index] = 0
    return CredentialRotationEnvelope(
        schema_version="controlforge-credential-rotation-v1",
        algorithm="AES-256-GCM-HKDF-SHA256",
        rotation_id=material.rotation_id,
        device_id=material.device_id,
        predecessor_credential_id=material.predecessor_credential_id,
        delivery_expires_at=normalized_expiry,
        ciphertext=_encode(ciphertext),
        iv=_encode(iv),
    )


def decrypt_rotation_envelope(
    envelope: CredentialRotationEnvelope,
    predecessor_secret: bytes,
    *,
    expected_device_id: str,
    expected_credential_id: str,
    now: datetime,
) -> CredentialRotationMaterial:
    """Authenticate, decrypt, and revalidate a device-bound rotation envelope."""

    if now.tzinfo is None:
        raise CredentialRotationEnvelopeError("rotation clock must be timezone-aware")
    if envelope.delivery_expires_at <= now.astimezone(timezone.utc):
        raise CredentialRotationEnvelopeError("credential rotation delivery expired")
    if (
        envelope.device_id != expected_device_id
        or envelope.predecessor_credential_id != expected_credential_id
    ):
        raise CredentialRotationEnvelopeError("credential rotation envelope binding failed")
    key, aad = _key_and_aad(
        envelope.rotation_id,
        envelope.device_id,
        envelope.predecessor_credential_id,
        predecessor_secret,
    )
    try:
        plaintext = bytearray(
            AESGCM(key).decrypt(_decode(envelope.iv), _decode(envelope.ciphertext), aad)
        )
        material = CredentialRotationMaterial.model_validate_json(bytes(plaintext))
    except Exception as exc:
        raise CredentialRotationEnvelopeError(
            "credential rotation envelope authentication failed"
        ) from exc
    finally:
        if "plaintext" in locals():
            for index in range(len(plaintext)):
                plaintext[index] = 0
    if (
        material.rotation_id != envelope.rotation_id
        or material.device_id != expected_device_id
        or material.predecessor_credential_id != expected_credential_id
        or material.replacement_expires_at <= now.astimezone(timezone.utc)
    ):
        raise CredentialRotationEnvelopeError("credential rotation material binding failed")
    return material


def _key_and_aad(
    rotation_id: str,
    device_id: str,
    predecessor_credential_id: str,
    predecessor_secret: bytes,
) -> tuple[bytes, bytes]:
    aad = (
        f"controlforge-credential-rotation:v1:{rotation_id}:{device_id}:{predecessor_credential_id}"
    ).encode()
    key = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=hashlib.sha256(aad).digest(),
        info=b"controlforge/endpoint-credential-rotation/delivery/v1",
    ).derive(predecessor_secret)
    return key, aad


def _encode(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


def _decode(value: str) -> bytes:
    try:
        return base64.b64decode(
            value + "=" * (-len(value) % 4),
            altchars=b"-_",
            validate=True,
        )
    except (TypeError, ValueError) as exc:
        raise CredentialRotationEnvelopeError("credential rotation encoding is invalid") from exc


__all__ = [
    "CredentialRotationEnvelope",
    "CredentialRotationEnvelopeError",
    "CredentialRotationMaterial",
    "decrypt_rotation_envelope",
    "encrypt_rotation_material",
]
