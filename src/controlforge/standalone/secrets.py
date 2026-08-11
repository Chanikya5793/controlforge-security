"""Durable, permission-checked standalone appliance secret provisioning."""

from __future__ import annotations

import os
import secrets
import stat
from dataclasses import dataclass
from pathlib import Path
from typing import ClassVar


class SecretProvisioningError(RuntimeError):
    """Raised when durable appliance secrets cannot be trusted."""


@dataclass(frozen=True)
class StandaloneSecretBundle:
    session_pepper: bytes
    recovery_pepper: bytes
    credential_key: bytes
    audit_key: bytes

    _FILES: ClassVar[dict[str, str]] = {
        "session_pepper": "session.pepper",
        "recovery_pepper": "recovery.pepper",
        "credential_key": "credential.key",
        "audit_key": "audit.key",
    }

    @classmethod
    def load_or_create(cls, directory: Path) -> StandaloneSecretBundle:
        cls._prepare_directory(directory)
        values = {
            field: cls._load_or_create_file(directory / filename)
            for field, filename in cls._FILES.items()
        }
        return cls(**values)

    @classmethod
    def load_existing(cls, directory: Path) -> StandaloneSecretBundle:
        """Load a complete existing bundle without creating replacement key material."""

        cls._validate_directory(directory)
        values = {
            field: cls._load_file(directory / filename) for field, filename in cls._FILES.items()
        }
        return cls(**values)

    @staticmethod
    def _prepare_directory(directory: Path) -> None:
        try:
            directory.mkdir(mode=0o700, parents=True, exist_ok=True)
        except OSError as exc:
            raise SecretProvisioningError("appliance secret directory is unavailable") from exc
        StandaloneSecretBundle._validate_directory(directory)

    @staticmethod
    def _validate_directory(directory: Path) -> None:
        try:
            metadata = directory.lstat()
        except OSError as exc:
            raise SecretProvisioningError("appliance secret directory is unavailable") from exc
        if not stat.S_ISDIR(metadata.st_mode) or directory.is_symlink():
            raise SecretProvisioningError("appliance secret path is not a trusted directory")
        if metadata.st_uid != os.geteuid() or stat.S_IMODE(metadata.st_mode) & 0o077:
            raise SecretProvisioningError(
                "appliance secret directory must be owned by the runtime user with mode 0700"
            )

    @classmethod
    def _load_or_create_file(cls, path: Path) -> bytes:
        try:
            descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        except FileExistsError:
            return cls._load_file(path)
        except OSError as exc:
            raise SecretProvisioningError("appliance secret could not be created") from exc
        value = secrets.token_bytes(32)
        try:
            written = os.write(descriptor, value)
            if written != len(value):
                raise SecretProvisioningError("appliance secret write was incomplete")
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
        return cls._load_file(path)

    @staticmethod
    def _load_file(path: Path) -> bytes:
        try:
            metadata = path.lstat()
            if not stat.S_ISREG(metadata.st_mode) or path.is_symlink():
                raise SecretProvisioningError("appliance secret is not a regular file")
            if metadata.st_uid != os.geteuid() or stat.S_IMODE(metadata.st_mode) != 0o600:
                raise SecretProvisioningError(
                    "appliance secret must be owned by the runtime user with mode 0600"
                )
            value = path.read_bytes()
        except SecretProvisioningError:
            raise
        except OSError as exc:
            raise SecretProvisioningError("appliance secret could not be read") from exc
        if len(value) != 32:
            raise SecretProvisioningError("appliance secret has an invalid length")
        return value


__all__ = ["SecretProvisioningError", "StandaloneSecretBundle"]
