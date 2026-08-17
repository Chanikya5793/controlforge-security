"""Narrow privileged handoff from the Mac account UI to the existing enroller."""

from __future__ import annotations

import fcntl
import hashlib
import hmac
import os
import platform
import re
import stat
import tempfile
import uuid
from collections.abc import Callable, Iterator
from contextlib import contextmanager, suppress
from datetime import datetime, timezone
from pathlib import Path
from typing import Literal, Optional, Protocol

from pydantic import AwareDatetime, BaseModel, ConfigDict, Field, SecretStr, ValidationError

from .collector_agent import CollectorDefinition, MacOSSystemKeychain, load_collector_definition
from .endpoint_enrollment import (
    AccountEndpointEnrollmentResult,
    StandaloneEndpointEnrollmentClient,
    install_collector_definition,
    standalone_collector_definition,
)
from .macos_lifecycle import MacOSEndpointLifecycle

ACCOUNT_PROFILE = Path("/Library/ControlForge/status/account-server.json")
MEMBERSHIP_RECEIPT = Path("/Library/ControlForge/status/network-membership.json")
REQUEST_DIRECTORY = Path("/private/var/tmp")
COLLECTOR_CONFIG = Path("/Library/Application Support/ControlForge/collector.yml")


class MacAccountError(RuntimeError):
    """A bounded local enrollment error that never includes request or secret data."""


class AccountServerProfile(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    schema_version: Literal["controlforge-account-server-v1"] = "controlforge-account-server-v1"
    api_host: str = Field(min_length=1, max_length=253)
    api_port: int = Field(ge=1, le=65535)
    device_id: str = Field(min_length=1, max_length=128, pattern=r"^[A-Za-z0-9._:-]+$")

    def validated_definition(self, current: CollectorDefinition) -> CollectorDefinition:
        if current.keychain_service != "com.controlforge.collector.v2":
            raise MacAccountError(
                "the installed collector needs the current signed Keychain helper"
            )
        return standalone_collector_definition(
            current, self.api_host, self.api_port, self.device_id
        )


class AccountEnrollmentRequest(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    schema_version: Literal["controlforge-account-enrollment-v1"]
    grant: SecretStr = Field(min_length=32, max_length=128)
    expected_account_id: str = Field(min_length=1, max_length=128)
    expected_tenant_id: str = Field(min_length=1, max_length=128)
    expected_device_id: str = Field(min_length=1, max_length=128)
    display_name: str = Field(min_length=1, max_length=100)


class NetworkMembershipReceipt(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    schema_version: Literal["controlforge-network-membership-v1"] = (
        "controlforge-network-membership-v1"
    )
    api_host: str = Field(min_length=1, max_length=253)
    api_port: int = Field(ge=1, le=65535)
    device_id: str = Field(min_length=1, max_length=128)
    tenant_id: str = Field(min_length=1, max_length=128)
    account_id: str = Field(min_length=1, max_length=128)
    network_name: str = Field(min_length=1, max_length=120)
    local_uid: int = Field(ge=500, le=2**31 - 1)
    enrolled_at: AwareDatetime
    activation_state: Literal["configured", "reporting"]


class InitialCredentialStore(Protocol):
    def require_initial_empty(self) -> None: ...
    def store_initial(self, credential_id: str, credential_secret: str) -> None: ...


def _trusted_directory(path: Path, expected_uid: int) -> None:
    """Every ancestor must be non-writable and non-symlinked, not just the leaf."""
    for directory in (path, *path.parents):
        metadata = directory.lstat()
        if (
            not stat.S_ISDIR(metadata.st_mode)
            or metadata.st_uid not in {0, expected_uid}
            or stat.S_IMODE(metadata.st_mode) & 0o022
        ):
            raise MacAccountError("account configuration directory is not trusted")


def _read_owned_file(
    path: Path, owner_uid: int, mode: int, limit: int
) -> tuple[bytes, os.stat_result]:
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        metadata = os.fstat(descriptor)
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_uid != owner_uid
            or stat.S_IMODE(metadata.st_mode) != mode
            or metadata.st_nlink != 1
            or not 0 < metadata.st_size <= limit
        ):
            raise MacAccountError("account configuration file is not trusted")
        data = os.read(descriptor, limit + 1)
        if len(data) > limit or len(data) != metadata.st_size:
            raise MacAccountError("account configuration size changed during reading")
        return data, metadata
    finally:
        os.close(descriptor)


def _write_public_json(path: Path, model: BaseModel, expected_uid: int) -> None:
    _trusted_directory(path.parent, expected_uid)
    if path.exists() or path.is_symlink():
        _read_owned_file(path, expected_uid, 0o644, 4096)
    descriptor, name = tempfile.mkstemp(prefix=".controlforge-account-", dir=path.parent)
    temporary = Path(name)
    try:
        os.fchmod(descriptor, 0o644)
        with os.fdopen(descriptor, "wb") as stream:
            descriptor = -1
            stream.write(model.model_dump_json().encode())
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
        directory = os.open(path.parent, os.O_RDONLY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    finally:
        if descriptor >= 0:
            os.close(descriptor)
        with suppress(OSError):
            temporary.unlink()


def read_account_profile(
    path: Path = ACCOUNT_PROFILE, *, expected_uid: int = 0
) -> AccountServerProfile:
    try:
        _trusted_directory(path.parent, expected_uid)
        payload, _ = _read_owned_file(path, expected_uid, 0o644, 4096)
        profile = AccountServerProfile.model_validate_json(payload)
        CollectorDefinition(
            api_host=profile.api_host, api_port=profile.api_port, device_id=profile.device_id
        )
        return profile
    except (OSError, ValidationError, ValueError) as exc:
        raise MacAccountError("account server profile is missing or invalid") from exc


def read_account_request(
    uid: int,
    digest: str,
    now: datetime,
    *,
    directory: Path = REQUEST_DIRECTORY,
) -> AccountEnrollmentRequest:
    if (
        not 500 <= uid <= 2**31 - 1
        or re.fullmatch(r"[a-f0-9]{64}", digest) is None
        or now.tzinfo is None
    ):
        raise MacAccountError("account enrollment handoff identity is invalid")
    # No caller-controlled path: only a numeric UID and a fixed-length hex digest.
    path = directory / f"controlforge-enroll-{uid}-{digest}.json"
    try:
        data, metadata = _read_owned_file(path, uid, 0o600, 4096)
        age = now.timestamp() - metadata.st_mtime
        if (
            age < -60
            or age > 300
            or not hmac.compare_digest(hashlib.sha256(data).hexdigest(), digest)
        ):
            raise MacAccountError("account enrollment request changed or expired")
        return AccountEnrollmentRequest.model_validate_json(data)
    except (OSError, ValidationError, ValueError) as exc:
        raise MacAccountError("account enrollment request is unavailable or invalid") from exc


class MacAccountEnrollment:
    def __init__(
        self,
        *,
        profile_path: Path = ACCOUNT_PROFILE,
        receipt_path: Path = MEMBERSHIP_RECEIPT,
        config_path: Path = COLLECTOR_CONFIG,
        request_directory: Path = REQUEST_DIRECTORY,
        expected_uid: int = 0,
        euid: Callable[[], int] = os.geteuid,
        system: Callable[[], str] = platform.system,
        credential_store: Optional[InitialCredentialStore] = None,
        client_factory: Callable[
            ..., StandaloneEndpointEnrollmentClient
        ] = StandaloneEndpointEnrollmentClient,
        activate: Optional[Callable[[], object]] = None,
    ) -> None:
        self.profile_path = profile_path
        self.receipt_path = receipt_path
        self.config_path = config_path
        self.request_directory = request_directory
        self.expected_uid = expected_uid
        self._euid = euid
        self._system = system
        self._store = credential_store or MacOSSystemKeychain("com.controlforge.collector.v2")
        self._client_factory = client_factory
        self._activate = activate or MacOSEndpointLifecycle(collector_config=config_path).activate

    def _require_root(self) -> None:
        if self._system() != "Darwin" or self._euid() != 0:
            raise MacAccountError("account configuration requires a macOS administrator")

    @contextmanager
    def _exclusive(self) -> Iterator[None]:
        self._require_root()
        _trusted_directory(self.config_path.parent, self.expected_uid)
        descriptor = os.open(
            self.config_path.parent / "account-enrollment.lock",
            os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW | os.O_NONBLOCK,
            0o600,
        )
        try:
            metadata = os.fstat(descriptor)
            if (
                not stat.S_ISREG(metadata.st_mode)
                or metadata.st_uid != self.expected_uid
                or stat.S_IMODE(metadata.st_mode) != 0o600
                or metadata.st_nlink != 1
            ):
                raise MacAccountError("account enrollment lock is not trusted")
            try:
                fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError as exc:
                raise MacAccountError("another account enrollment is already running") from exc
            yield
        finally:
            os.close(descriptor)

    def configure_server(self, host: str, port: int) -> AccountServerProfile:
        with self._exclusive():
            return self._configure_server(host, port)

    def _configure_server(self, host: str, port: int) -> AccountServerProfile:
        self._store.require_initial_empty()
        _trusted_directory(self.config_path.parent, self.expected_uid)
        _read_owned_file(self.config_path, self.expected_uid, 0o600, 65536)
        current = load_collector_definition(self.config_path)
        profile = AccountServerProfile(api_host=host, api_port=port, device_id=str(uuid.uuid4()))
        profile.validated_definition(current)
        if self.profile_path.exists() or self.profile_path.is_symlink():
            previous = read_account_profile(self.profile_path, expected_uid=self.expected_uid)
            if previous.api_host == host and previous.api_port == port:
                return previous
            raise MacAccountError("a server profile already exists; explicit migration is required")
        _write_public_json(self.profile_path, profile, self.expected_uid)
        return profile

    def enroll(self, uid: int, digest: str, now: datetime) -> NetworkMembershipReceipt:
        with self._exclusive():
            return self._enroll(uid, digest, now)

    def _enroll(self, uid: int, digest: str, now: datetime) -> NetworkMembershipReceipt:
        request = read_account_request(uid, digest, now, directory=self.request_directory)
        profile = read_account_profile(self.profile_path, expected_uid=self.expected_uid)
        if profile.device_id != request.expected_device_id:
            raise MacAccountError("the Mac identity changed; sign in again before connecting")
        _trusted_directory(self.config_path.parent, self.expected_uid)
        _read_owned_file(self.config_path, self.expected_uid, 0o600, 65536)
        _trusted_directory(self.receipt_path.parent, self.expected_uid)
        if self.receipt_path.exists() or self.receipt_path.is_symlink():
            raise MacAccountError(
                "this Mac already has a network enrollment; use finish activation"
            )
        current = load_collector_definition(self.config_path)
        definition = profile.validated_definition(current)
        self._store.require_initial_empty()
        install_collector_definition(self.config_path, definition)
        result = self._client_factory(
            profile.api_host, api_port=profile.api_port, account_context=True
        ).claim(
            request.grant.get_secret_value(),
            profile.device_id,
            request.display_name,
        )
        if (
            not isinstance(result, AccountEndpointEnrollmentResult)
            or result.account_id != request.expected_account_id
            or result.tenant_id != request.expected_tenant_id
            or result.device_id != profile.device_id
            or result.expires_at <= now
        ):
            raise MacAccountError("server returned an unexpected account or network")
        self._store.store_initial(result.credential_id, result.credential_secret)
        receipt = NetworkMembershipReceipt(
            api_host=profile.api_host,
            api_port=profile.api_port,
            device_id=result.device_id,
            tenant_id=result.tenant_id,
            account_id=result.account_id,
            network_name=result.network_name,
            local_uid=uid,
            enrolled_at=now.astimezone(timezone.utc),
            activation_state="configured",
        )
        _write_public_json(self.receipt_path, receipt, self.expected_uid)
        try:
            self._activate()
        except Exception as exc:
            raise MacAccountError(
                "device credentials are installed; finish activation to check in"
            ) from exc
        receipt = receipt.model_copy(update={"activation_state": "reporting"})
        _write_public_json(self.receipt_path, receipt, self.expected_uid)
        return receipt

    def finish_activation(self, uid: int) -> NetworkMembershipReceipt:
        with self._exclusive():
            return self._finish_activation(uid)

    def _finish_activation(self, uid: int) -> NetworkMembershipReceipt:
        if not 500 <= uid <= 2**31 - 1:
            raise MacAccountError("local account identity is invalid")
        profile = read_account_profile(self.profile_path, expected_uid=self.expected_uid)
        _trusted_directory(self.receipt_path.parent, self.expected_uid)
        raw, _ = _read_owned_file(self.receipt_path, self.expected_uid, 0o644, 4096)
        receipt = NetworkMembershipReceipt.model_validate_json(raw)
        if (
            receipt.local_uid != uid
            or receipt.device_id != profile.device_id
            or receipt.api_host != profile.api_host
            or receipt.api_port != profile.api_port
        ):
            raise MacAccountError("this local account does not own the pending enrollment")
        _trusted_directory(self.config_path.parent, self.expected_uid)
        _read_owned_file(self.config_path, self.expected_uid, 0o600, 65536)
        definition = load_collector_definition(self.config_path)
        if (
            definition.device_id != profile.device_id
            or definition.api_host != profile.api_host
            or definition.api_port != profile.api_port
            or definition.access_proxy_required
            or definition.credential_source != "macos_system_keychain"
            or definition.keychain_service != "com.controlforge.collector.v2"
        ):
            raise MacAccountError(
                "collector configuration no longer matches the pending enrollment"
            )
        self._activate()
        receipt = receipt.model_copy(update={"activation_state": "reporting"})
        _write_public_json(self.receipt_path, receipt, self.expected_uid)
        return receipt
