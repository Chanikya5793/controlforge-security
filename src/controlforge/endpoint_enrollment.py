"""Fail-closed endpoint enrollment client for a standalone appliance."""

from __future__ import annotations

import http.client
import json
import os
import stat
import tempfile
import uuid
from contextlib import suppress
from pathlib import Path
from typing import Optional, Protocol

import yaml
from pydantic import AwareDatetime, BaseModel, ConfigDict, Field, ValidationError

from .collector_agent import CollectorDefinition, CollectorSecrets


class EndpointEnrollmentError(RuntimeError):
    """Raised when a one-time endpoint enrollment cannot be trusted."""


class EndpointEnrollmentResult(BaseModel):
    """Exact response returned once by the standalone enrollment boundary."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    tenant_id: str = Field(min_length=1, max_length=128)
    device_id: str = Field(min_length=1, max_length=128, pattern=r"^[A-Za-z0-9._:-]+$")
    credential_id: str = Field(min_length=36, max_length=36)
    credential_secret: str = Field(min_length=32, max_length=256)
    expires_at: AwareDatetime


class EnrollmentTransport(Protocol):
    def claim(
        self,
        host: str,
        port: int,
        body: bytes,
        timeout_seconds: float,
    ) -> tuple[int, bytes]: ...


class FixedHostEnrollmentTransport:
    """POST one enrollment claim to a validated host over trusted HTTPS."""

    def claim(
        self,
        host: str,
        port: int,
        body: bytes,
        timeout_seconds: float,
    ) -> tuple[int, bytes]:
        connection = http.client.HTTPSConnection(host, port=port, timeout=timeout_seconds)
        try:
            connection.request(
                "POST",
                "/v1/devices/enroll",
                body=body,
                headers={
                    "accept": "application/json",
                    "content-type": "application/json",
                    "user-agent": "ControlForge-Endpoint-Enroller/0.3",
                },
            )
            response = connection.getresponse()
            payload = response.read(16_385)
            if len(payload) > 16_384:
                raise EndpointEnrollmentError("enrollment response exceeds 16 KB")
            return response.status, payload
        finally:
            connection.close()


class StandaloneEndpointEnrollmentClient:
    """Exchange a one-use grant without accepting an arbitrary URL or redirect."""

    def __init__(
        self,
        api_host: str,
        *,
        api_port: int = 8443,
        transport: Optional[EnrollmentTransport] = None,
        timeout_seconds: float = 15.0,
    ) -> None:
        # Reuse the collector's pinned-host contract rather than accepting a URL,
        # scheme, path, credentials, or caller-selected TLS behavior.
        CollectorDefinition(
            api_host=api_host,
            api_port=api_port,
            device_id="enrollment-validation",
        )
        if timeout_seconds < 1 or timeout_seconds > 60:
            raise ValueError("enrollment timeout must be between 1 and 60 seconds")
        self._api_host = api_host
        self._api_port = api_port
        self._transport = transport or FixedHostEnrollmentTransport()
        self._timeout_seconds = timeout_seconds

    def claim(
        self,
        token: str,
        device_id: str,
        display_name: str,
    ) -> EndpointEnrollmentResult:
        definition = CollectorDefinition(
            api_host=self._api_host,
            api_port=self._api_port,
            device_id=device_id,
            access_proxy_required=False,
        )
        normalized_name = display_name.strip()
        if not normalized_name or len(normalized_name) > 100:
            raise ValueError("device display name must contain between 1 and 100 characters")
        if len(token) < 32 or len(token) > 128:
            raise EndpointEnrollmentError("enrollment grant is invalid")
        body = json.dumps(
            {
                "device_id": definition.device_id,
                "display_name": normalized_name,
                "platform": "macos",
                "token": token,
            },
            separators=(",", ":"),
            sort_keys=True,
        ).encode()
        try:
            status, payload = self._transport.claim(
                self._api_host,
                self._api_port,
                body,
                self._timeout_seconds,
            )
        except EndpointEnrollmentError:
            raise
        except (OSError, TimeoutError) as exc:
            raise EndpointEnrollmentError("standalone appliance enrollment request failed") from exc
        if status != 201:
            raise EndpointEnrollmentError(
                f"standalone appliance enrollment failed with HTTP {status}"
            )
        try:
            result = EndpointEnrollmentResult.model_validate_json(payload)
            uuid.UUID(result.credential_id)
        except (ValidationError, ValueError) as exc:
            raise EndpointEnrollmentError(
                "standalone appliance returned invalid credentials"
            ) from exc
        if result.device_id != device_id:
            raise EndpointEnrollmentError(
                "standalone appliance returned a different device identity"
            )
        return result


def standalone_collector_definition(
    current: CollectorDefinition,
    api_host: str,
    api_port: int,
    device_id: str,
) -> CollectorDefinition:
    """Preserve local paths and telemetry settings while switching control planes."""

    validated = CollectorDefinition(
        **{
            **current.model_dump(),
            "api_host": api_host,
            "api_port": api_port,
            "device_id": device_id,
            "credential_source": "macos_system_keychain",
            "access_proxy_required": False,
            "action_polling_enabled": True,
            "credential_rotation_enabled": True,
        }
    )
    return validated


def install_collector_definition(path: Path, definition: CollectorDefinition) -> None:
    """Atomically install a non-secret collector definition with mode 0600."""

    if path.exists() and (path.is_symlink() or not stat.S_ISREG(path.lstat().st_mode)):
        raise EndpointEnrollmentError("collector configuration path is not a regular file")
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    descriptor, temporary_name = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    temporary_path = Path(temporary_name)
    try:
        os.fchmod(descriptor, 0o600)
        payload = yaml.safe_dump(
            definition.model_dump(mode="json"),
            default_flow_style=False,
            sort_keys=True,
        ).encode()
        with os.fdopen(descriptor, "wb", closefd=True) as stream:
            descriptor = -1
            stream.write(payload)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary_path, path)
        directory_descriptor = os.open(path.parent, os.O_RDONLY)
        try:
            os.fsync(directory_descriptor)
        finally:
            os.close(directory_descriptor)
    except OSError as exc:
        raise EndpointEnrollmentError("collector configuration could not be installed") from exc
    finally:
        if descriptor >= 0:
            os.close(descriptor)
        with suppress(OSError):
            temporary_path.unlink(missing_ok=True)


def credentials_from_enrollment(result: EndpointEnrollmentResult) -> CollectorSecrets:
    """Convert a validated one-time response without adding cloud proxy credentials."""

    return CollectorSecrets(
        credential_id=result.credential_id,
        credential_secret=result.credential_secret,
        access_client_id=None,
        access_client_secret=None,
    )


__all__ = [
    "EndpointEnrollmentError",
    "EndpointEnrollmentResult",
    "FixedHostEnrollmentTransport",
    "StandaloneEndpointEnrollmentClient",
    "credentials_from_enrollment",
    "install_collector_definition",
    "standalone_collector_definition",
]
