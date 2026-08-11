"""Authenticated, device-bound standalone collector ingestion service."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from typing import Optional

from pydantic import AwareDatetime, BaseModel, ConfigDict, Field, ValidationError

from controlforge.models import SecurityEvent

from .auth import DeviceHmacAuthenticator, SignedCollectorRequest
from .store import StandaloneStore


class CollectorIngestionError(RuntimeError):
    """Raised when an authenticated collector batch is invalid."""


class DeviceBindingError(CollectorIngestionError):
    """Raised when telemetry does not belong to the authenticated device."""


class CollectorSecurityEvent(SecurityEvent):
    model_config = ConfigDict(extra="forbid")

    event_id: str = Field(min_length=1, max_length=128, pattern=r"^[A-Za-z0-9._:-]+$")
    event_type: str = Field(min_length=1, max_length=128, pattern=r"^[A-Za-z0-9._:-]+$")
    timestamp: AwareDatetime
    actor: str = Field(min_length=1, max_length=320)
    source_ip: Optional[str] = Field(default=None, min_length=2, max_length=45)
    target: Optional[str] = Field(default=None, min_length=1, max_length=512)
    device_id: str = Field(
        min_length=1,
        max_length=128,
        pattern=r"^[A-Za-z0-9._:-]+$",
    )


class CollectorEventBatch(BaseModel):
    model_config = ConfigDict(extra="forbid")

    events: list[CollectorSecurityEvent] = Field(min_length=1, max_length=1_000)


@dataclass(frozen=True)
class CollectorIngestionResult:
    tenant_id: str
    device_id: str
    accepted: int
    duplicates: int
    event_ids: tuple[str, ...]


class CollectorIngestionService:
    """Authenticate, validate device ownership, and durably enqueue telemetry."""

    def __init__(
        self,
        authenticator: DeviceHmacAuthenticator,
        store: StandaloneStore,
        max_body_bytes: int = 8_000_000,
    ) -> None:
        if max_body_bytes < 1_024 or max_body_bytes > 16_000_000:
            raise ValueError("max_body_bytes must be between 1024 and 16000000")
        self._authenticator = authenticator
        self._store = store
        self._max_body_bytes = max_body_bytes

    def ingest(
        self,
        request: SignedCollectorRequest,
        received_at: datetime,
    ) -> CollectorIngestionResult:
        if len(request.body) > self._max_body_bytes:
            raise CollectorIngestionError("collector request exceeds the ingestion limit")
        principal = self._authenticator.authenticate(request, received_at)
        try:
            batch = CollectorEventBatch.model_validate_json(request.body)
        except ValidationError as exc:
            raise CollectorIngestionError("collector event batch failed schema validation") from exc
        events = [SecurityEvent.model_validate(event.model_dump()) for event in batch.events]
        if any(event.device_id != principal.device_id for event in events):
            raise DeviceBindingError("every collector event must match the authenticated device")
        results = self._store.ingest_events(principal.tenant_id, events, received_at)
        return CollectorIngestionResult(
            tenant_id=principal.tenant_id,
            device_id=principal.device_id,
            accepted=sum(result.accepted for result in results),
            duplicates=sum(not result.accepted for result in results),
            event_ids=tuple(result.event_id for result in results if result.accepted),
        )
