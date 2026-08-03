"""Bounded ingestion of North Pole Security Santa JSON telemetry."""

from __future__ import annotations

import json
import os
import re
import stat
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import ClassVar, Optional

from pydantic import BaseModel, Field, model_validator

from .models import SecurityEvent


class SantaLogError(RuntimeError):
    """Raised when the Santa telemetry boundary cannot be read safely."""


class SantaLogDefinition(BaseModel):
    """Non-secret configuration for a local Santa JSONL telemetry source."""

    enabled: bool = False
    log_path: Path = Path("/var/db/santa/santa.log")
    max_events_per_run: int = Field(default=500, ge=1, le=1_000)
    max_line_bytes: int = Field(default=131_072, ge=1_024, le=1_048_576)
    max_read_bytes: int = Field(default=2_000_000, ge=1_024, le=8_000_000)

    @model_validator(mode="after")
    def validate_enabled_path(self) -> SantaLogDefinition:
        if self.enabled and not self.log_path.is_absolute():
            raise ValueError("enabled Santa log_path must be absolute")
        return self


@dataclass(frozen=True)
class SourceCursor:
    device: int
    inode: int
    byte_offset: int


@dataclass(frozen=True)
class SantaReadBatch:
    events: list[SecurityEvent]
    rejected_lines: int
    cursor: SourceCursor


def _mapping(value: object) -> dict[str, object]:
    return value if isinstance(value, dict) else {}


def _text(value: object, maximum: int = 2_048) -> str:
    return value[:maximum] if isinstance(value, str) else ""


def _nested_text(value: object, *keys: str, maximum: int = 2_048) -> str:
    current = value
    for key in keys:
        current = _mapping(current).get(key)
    return _text(current, maximum)


def _parse_timestamp(value: object) -> datetime:
    """Parse Santa RFC 3339 timestamps while bounding nanoseconds to Python precision."""
    timestamp = _text(value, 40)
    match = re.fullmatch(
        r"(?P<seconds>\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})"
        r"(?:\.(?P<fraction>\d{1,9}))?"
        r"(?P<timezone>Z|[+-]\d{2}:\d{2})",
        timestamp,
    )
    if match is None:
        raise ValueError("Santa event_time must be an RFC 3339 timestamp")
    fraction = match.group("fraction")
    normalized_fraction = "" if fraction is None else f".{fraction[:6].ljust(6, '0')}"
    timezone_suffix = "+00:00" if match.group("timezone") == "Z" else match.group("timezone")
    occurred_at = datetime.fromisoformat(
        f"{match.group('seconds')}{normalized_fraction}{timezone_suffix}"
    )
    if occurred_at.tzinfo is None:
        raise ValueError("Santa event_time must include a timezone")
    return occurred_at


class SantaJsonLogReader:
    """Read complete JSONL records without trusting Santa's beta JSON schema."""

    _EVENT_TYPES: ClassVar[dict[str, str]] = {
        "execution": "santa_execution",
        "file_access": "santa_file_access",
        "gatekeeper_override": "santa_gatekeeper_override",
        "launch_item": "santa_launch_item",
        "tcc_modification": "santa_tcc_modification",
        "xprotect": "santa_xprotect",
    }

    def __init__(self, definition: SantaLogDefinition, device_id: str) -> None:
        self._definition = definition
        self._device_id = device_id

    @property
    def source_id(self) -> str:
        return f"santa-json:{self._definition.log_path}"

    def read(self, cursor: Optional[SourceCursor]) -> SantaReadBatch:
        path = self._definition.log_path
        try:
            path_info = path.lstat()
        except FileNotFoundError as exc:
            raise SantaLogError("Santa JSON telemetry file is unavailable") from exc
        if stat.S_ISLNK(path_info.st_mode) or not stat.S_ISREG(path_info.st_mode):
            raise SantaLogError("Santa JSON telemetry path must be a regular file")
        if path_info.st_mode & 0o022:
            raise SantaLogError("Santa JSON telemetry file must not be group or world writable")

        events: list[SecurityEvent] = []
        rejected = 0
        consumed = 0
        with path.open("rb") as stream:
            opened_info = stream.fileno()
            file_info = os.fstat(opened_info)
            if not stat.S_ISREG(file_info.st_mode):
                raise SantaLogError("Santa JSON telemetry changed during open")
            offset = 0
            if (
                cursor is not None
                and cursor.device == file_info.st_dev
                and cursor.inode == file_info.st_ino
                and 0 <= cursor.byte_offset <= file_info.st_size
            ):
                offset = cursor.byte_offset
            stream.seek(offset)

            while len(events) < self._definition.max_events_per_run:
                line_start = stream.tell()
                line = stream.readline(self._definition.max_line_bytes + 1)
                if not line:
                    break
                if len(line) > self._definition.max_line_bytes:
                    raise SantaLogError("Santa JSON telemetry line exceeds the configured limit")
                if not line.endswith(b"\n"):
                    stream.seek(line_start)
                    break
                if consumed + len(line) > self._definition.max_read_bytes:
                    stream.seek(line_start)
                    break
                consumed += len(line)
                try:
                    event = self._parse_line(line)
                except (UnicodeDecodeError, json.JSONDecodeError, ValueError):
                    rejected += 1
                    continue
                if event is not None:
                    events.append(event)

            next_cursor = SourceCursor(
                device=file_info.st_dev,
                inode=file_info.st_ino,
                byte_offset=stream.tell(),
            )
        return SantaReadBatch(events=events, rejected_lines=rejected, cursor=next_cursor)

    def _parse_line(self, line: bytes) -> Optional[SecurityEvent]:
        raw = json.loads(line.decode("utf-8"))
        if not isinstance(raw, dict):
            raise ValueError("Santa JSON record must be an object")
        event_id = _text(raw.get("event_id"), 32).casefold()
        if len(event_id) != 32 or any(
            character not in "0123456789abcdef" for character in event_id
        ):
            raise ValueError("Santa event_id must be a 32-character hexadecimal identifier")
        occurred_at = _parse_timestamp(raw.get("event_time"))

        event_key = next((key for key in self._EVENT_TYPES if isinstance(raw.get(key), dict)), None)
        if event_key is None:
            return None
        payload = _mapping(raw[event_key])
        attributes, actor, target = self._normalize(event_key, payload)
        attributes["santa_event_id"] = event_id
        attributes["santa_boot_session_uuid"] = _text(raw.get("boot_session_uuid"), 64)
        return SecurityEvent(
            event_id=f"santa:{event_id}",
            event_type=self._EVENT_TYPES[event_key],
            timestamp=occurred_at,
            actor=actor,
            target=target or None,
            device_id=self._device_id,
            attributes=attributes,
        )

    def _normalize(
        self,
        event_key: str,
        payload: dict[str, object],
    ) -> tuple[dict[str, object], str, str]:
        process = _mapping(payload.get("target" if event_key == "execution" else "instigator"))
        if event_key == "xprotect":
            xprotect_payload = _mapping(payload.get("detected")) or _mapping(
                payload.get("remediated")
            )
            process = _mapping(xprotect_payload.get("instigator"))
        executable = _mapping(process.get("executable"))
        code_signature = _mapping(process.get("code_signature"))
        effective_user = _mapping(process.get("effective_user"))
        process_path = _text(executable.get("path"))
        actor_name = _text(effective_user.get("name"), 320)
        actor = f"user:{actor_name}" if actor_name else f"device:{self._device_id}"
        attributes: dict[str, object] = {
            "source": "north-pole-security-santa",
            "process_path": process_path,
            "process_name": Path(process_path).name,
            "parent_process_path": _nested_text(payload, "instigator", "executable", "path"),
            "file_sha256": _nested_text(executable, "hash", "hash", maximum=64),
            "signing_id": _text(code_signature.get("signing_id"), 256),
            "team_id": _text(code_signature.get("team_id"), 32),
            "is_platform_binary": bool(process.get("is_platform_binary", False)),
        }
        target = process_path
        if event_key == "execution":
            attributes.update(
                {
                    "decision": _text(payload.get("decision"), 64),
                    "reason": _text(payload.get("reason"), 64),
                    "mode": _text(payload.get("mode"), 64),
                    "static_rule": bool(payload.get("static_rule", False)),
                }
            )
        elif event_key == "file_access":
            target = _nested_text(payload, "target", "path")
            attributes.update(
                {
                    "target_path": target,
                    "policy_name": _text(payload.get("policy_name"), 256),
                    "policy_version": _text(payload.get("policy_version"), 128),
                    "access_type": _text(payload.get("access_type"), 64),
                    "policy_decision": _text(payload.get("policy_decision"), 64),
                }
            )
        elif event_key == "gatekeeper_override":
            target = _nested_text(payload, "target", "path")
            target_signature = _mapping(payload.get("code_signature"))
            attributes.update(
                {
                    "target_path": target,
                    "target_signing_id": _text(target_signature.get("signing_id"), 256),
                    "target_team_id": _text(target_signature.get("team_id"), 32),
                }
            )
        elif event_key == "launch_item":
            target = _text(payload.get("item_path")) or _text(payload.get("executable_path"))
            attributes.update(
                {
                    "action": _text(payload.get("action"), 64),
                    "item_type": _text(payload.get("item_type"), 64),
                    "item_path": _text(payload.get("item_path")),
                    "app_path": _text(payload.get("app_path")),
                    "executable_path": _text(payload.get("executable_path")),
                    "managed": bool(payload.get("managed", False)),
                }
            )
        elif event_key == "tcc_modification":
            target = _text(payload.get("identity"), 512)
            attributes.update(
                {
                    "service": _text(payload.get("service"), 256),
                    "identity": target,
                    "identity_type": _text(payload.get("identity_type"), 64),
                    "event_type": _text(payload.get("event_type"), 64),
                    "authorization_right": _text(payload.get("authorization_right"), 64),
                    "authorization_reason": _text(payload.get("authorization_reason"), 64),
                }
            )
        elif event_key == "xprotect":
            event_variant = (
                "detected" if isinstance(payload.get("detected"), dict) else "remediated"
            )
            xprotect_payload = _mapping(payload.get(event_variant))
            target = _text(
                xprotect_payload.get(
                    "detected_path" if event_variant == "detected" else "remediated_path"
                )
            )
            attributes.update(
                {
                    "xprotect_event": event_variant,
                    "signature_version": _text(xprotect_payload.get("signature_version"), 128),
                    "malware_identifier": _text(xprotect_payload.get("malware_identifier"), 256),
                    "incident_identifier": _text(xprotect_payload.get("incident_identifier"), 256),
                    "action_type": _text(xprotect_payload.get("action_type"), 128),
                    "remediation_success": bool(xprotect_payload.get("success", False)),
                    "target_path": target,
                }
            )
        else:
            target = _nested_text(payload, "target", "path") or process_path
            attributes["event_payload"] = self._bounded_security_payload(event_key, payload)
        return attributes, actor, target

    @staticmethod
    def _bounded_security_payload(event_key: str, payload: dict[str, object]) -> dict[str, object]:
        allowed_keys = {
            "gatekeeper_override": {"target"},
            "launch_item": {"action"},
            "tcc_modification": {"event", "service", "decision"},
            "xprotect": {"detected", "remediated"},
        }.get(event_key, set())
        bounded: dict[str, object] = {}
        for key in sorted(allowed_keys):
            value = payload.get(key)
            if isinstance(value, (str, bool, int, float)):
                bounded[key] = _text(value) if isinstance(value, str) else value
            elif isinstance(value, dict):
                bounded[key] = {
                    child_key: _text(child_value)
                    for child_key, child_value in list(value.items())[:12]
                    if isinstance(child_value, str)
                }
        return bounded
