"""Immutable HMAC-chained audit storage for the standalone appliance."""

from __future__ import annotations

import hashlib
import hmac
import json
import sqlite3
import uuid
from dataclasses import dataclass
from datetime import datetime
from typing import Optional

from .database import StandaloneDatabase
from .store import _utc_text


class AuditError(RuntimeError):
    """Raised when an audit entry cannot be safely persisted."""


@dataclass(frozen=True)
class AuditEntry:
    sequence: int
    audit_id: str
    tenant_id: str
    action: str
    actor_type: str
    actor_id: str
    resource_type: str
    resource_id: str
    payload: dict[str, object]
    previous_hmac: Optional[str]
    integrity_hmac: str
    created_at: datetime


@dataclass(frozen=True)
class AuditVerification:
    valid: bool
    entries_checked: int
    checkpoints_checked: int
    terminal_hmac: Optional[str]
    failure_sequence: Optional[int] = None
    reason: Optional[str] = None


class StandaloneAuditLog:
    """Append and verify a per-tenant HMAC chain inside caller transactions."""

    _CHAIN_VERSION = "controlforge-audit-v1"
    _MAX_PAYLOAD_BYTES = 65_536

    def __init__(self, database: StandaloneDatabase, audit_key: bytes) -> None:
        if len(audit_key) < 32:
            raise ValueError("audit key must contain at least 32 bytes")
        self._database = database
        self._audit_key = audit_key

    def append(
        self,
        connection: sqlite3.Connection,
        tenant_id: str,
        action: str,
        actor_type: str,
        actor_id: str,
        resource_type: str,
        resource_id: str,
        payload: dict[str, object],
        now: datetime,
    ) -> AuditEntry:
        """Append one entry and immutable terminal checkpoint to an active transaction."""

        if not connection.in_transaction:
            raise AuditError("audit append requires an active database transaction")
        for name, value in {
            "tenant_id": tenant_id,
            "action": action,
            "actor_type": actor_type,
            "actor_id": actor_id,
            "resource_type": resource_type,
            "resource_id": resource_id,
        }.items():
            if not value or len(value) > 256:
                raise AuditError(f"audit {name} is invalid")
        try:
            payload_json = json.dumps(
                payload,
                ensure_ascii=False,
                separators=(",", ":"),
                sort_keys=True,
                allow_nan=False,
            )
        except (TypeError, ValueError) as exc:
            raise AuditError("audit payload is not canonical JSON") from exc
        if len(payload_json.encode("utf-8")) > self._MAX_PAYLOAD_BYTES:
            raise AuditError("audit payload exceeds the bounded size")

        previous = connection.execute(
            """
            SELECT integrity_hmac FROM audit_log
            WHERE tenant_id = ? ORDER BY sequence DESC LIMIT 1
            """,
            (tenant_id,),
        ).fetchone()
        previous_hmac = str(previous["integrity_hmac"]) if previous is not None else None
        audit_id = str(uuid.uuid4())
        created_at = _utc_text(now)
        integrity_hmac = self._entry_hmac(
            tenant_id,
            audit_id,
            action,
            actor_type,
            actor_id,
            resource_type,
            resource_id,
            payload_json,
            previous_hmac,
            created_at,
        )
        cursor = connection.execute(
            """
            INSERT INTO audit_log(
                audit_id, tenant_id, action, actor_type, actor_id,
                resource_type, resource_id, payload_json, previous_hmac,
                integrity_hmac, created_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                audit_id,
                tenant_id,
                action,
                actor_type,
                actor_id,
                resource_type,
                resource_id,
                payload_json,
                previous_hmac,
                integrity_hmac,
                created_at,
            ),
        )
        if cursor.lastrowid is None:
            raise AuditError("audit sequence was not allocated")
        sequence = cursor.lastrowid
        checkpoint_id = str(uuid.uuid4())
        checkpoint_signature = self._checkpoint_hmac(
            checkpoint_id,
            tenant_id,
            sequence,
            integrity_hmac,
            created_at,
        )
        connection.execute(
            """
            INSERT INTO audit_checkpoints(
                checkpoint_id, tenant_id, through_sequence,
                terminal_hmac, signature, created_at
            ) VALUES (?, ?, ?, ?, ?, ?)
            """,
            (
                checkpoint_id,
                tenant_id,
                sequence,
                integrity_hmac,
                checkpoint_signature,
                created_at,
            ),
        )
        return AuditEntry(
            sequence=sequence,
            audit_id=audit_id,
            tenant_id=tenant_id,
            action=action,
            actor_type=actor_type,
            actor_id=actor_id,
            resource_type=resource_type,
            resource_id=resource_id,
            payload=payload,
            previous_hmac=previous_hmac,
            integrity_hmac=integrity_hmac,
            created_at=self._parse_time(created_at),
        )

    def verify(self, tenant_id: str) -> AuditVerification:
        """Verify every entry, link, and immutable terminal checkpoint for a tenant."""

        with self._database.connect() as connection:
            entries = connection.execute(
                """
                SELECT * FROM audit_log
                WHERE tenant_id = ? ORDER BY sequence
                """,
                (tenant_id,),
            ).fetchall()
            checkpoints = connection.execute(
                """
                SELECT * FROM audit_checkpoints
                WHERE tenant_id = ? ORDER BY through_sequence
                """,
                (tenant_id,),
            ).fetchall()

        previous_hmac: Optional[str] = None
        entries_by_sequence: dict[int, str] = {}
        for index, row in enumerate(entries):
            sequence = int(row["sequence"])
            payload_json = str(row["payload_json"])
            try:
                payload = json.loads(payload_json)
            except (TypeError, ValueError):
                return self._invalid(index, 0, previous_hmac, sequence, "payload is not JSON")
            if not isinstance(payload, dict):
                return self._invalid(index, 0, previous_hmac, sequence, "payload is not an object")
            stored_previous = row["previous_hmac"]
            if stored_previous != previous_hmac:
                return self._invalid(index, 0, previous_hmac, sequence, "chain link mismatch")
            expected = self._entry_hmac(
                str(row["tenant_id"]),
                str(row["audit_id"]),
                str(row["action"]),
                str(row["actor_type"]),
                str(row["actor_id"]),
                str(row["resource_type"]),
                str(row["resource_id"]),
                payload_json,
                previous_hmac,
                str(row["created_at"]),
            )
            stored_hmac = str(row["integrity_hmac"])
            if not hmac.compare_digest(stored_hmac, expected):
                return self._invalid(index, 0, previous_hmac, sequence, "entry HMAC mismatch")
            entries_by_sequence[sequence] = stored_hmac
            previous_hmac = stored_hmac

        if len(checkpoints) != len(entries):
            return self._invalid(
                len(entries),
                0,
                previous_hmac,
                None,
                "checkpoint count does not match entry count",
            )
        for index, row in enumerate(checkpoints):
            sequence = int(row["through_sequence"])
            terminal_hmac = str(row["terminal_hmac"])
            if entries_by_sequence.get(sequence) != terminal_hmac:
                return self._invalid(
                    len(entries),
                    index,
                    previous_hmac,
                    sequence,
                    "checkpoint does not reference its audit entry",
                )
            expected = self._checkpoint_hmac(
                str(row["checkpoint_id"]),
                str(row["tenant_id"]),
                sequence,
                terminal_hmac,
                str(row["created_at"]),
            )
            if not hmac.compare_digest(str(row["signature"]), expected):
                return self._invalid(
                    len(entries),
                    index,
                    previous_hmac,
                    sequence,
                    "checkpoint HMAC mismatch",
                )
        return AuditVerification(
            valid=True,
            entries_checked=len(entries),
            checkpoints_checked=len(checkpoints),
            terminal_hmac=previous_hmac,
        )

    def _entry_hmac(
        self,
        tenant_id: str,
        audit_id: str,
        action: str,
        actor_type: str,
        actor_id: str,
        resource_type: str,
        resource_id: str,
        payload_json: str,
        previous_hmac: Optional[str],
        created_at: str,
    ) -> str:
        material = json.dumps(
            {
                "action": action,
                "actor_id": actor_id,
                "actor_type": actor_type,
                "audit_id": audit_id,
                "chain_version": self._CHAIN_VERSION,
                "created_at": created_at,
                "payload_json": payload_json,
                "previous_hmac": previous_hmac,
                "resource_id": resource_id,
                "resource_type": resource_type,
                "tenant_id": tenant_id,
            },
            separators=(",", ":"),
            sort_keys=True,
        ).encode()
        return hmac.new(self._audit_key, material, hashlib.sha256).hexdigest()

    def _checkpoint_hmac(
        self,
        checkpoint_id: str,
        tenant_id: str,
        through_sequence: int,
        terminal_hmac: str,
        created_at: str,
    ) -> str:
        material = json.dumps(
            {
                "chain_version": self._CHAIN_VERSION,
                "checkpoint_id": checkpoint_id,
                "created_at": created_at,
                "tenant_id": tenant_id,
                "terminal_hmac": terminal_hmac,
                "through_sequence": through_sequence,
            },
            separators=(",", ":"),
            sort_keys=True,
        ).encode()
        return hmac.new(self._audit_key, material, hashlib.sha256).hexdigest()

    @staticmethod
    def _invalid(
        entries_checked: int,
        checkpoints_checked: int,
        terminal_hmac: Optional[str],
        sequence: Optional[int],
        reason: str,
    ) -> AuditVerification:
        return AuditVerification(
            valid=False,
            entries_checked=entries_checked,
            checkpoints_checked=checkpoints_checked,
            terminal_hmac=terminal_hmac,
            failure_sequence=sequence,
            reason=reason,
        )

    @staticmethod
    def _parse_time(value: str) -> datetime:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))


__all__ = [
    "AuditEntry",
    "AuditError",
    "AuditVerification",
    "StandaloneAuditLog",
]
