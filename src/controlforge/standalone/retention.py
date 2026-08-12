"""Tenant-scoped, evidence-preserving telemetry retention."""

from __future__ import annotations

import sqlite3
import uuid
from dataclasses import dataclass
from datetime import datetime, timedelta

from .audit import StandaloneAuditLog
from .database import StandaloneDatabase
from .identity import Capability, HumanIdentityService, SessionPrincipal
from .store import _utc_text


class RetentionError(RuntimeError):
    """Raised when retention cannot be applied without weakening evidence."""


@dataclass(frozen=True)
class RetentionPolicy:
    telemetry_days: int
    updated_by: str | None
    updated_at: datetime | None


@dataclass(frozen=True)
class RetentionPreview:
    telemetry_days: int
    cutoff_at: datetime
    terminal_jobs: int
    unreferenced_events: int


@dataclass(frozen=True)
class RetentionRun:
    run_id: str
    cutoff_at: datetime
    terminal_jobs_deleted: int
    unreferenced_events_deleted: int
    executed_by: str
    executed_at: datetime


class StandaloneRetentionService:
    """Preview and apply bounded retention without deleting alert evidence."""

    DEFAULT_TELEMETRY_DAYS = 90
    MIN_TELEMETRY_DAYS = 30
    MAX_TELEMETRY_DAYS = 3_650

    def __init__(
        self,
        database: StandaloneDatabase,
        identity: HumanIdentityService,
        audit: StandaloneAuditLog,
    ) -> None:
        self._database = database
        self._identity = identity
        self._audit = audit

    def policy(self, principal: SessionPrincipal) -> RetentionPolicy:
        self._identity.require_capability(principal, principal.tenant_id, Capability.VIEW)
        with self._database.connect() as connection:
            row = connection.execute(
                """
                SELECT telemetry_days, updated_by, updated_at
                FROM retention_policies WHERE tenant_id = ?
                """,
                (principal.tenant_id,),
            ).fetchone()
        if row is None:
            return RetentionPolicy(self.DEFAULT_TELEMETRY_DAYS, None, None)
        return RetentionPolicy(
            telemetry_days=int(row["telemetry_days"]),
            updated_by=str(row["updated_by"]),
            updated_at=self._parse_time(str(row["updated_at"])),
        )

    def set_policy(
        self,
        principal: SessionPrincipal,
        telemetry_days: int,
        now: datetime,
    ) -> RetentionPolicy:
        self._identity.require_capability(principal, principal.tenant_id, Capability.MANAGE)
        self._validate_days(telemetry_days)
        with self._database.connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            try:
                previous = self._policy_days(connection, principal.tenant_id)
                connection.execute(
                    """
                    INSERT INTO retention_policies(
                        tenant_id, telemetry_days, updated_by, updated_at
                    ) VALUES (?, ?, ?, ?)
                    ON CONFLICT(tenant_id) DO UPDATE SET
                        telemetry_days = excluded.telemetry_days,
                        updated_by = excluded.updated_by,
                        updated_at = excluded.updated_at
                    """,
                    (
                        principal.tenant_id,
                        telemetry_days,
                        principal.user_id,
                        _utc_text(now),
                    ),
                )
                self._audit.append(
                    connection,
                    principal.tenant_id,
                    "retention.policy_changed",
                    "user",
                    principal.user_id,
                    "retention_policy",
                    principal.tenant_id,
                    {"from_days": previous, "to_days": telemetry_days},
                    now,
                )
                connection.execute("COMMIT")
            except Exception:
                if connection.in_transaction:
                    connection.execute("ROLLBACK")
                raise
        return RetentionPolicy(telemetry_days, principal.user_id, now)

    def preview(self, principal: SessionPrincipal, now: datetime) -> RetentionPreview:
        self._identity.require_capability(principal, principal.tenant_id, Capability.VIEW)
        with self._database.connect() as connection:
            days = self._policy_days(connection, principal.tenant_id)
            return self._preview(connection, principal.tenant_id, days, now)

    def latest_run(self, principal: SessionPrincipal) -> RetentionRun | None:
        self._identity.require_capability(principal, principal.tenant_id, Capability.VIEW)
        with self._database.connect() as connection:
            row = connection.execute(
                """
                SELECT run_id, cutoff_at, terminal_jobs_deleted,
                       unreferenced_events_deleted, executed_by, executed_at
                FROM retention_runs WHERE tenant_id = ?
                ORDER BY executed_at DESC, run_id DESC LIMIT 1
                """,
                (principal.tenant_id,),
            ).fetchone()
        if row is None:
            return None
        return RetentionRun(
            run_id=str(row["run_id"]),
            cutoff_at=self._parse_time(str(row["cutoff_at"])),
            terminal_jobs_deleted=int(row["terminal_jobs_deleted"]),
            unreferenced_events_deleted=int(row["unreferenced_events_deleted"]),
            executed_by=str(row["executed_by"]),
            executed_at=self._parse_time(str(row["executed_at"])),
        )

    def apply(self, principal: SessionPrincipal, now: datetime) -> RetentionRun:
        self._identity.require_capability(principal, principal.tenant_id, Capability.MANAGE)
        verification = self._audit.verify(principal.tenant_id)
        if not verification.valid:
            raise RetentionError("retention refused because audit verification failed")

        run_id = str(uuid.uuid4())
        with self._database.connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            try:
                days = self._policy_days(connection, principal.tenant_id)
                preview = self._preview(connection, principal.tenant_id, days, now)
                jobs = connection.execute(
                    """
                    DELETE FROM detection_jobs
                    WHERE tenant_id = ?
                      AND status IN ('succeeded', 'dead')
                      AND updated_at < ?
                    """,
                    (principal.tenant_id, _utc_text(preview.cutoff_at)),
                )
                events = connection.execute(
                    """
                    DELETE FROM events
                    WHERE tenant_id = ? AND received_at < ?
                      AND NOT EXISTS (
                        SELECT 1 FROM detection_jobs j
                        WHERE j.tenant_id = events.tenant_id
                          AND j.event_id = events.event_id
                      )
                      AND NOT EXISTS (
                        SELECT 1 FROM alerts a
                        WHERE a.tenant_id = events.tenant_id
                          AND a.event_id = events.event_id
                      )
                    """,
                    (principal.tenant_id, _utc_text(preview.cutoff_at)),
                )
                jobs_deleted = self._rowcount(jobs)
                events_deleted = self._rowcount(events)
                if (
                    jobs_deleted != preview.terminal_jobs
                    or events_deleted != preview.unreferenced_events
                ):
                    raise RetentionError("retention counts changed inside the locked transaction")
                connection.execute(
                    """
                    INSERT INTO retention_runs(
                        tenant_id, run_id, cutoff_at, terminal_jobs_deleted,
                        unreferenced_events_deleted, executed_by, executed_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        principal.tenant_id,
                        run_id,
                        _utc_text(preview.cutoff_at),
                        jobs_deleted,
                        events_deleted,
                        principal.user_id,
                        _utc_text(now),
                    ),
                )
                self._audit.append(
                    connection,
                    principal.tenant_id,
                    "retention.applied",
                    "user",
                    principal.user_id,
                    "retention_run",
                    run_id,
                    {
                        "cutoff_at": _utc_text(preview.cutoff_at),
                        "telemetry_days": days,
                        "terminal_jobs_deleted": jobs_deleted,
                        "unreferenced_events_deleted": events_deleted,
                    },
                    now,
                )
                connection.execute("COMMIT")
            except Exception:
                if connection.in_transaction:
                    connection.execute("ROLLBACK")
                raise
        return RetentionRun(
            run_id=run_id,
            cutoff_at=preview.cutoff_at,
            terminal_jobs_deleted=jobs_deleted,
            unreferenced_events_deleted=events_deleted,
            executed_by=principal.user_id,
            executed_at=now,
        )

    def _preview(
        self,
        connection: sqlite3.Connection,
        tenant_id: str,
        days: int,
        now: datetime,
    ) -> RetentionPreview:
        cutoff = now - timedelta(days=days)
        cutoff_text = _utc_text(cutoff)
        terminal_jobs = int(
            connection.execute(
                """
                SELECT COUNT(*) FROM detection_jobs
                WHERE tenant_id = ?
                  AND status IN ('succeeded', 'dead')
                  AND updated_at < ?
                """,
                (tenant_id, cutoff_text),
            ).fetchone()[0]
        )
        unreferenced_events = int(
            connection.execute(
                """
                SELECT COUNT(*) FROM events e
                WHERE e.tenant_id = ? AND e.received_at < ?
                  AND NOT EXISTS (
                    SELECT 1 FROM alerts a
                    WHERE a.tenant_id = e.tenant_id AND a.event_id = e.event_id
                  )
                  AND NOT EXISTS (
                    SELECT 1 FROM detection_jobs j
                    WHERE j.tenant_id = e.tenant_id AND j.event_id = e.event_id
                      AND NOT (
                        j.status IN ('succeeded', 'dead') AND j.updated_at < ?
                      )
                  )
                """,
                (tenant_id, cutoff_text, cutoff_text),
            ).fetchone()[0]
        )
        return RetentionPreview(days, cutoff, terminal_jobs, unreferenced_events)

    def _policy_days(self, connection: sqlite3.Connection, tenant_id: str) -> int:
        row = connection.execute(
            "SELECT telemetry_days FROM retention_policies WHERE tenant_id = ?",
            (tenant_id,),
        ).fetchone()
        days = int(row["telemetry_days"]) if row is not None else self.DEFAULT_TELEMETRY_DAYS
        self._validate_days(days)
        return days

    @classmethod
    def _validate_days(cls, days: int) -> None:
        if not cls.MIN_TELEMETRY_DAYS <= days <= cls.MAX_TELEMETRY_DAYS:
            raise RetentionError("telemetry retention must be between 30 and 3650 days")

    @staticmethod
    def _rowcount(cursor: sqlite3.Cursor) -> int:
        if cursor.rowcount < 0:
            raise RetentionError("retention deletion count is unavailable")
        return cursor.rowcount

    @staticmethod
    def _parse_time(value: str) -> datetime:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))


__all__ = [
    "RetentionError",
    "RetentionPolicy",
    "RetentionPreview",
    "RetentionRun",
    "StandaloneRetentionService",
]
