"""Read-only operational projections for the standalone admin dashboard."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta

from .database import StandaloneDatabase
from .store import _utc_text


@dataclass(frozen=True)
class OperationsSummary:
    events_24h: int
    alerts_24h: int
    critical_open: int
    open_cases: int
    active_devices: int
    pending_jobs: int
    dead_jobs: int


class StandaloneOperationsRepository:
    """Produce bounded tenant-scoped views without exposing raw database access."""

    def __init__(self, database: StandaloneDatabase) -> None:
        self._database = database

    def summary(self, tenant_id: str, now: datetime) -> OperationsSummary:
        since = _utc_text(now - timedelta(hours=24))
        with self._database.connect() as connection:
            row = connection.execute(
                """
                SELECT
                  (SELECT COUNT(*) FROM events
                   WHERE tenant_id = ? AND received_at >= ?) AS events_24h,
                  (SELECT COUNT(*) FROM alerts
                   WHERE tenant_id = ? AND created_at >= ?) AS alerts_24h,
                  (SELECT COUNT(*) FROM cases
                   WHERE tenant_id = ? AND priority = 'critical' AND status != 'closed')
                    AS critical_open,
                  (SELECT COUNT(*) FROM cases
                   WHERE tenant_id = ? AND status != 'closed') AS open_cases,
                  (SELECT COUNT(*) FROM devices
                   WHERE tenant_id = ? AND status = 'active') AS active_devices,
                  (SELECT COUNT(*) FROM detection_jobs
                   WHERE tenant_id = ? AND status IN ('pending', 'leased', 'retry'))
                    AS pending_jobs,
                  (SELECT COUNT(*) FROM detection_jobs
                   WHERE tenant_id = ? AND status = 'dead') AS dead_jobs
                """,
                (
                    tenant_id,
                    since,
                    tenant_id,
                    since,
                    tenant_id,
                    tenant_id,
                    tenant_id,
                    tenant_id,
                    tenant_id,
                ),
            ).fetchone()
        if row is None:
            raise RuntimeError("operations summary query returned no row")
        return OperationsSummary(
            events_24h=int(row["events_24h"]),
            alerts_24h=int(row["alerts_24h"]),
            critical_open=int(row["critical_open"]),
            open_cases=int(row["open_cases"]),
            active_devices=int(row["active_devices"]),
            pending_jobs=int(row["pending_jobs"]),
            dead_jobs=int(row["dead_jobs"]),
        )

    def recent_alerts(self, tenant_id: str, limit: int) -> list[dict[str, object]]:
        self._validate_limit(limit)
        with self._database.connect() as connection:
            rows = connection.execute(
                """
                SELECT alert_id, event_id, rule_id, rule_version, rule_digest,
                       fingerprint_version, detector_version, title, severity, actor,
                       reasons_json, tags_json, evidence_json, created_at
                FROM alerts WHERE tenant_id = ?
                ORDER BY created_at DESC, alert_id DESC LIMIT ?
                """,
                (tenant_id, limit),
            ).fetchall()
        return [dict(row) for row in rows]

    def recent_cases(self, tenant_id: str, limit: int) -> list[dict[str, object]]:
        self._validate_limit(limit)
        with self._database.connect() as connection:
            rows = connection.execute(
                """
                SELECT c.case_id, c.title, c.priority, c.status, c.assignee_user_id,
                       c.opened_at, c.updated_at, c.closed_at, COUNT(ca.alert_id) AS alert_count
                FROM cases c
                LEFT JOIN case_alerts ca
                  ON ca.tenant_id = c.tenant_id AND ca.case_id = c.case_id
                WHERE c.tenant_id = ?
                GROUP BY c.tenant_id, c.case_id
                ORDER BY c.updated_at DESC, c.case_id DESC LIMIT ?
                """,
                (tenant_id, limit),
            ).fetchall()
        return [dict(row) for row in rows]

    @staticmethod
    def _validate_limit(limit: int) -> None:
        if limit < 1 or limit > 200:
            raise ValueError("query limit must be between 1 and 200")


__all__ = ["OperationsSummary", "StandaloneOperationsRepository"]
