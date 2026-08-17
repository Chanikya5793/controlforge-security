"""Bounded, tenant-scoped projections for the standalone analyst workspace."""

from __future__ import annotations

import json
import os
import sqlite3
import stat
from dataclasses import asdict, dataclass
from datetime import datetime, timedelta, timezone
from typing import Literal, Optional, cast

from .database import StandaloneDatabase
from .device_guidance import device_guidance
from .finding_guidance import finding_guidance
from .store import _utc_text

CaseFilterStatus = Literal["open", "investigating", "contained", "closed"]
CaseFilterPriority = Literal["low", "medium", "high", "critical"]


class PresentationError(RuntimeError):
    """Raised when a bounded dashboard projection cannot be produced safely."""


@dataclass(frozen=True)
class AppliancePosture:
    database_private: bool
    database_size_bytes: int
    journal_mode: str
    foreign_keys_enabled: bool
    schema_versions: tuple[int, ...]
    last_event_received_at: Optional[str]
    ingestion_lag_seconds: Optional[int]
    events_24h: int
    jobs_pending: int
    jobs_leased: int
    jobs_retry: int
    jobs_dead: int
    oldest_ready_at: Optional[str]
    devices_active: int
    devices_stale: int
    devices_never_seen: int
    audit_entries: int
    audit_checkpoints: int
    latest_audit_at: Optional[str]
    latest_backup_status: Optional[str]
    latest_backup_at: Optional[str]
    last_successful_backup_at: Optional[str]
    backup_failures: int

    def as_dict(self) -> dict[str, object]:
        return asdict(self)


class StandalonePresentationRepository:
    """Serve operational views without exposing raw records or filesystem paths."""

    _STALE_DEVICE_SECONDS = 900

    def __init__(self, database: StandaloneDatabase) -> None:
        self._database = database

    def posture(self, tenant_id: str, now: datetime) -> AppliancePosture:
        now_utc = self._aware_utc(now)
        since = _utc_text(now_utc.replace(microsecond=0) - timedelta(hours=24))
        stale_before = _utc_text(now_utc - timedelta(seconds=self._STALE_DEVICE_SECONDS))
        with self._database.connect() as connection:
            row = connection.execute(
                """
                SELECT
                  (SELECT MAX(received_at) FROM events WHERE tenant_id = ?) AS last_event,
                  (SELECT COUNT(*) FROM events
                   WHERE tenant_id = ? AND received_at >= ?) AS events_24h,
                  (SELECT COUNT(*) FROM detection_jobs
                   WHERE tenant_id = ? AND status = 'pending') AS jobs_pending,
                  (SELECT COUNT(*) FROM detection_jobs
                   WHERE tenant_id = ? AND status = 'leased') AS jobs_leased,
                  (SELECT COUNT(*) FROM detection_jobs
                   WHERE tenant_id = ? AND status = 'retry') AS jobs_retry,
                  (SELECT COUNT(*) FROM detection_jobs
                   WHERE tenant_id = ? AND status = 'dead') AS jobs_dead,
                  (SELECT MIN(available_at) FROM detection_jobs
                   WHERE tenant_id = ? AND status IN ('pending', 'retry')) AS oldest_ready,
                  (SELECT COUNT(*) FROM devices
                   WHERE tenant_id = ? AND status = 'active') AS devices_active,
                  (SELECT COUNT(*) FROM devices
                   WHERE tenant_id = ? AND status = 'active'
                     AND last_seen_at IS NOT NULL AND last_seen_at < ?) AS devices_stale,
                  (SELECT COUNT(*) FROM devices
                   WHERE tenant_id = ? AND status = 'active'
                     AND last_seen_at IS NULL) AS devices_never_seen,
                  (SELECT COUNT(*) FROM audit_log WHERE tenant_id = ?) AS audit_entries,
                  (SELECT COUNT(*) FROM audit_checkpoints
                   WHERE tenant_id = ?) AS audit_checkpoints,
                  (SELECT MAX(created_at) FROM audit_log
                   WHERE tenant_id = ?) AS latest_audit,
                  (SELECT status FROM backup_history
                   WHERE tenant_id = ? ORDER BY started_at DESC LIMIT 1) AS backup_status,
                  (SELECT COALESCE(completed_at, started_at) FROM backup_history
                   WHERE tenant_id = ? ORDER BY started_at DESC LIMIT 1) AS backup_at,
                  (SELECT MAX(completed_at) FROM backup_history
                   WHERE tenant_id = ? AND status IN ('succeeded', 'restored'))
                    AS backup_success_at,
                  (SELECT COUNT(*) FROM backup_history
                   WHERE tenant_id = ? AND status = 'failed') AS backup_failures
                """,
                (
                    tenant_id,
                    tenant_id,
                    since,
                    tenant_id,
                    tenant_id,
                    tenant_id,
                    tenant_id,
                    tenant_id,
                    tenant_id,
                    tenant_id,
                    stale_before,
                    tenant_id,
                    tenant_id,
                    tenant_id,
                    tenant_id,
                    tenant_id,
                    tenant_id,
                    tenant_id,
                    tenant_id,
                ),
            ).fetchone()
            journal = str(connection.execute("PRAGMA journal_mode").fetchone()[0]).casefold()
            foreign_keys = int(connection.execute("PRAGMA foreign_keys").fetchone()[0]) == 1
            schema_versions = tuple(
                int(item[0])
                for item in connection.execute(
                    "SELECT version FROM schema_migrations ORDER BY version"
                ).fetchall()
            )
        if row is None:
            raise PresentationError("appliance posture is unavailable")
        last_event = self._optional_text(row["last_event"])
        lag = (
            max(0, int((now_utc - self._parse_time(last_event)).total_seconds()))
            if last_event is not None
            else None
        )
        path = self._database.settings.database_path
        database_private = False
        database_size = 0
        try:
            metadata = path.lstat()
            database_private = bool(
                stat.S_ISREG(metadata.st_mode)
                and not path.is_symlink()
                and metadata.st_uid == os.geteuid()
                and stat.S_IMODE(metadata.st_mode) == 0o600
            )
            database_size = metadata.st_size
        except OSError:
            pass
        return AppliancePosture(
            database_private=database_private,
            database_size_bytes=database_size,
            journal_mode=journal,
            foreign_keys_enabled=foreign_keys,
            schema_versions=schema_versions,
            last_event_received_at=last_event,
            ingestion_lag_seconds=lag,
            events_24h=int(row["events_24h"]),
            jobs_pending=int(row["jobs_pending"]),
            jobs_leased=int(row["jobs_leased"]),
            jobs_retry=int(row["jobs_retry"]),
            jobs_dead=int(row["jobs_dead"]),
            oldest_ready_at=self._optional_text(row["oldest_ready"]),
            devices_active=int(row["devices_active"]),
            devices_stale=int(row["devices_stale"]),
            devices_never_seen=int(row["devices_never_seen"]),
            audit_entries=int(row["audit_entries"]),
            audit_checkpoints=int(row["audit_checkpoints"]),
            latest_audit_at=self._optional_text(row["latest_audit"]),
            latest_backup_status=self._optional_text(row["backup_status"]),
            latest_backup_at=self._optional_text(row["backup_at"]),
            last_successful_backup_at=self._optional_text(row["backup_success_at"]),
            backup_failures=int(row["backup_failures"]),
        )

    def device_health(
        self, tenant_id: str, now: datetime, limit: int = 200, *, device_id: Optional[str] = None
    ) -> list[dict[str, object]]:
        self._validate_limit(limit)
        if device_id is not None and (not device_id or len(device_id) > 128):
            raise PresentationError("invalid device identifier")
        now_utc = self._aware_utc(now)
        with self._database.connect() as connection:
            rows = connection.execute(
                """
                SELECT d.device_id, d.display_name, d.platform, d.status,
                       d.enrolled_at, d.last_seen_at,
                       MAX(e.received_at) AS last_telemetry_at,
                       (SELECT COUNT(*) FROM device_credentials c
                        WHERE c.tenant_id = d.tenant_id AND c.device_id = d.device_id
                          AND c.revoked_at IS NULL AND c.expires_at > ?)
                         AS active_credentials,
                       (SELECT MIN(c.expires_at) FROM device_credentials c
                        WHERE c.tenant_id = d.tenant_id AND c.device_id = d.device_id
                          AND c.revoked_at IS NULL AND c.expires_at > ?)
                         AS next_credential_expiry
                FROM devices d
                LEFT JOIN events e
                  ON e.tenant_id = d.tenant_id AND e.device_id = d.device_id
                WHERE d.tenant_id = ? AND (? IS NULL OR d.device_id = ?)
                GROUP BY d.tenant_id, d.device_id
                ORDER BY CASE d.status WHEN 'active' THEN 0 WHEN 'enrolling' THEN 1 ELSE 2 END,
                         d.last_seen_at DESC, d.display_name
                LIMIT ?
                """,
                (_utc_text(now_utc), _utc_text(now_utc), tenant_id, device_id, device_id, limit),
            ).fetchall()
        result: list[dict[str, object]] = []
        for row in rows:
            last_seen = self._optional_text(row["last_seen_at"])
            freshness = "revoked"
            if row["status"] == "active":
                if last_seen is None:
                    freshness = "never_seen"
                else:
                    age = (now_utc - self._parse_time(last_seen)).total_seconds()
                    freshness = (
                        "clock_skew"
                        if age < 0
                        else "fresh"
                        if age <= self._STALE_DEVICE_SECONDS
                        else "stale"
                    )
            elif row["status"] == "enrolling":
                freshness = "enrolling"
            result.append(
                {
                    "device_id": str(row["device_id"]),
                    "display_name": str(row["display_name"]),
                    "platform": str(row["platform"]),
                    "status": str(row["status"]),
                    "freshness": freshness,
                    "enrolled_at": self._optional_text(row["enrolled_at"]),
                    "last_seen_at": last_seen,
                    "last_telemetry_at": self._optional_text(row["last_telemetry_at"]),
                    "active_credentials": int(row["active_credentials"] or 0),
                    "next_credential_expiry": self._optional_text(row["next_credential_expiry"]),
                    "observed_at": _utc_text(now_utc),
                    "stale_after_seconds": self._STALE_DEVICE_SECONDS,
                    "guidance": device_guidance(
                        str(row["status"]), freshness, int(row["active_credentials"] or 0)
                    ),
                }
            )
        return result

    def case_queue(
        self,
        tenant_id: str,
        *,
        status: Optional[CaseFilterStatus] = None,
        priority: Optional[CaseFilterPriority] = None,
        query: str = "",
        limit: int = 200,
        device_id: Optional[str] = None,
    ) -> list[dict[str, object]]:
        self._validate_limit(limit)
        normalized_query = query.strip().casefold()
        if len(normalized_query) > 120:
            raise PresentationError("case search is too long")
        if device_id is not None and (not device_id or len(device_id) > 128):
            raise PresentationError("invalid device identifier")
        search = f"%{self._escape_like(normalized_query)}%"
        with self._database.connect() as connection:
            rows = connection.execute(
                """
                SELECT c.case_id, c.title, c.priority, c.status, c.assignee_user_id,
                       c.opened_at, c.updated_at, c.closed_at,
                       COUNT(DISTINCT ca.alert_id) AS alert_count,
                       MAX(a.created_at) AS latest_alert_at,
                       MAX(CASE a.severity
                           WHEN 'critical' THEN 5 WHEN 'high' THEN 4 WHEN 'medium' THEN 3
                           WHEN 'low' THEN 2 WHEN 'informational' THEN 1 ELSE 0 END)
                         AS severity_rank,
                       COUNT(DISTINCT CASE
                         WHEN r.status IN ('proposed', 'approved', 'dispatched')
                         THEN r.action_id END) AS live_response_count
                FROM cases c
                LEFT JOIN case_alerts ca
                  ON ca.tenant_id = c.tenant_id AND ca.case_id = c.case_id
                LEFT JOIN alerts a
                  ON a.tenant_id = ca.tenant_id AND a.alert_id = ca.alert_id
                LEFT JOIN response_actions r
                  ON r.tenant_id = c.tenant_id AND r.case_id = c.case_id
                WHERE c.tenant_id = ?
                  AND (? IS NULL OR c.status = ?)
                  AND (? IS NULL OR c.priority = ?)
                  AND (? IS NULL OR EXISTS (
                    SELECT 1 FROM case_alerts dca
                    JOIN alerts da
                      ON da.tenant_id = dca.tenant_id AND da.alert_id = dca.alert_id
                    JOIN events de
                      ON de.tenant_id = da.tenant_id AND de.event_id = da.event_id
                    WHERE dca.tenant_id = c.tenant_id AND dca.case_id = c.case_id
                      AND de.device_id = ?
                  ))
                  AND (
                    ? = '' OR lower(c.title) LIKE ? ESCAPE '\\'
                    OR lower(c.case_id) LIKE ? ESCAPE '\\'
                    OR EXISTS (
                      SELECT 1 FROM case_alerts sca
                      JOIN alerts sa
                        ON sa.tenant_id = sca.tenant_id AND sa.alert_id = sca.alert_id
                      WHERE sca.tenant_id = c.tenant_id AND sca.case_id = c.case_id
                        AND (lower(sa.title) LIKE ? ESCAPE '\\'
                             OR lower(sa.rule_id) LIKE ? ESCAPE '\\'
                             OR lower(sa.actor) LIKE ? ESCAPE '\\')
                    )
                  )
                GROUP BY c.tenant_id, c.case_id
                ORDER BY
                  CASE c.priority WHEN 'critical' THEN 0 WHEN 'high' THEN 1
                                  WHEN 'medium' THEN 2 ELSE 3 END,
                  CASE c.status WHEN 'investigating' THEN 0 WHEN 'open' THEN 1
                                WHEN 'contained' THEN 2 ELSE 3 END,
                  c.updated_at DESC, c.case_id DESC
                LIMIT ?
                """,
                (
                    tenant_id,
                    status,
                    status,
                    priority,
                    priority,
                    device_id,
                    device_id,
                    normalized_query,
                    search,
                    search,
                    search,
                    search,
                    search,
                    limit,
                ),
            ).fetchall()
        return [
            {
                "case_id": str(row["case_id"]),
                "title": str(row["title"]),
                "priority": str(row["priority"]),
                "status": str(row["status"]),
                "assignee_user_id": self._optional_text(row["assignee_user_id"]),
                "opened_at": str(row["opened_at"]),
                "updated_at": str(row["updated_at"]),
                "closed_at": self._optional_text(row["closed_at"]),
                "alert_count": int(row["alert_count"]),
                "recurrence_count": max(0, int(row["alert_count"]) - 1),
                "latest_alert_at": self._optional_text(row["latest_alert_at"]),
                "highest_severity": self._severity(int(row["severity_rank"] or 0)),
                "live_response_count": int(row["live_response_count"] or 0),
            }
            for row in rows
        ]

    def case_assignees(self, tenant_id: str) -> list[dict[str, object]]:
        """Return active same-tenant humans who can investigate cases."""

        with self._database.connect() as connection:
            rows = connection.execute(
                """
                SELECT user_id, display_name, role
                FROM users
                WHERE tenant_id = ? AND status = 'active'
                  AND role IN ('analyst', 'responder', 'admin')
                ORDER BY lower(display_name), user_id
                """,
                (tenant_id,),
            ).fetchall()
        return [
            {
                "user_id": str(row["user_id"]),
                "display_name": str(row["display_name"]),
                "role": str(row["role"]),
            }
            for row in rows
        ]

    def case_evidence(self, tenant_id: str, case_id: str) -> list[dict[str, object]]:
        with self._database.connect() as connection:
            rows = connection.execute(
                """
                SELECT a.alert_id, a.event_id, a.rule_id, a.rule_version, a.rule_digest,
                       a.rule_snapshot_json, a.fingerprint_version, a.detector_version,
                       a.title, a.severity, a.actor, a.reasons_json, a.tags_json,
                       a.evidence_json, a.created_at, e.event_type, e.occurred_at,
                       e.received_at, e.device_id, e.payload_sha256,
                       d.display_name AS device_name, d.status AS device_status,
                       dr.replay_mode, dr.outcome AS replay_outcome,
                       dr.created_at AS replayed_at
                FROM case_alerts ca
                JOIN alerts a
                  ON a.tenant_id = ca.tenant_id AND a.alert_id = ca.alert_id
                JOIN events e
                  ON e.tenant_id = a.tenant_id AND e.event_id = a.event_id
                LEFT JOIN devices d
                  ON d.tenant_id = e.tenant_id AND d.device_id = e.device_id
                LEFT JOIN detection_replays dr
                  ON dr.tenant_id = a.tenant_id AND dr.alert_id = a.alert_id
                 AND dr.created_at = (
                   SELECT MAX(r2.created_at) FROM detection_replays r2
                   WHERE r2.tenant_id = a.tenant_id AND r2.alert_id = a.alert_id
                 )
                WHERE ca.tenant_id = ? AND ca.case_id = ?
                ORDER BY a.created_at DESC, a.alert_id DESC
                LIMIT 200
                """,
                (tenant_id, case_id),
            ).fetchall()
        return [self._evidence_row(row) for row in rows]

    def response_queue(self, tenant_id: str, limit: int = 200) -> list[dict[str, object]]:
        self._validate_limit(limit)
        with self._database.connect() as connection:
            rows = connection.execute(
                """
                SELECT r.*, c.title AS case_title, d.display_name AS device_name,
                       proposer.display_name AS proposer_name,
                       approver.display_name AS approver_name,
                       rejector.display_name AS rejector_name
                FROM response_actions r
                JOIN cases c ON c.tenant_id = r.tenant_id AND c.case_id = r.case_id
                JOIN devices d ON d.tenant_id = r.tenant_id AND d.device_id = r.target_id
                LEFT JOIN users proposer
                  ON proposer.tenant_id = r.tenant_id AND proposer.user_id = r.proposed_by
                LEFT JOIN users approver
                  ON approver.tenant_id = r.tenant_id AND approver.user_id = r.approved_by
                LEFT JOIN users rejector
                  ON rejector.tenant_id = r.tenant_id AND rejector.user_id = r.rejected_by
                WHERE r.tenant_id = ? AND r.target_type = 'device'
                ORDER BY CASE r.status WHEN 'proposed' THEN 0 WHEN 'approved' THEN 1
                                       WHEN 'dispatched' THEN 2 ELSE 3 END,
                         r.proposed_at DESC, r.action_id DESC
                LIMIT ?
                """,
                (tenant_id, limit),
            ).fetchall()
        result: list[dict[str, object]] = []
        for row in rows:
            result_payload = self._json_object(row["result_json"], allow_none=True)
            evidence = result_payload.get("evidence", [])
            result.append(
                {
                    "action_id": str(row["action_id"]),
                    "case_id": str(row["case_id"]),
                    "case_title": str(row["case_title"]),
                    "action_type": str(row["action_type"]),
                    "device_id": str(row["target_id"]),
                    "device_name": str(row["device_name"]),
                    "rationale": str(row["rationale"]),
                    "status": str(row["status"]),
                    "proposed_by": str(row["proposed_by"]),
                    "proposer_name": self._optional_text(row["proposer_name"]) or "Unknown user",
                    "proposed_at": str(row["proposed_at"]),
                    "approved_by": self._optional_text(row["approved_by"]),
                    "approver_name": self._optional_text(row["approver_name"]),
                    "rejected_by": self._optional_text(row["rejected_by"]),
                    "rejector_name": self._optional_text(row["rejector_name"]),
                    "rejection_reason": self._optional_text(row["rejection_reason"]),
                    "expires_at": str(row["expires_at"]),
                    "completed_at": self._optional_text(row["completed_at"]),
                    "result_summary": (
                        str(result_payload["summary"])
                        if isinstance(result_payload.get("summary"), str)
                        else None
                    ),
                    "result_evidence": (
                        [str(item) for item in evidence if isinstance(item, str)]
                        if isinstance(evidence, list)
                        else []
                    ),
                }
            )
        return result

    def _evidence_row(self, row: sqlite3.Row) -> dict[str, object]:
        record = cast(dict[str, object], dict(row))
        reasons = self._json_string_list(record["reasons_json"])
        tags = self._json_string_list(record["tags_json"])
        evidence = self._json_object(record["evidence_json"])
        snapshot = self._json_object(record["rule_snapshot_json"])
        detection = snapshot.get("detection", {})
        logsource = snapshot.get("logsource", {})
        logsource_projection = (
            {
                str(key): str(value)
                for key, value in logsource.items()
                if isinstance(key, str) and isinstance(value, str)
            }
            if isinstance(logsource, dict)
            else {}
        )
        matched = evidence.get("matched_evidence", reasons)
        return {
            "alert_id": str(record["alert_id"]),
            "title": str(record["title"]),
            "severity": str(record["severity"]),
            "actor": str(record["actor"]),
            "created_at": str(record["created_at"]),
            "reasons": reasons,
            "tags": tags,
            "guidance": finding_guidance(
                str(record["event_type"]), device_bound=record["device_id"] is not None
            ),
            "device": (
                {
                    "device_id": str(record["device_id"]),
                    "display_name": str(record["device_name"]),
                    "status": str(record["device_status"]),
                }
                if record["device_name"] is not None
                else None
            ),
            "matched_evidence": (
                [str(item) for item in matched if isinstance(item, str)]
                if isinstance(matched, list)
                else reasons
            ),
            "event": {
                "event_id": str(record["event_id"]),
                "event_type": str(record["event_type"]),
                "occurred_at": str(record["occurred_at"]),
                "received_at": str(record["received_at"]),
                "device_id": self._optional_text(record["device_id"]),
                "payload_sha256": str(record["payload_sha256"]),
            },
            "rule": {
                "rule_id": str(record["rule_id"]),
                "rule_version": str(record["rule_version"]),
                "rule_digest": str(record["rule_digest"]),
                "fingerprint_version": str(record["fingerprint_version"]),
                "detector_version": str(record["detector_version"]),
                "description": (
                    str(snapshot["description"])
                    if isinstance(snapshot.get("description"), str)
                    else None
                ),
                "status": (
                    str(snapshot["status"]) if isinstance(snapshot.get("status"), str) else None
                ),
                "condition": (
                    str(detection["condition"])
                    if isinstance(detection, dict) and isinstance(detection.get("condition"), str)
                    else None
                ),
                "logsource": logsource_projection,
            },
            "latest_replay": (
                {
                    "mode": str(record["replay_mode"]),
                    "outcome": str(record["replay_outcome"]),
                    "created_at": str(record["replayed_at"]),
                }
                if record["replay_mode"] is not None
                else None
            ),
        }

    @staticmethod
    def _json_object(value: object, *, allow_none: bool = False) -> dict[str, object]:
        if value is None and allow_none:
            return {}
        try:
            parsed = json.loads(str(value))
        except (TypeError, ValueError) as exc:
            raise PresentationError("stored presentation data is invalid") from exc
        if not isinstance(parsed, dict):
            raise PresentationError("stored presentation data is invalid")
        return cast(dict[str, object], parsed)

    @staticmethod
    def _json_string_list(value: object) -> list[str]:
        try:
            parsed = json.loads(str(value))
        except (TypeError, ValueError) as exc:
            raise PresentationError("stored presentation data is invalid") from exc
        if not isinstance(parsed, list) or not all(isinstance(item, str) for item in parsed):
            raise PresentationError("stored presentation data is invalid")
        return cast(list[str], parsed)

    @staticmethod
    def _validate_limit(limit: int) -> None:
        if limit < 1 or limit > 200:
            raise PresentationError("dashboard limit must be between 1 and 200")

    @staticmethod
    def _escape_like(value: str) -> str:
        return value.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")

    @staticmethod
    def _optional_text(value: object) -> Optional[str]:
        return str(value) if value is not None else None

    @staticmethod
    def _severity(rank: int) -> Optional[str]:
        return {
            5: "critical",
            4: "high",
            3: "medium",
            2: "low",
            1: "informational",
        }.get(rank)

    @staticmethod
    def _aware_utc(value: datetime) -> datetime:
        if value.tzinfo is None:
            raise ValueError("presentation clock must be timezone-aware")
        return value.astimezone(timezone.utc)

    @staticmethod
    def _parse_time(value: str) -> datetime:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
        if parsed.tzinfo is None:
            raise PresentationError("stored presentation timestamp is invalid")
        return parsed.astimezone(timezone.utc)


__all__ = [
    "AppliancePosture",
    "CaseFilterPriority",
    "CaseFilterStatus",
    "PresentationError",
    "StandalonePresentationRepository",
]
