"""Transactional event ingestion and durable detection-job primitives."""

from __future__ import annotations

import hashlib
import json
import sqlite3
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Literal, Optional

from controlforge.detections import stateful_correlation_for_event
from controlforge.models import DetectionAlert, SecurityEvent

from .database import StandaloneDatabase


class EventIdentityConflict(ValueError):
    """Raised when an existing event identity is reused for different content."""


JobStatus = Literal["pending", "leased", "retry", "succeeded", "dead"]


@dataclass(frozen=True)
class IngestResult:
    accepted: bool
    event_id: str
    job_id: str


@dataclass(frozen=True)
class JobLease:
    tenant_id: str
    job_id: str
    event_id: str
    attempts: int
    lease_owner: str
    lease_expires_at: datetime


@dataclass(frozen=True)
class JobTransition:
    changed: bool
    status: JobStatus
    attempts: int


@dataclass(frozen=True)
class AlertPersistenceResult:
    inserted_alerts: int
    job_status: JobStatus


class LeaseOwnershipError(RuntimeError):
    """Raised when a worker tries to persist without a current owned lease."""


def _utc_text(value: datetime) -> str:
    if value.tzinfo is None:
        raise ValueError("timestamps must be timezone-aware")
    return value.astimezone(timezone.utc).isoformat(timespec="microseconds").replace("+00:00", "Z")


def _parse_utc(value: str) -> datetime:
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


def _canonical_event(event: SecurityEvent) -> str:
    return json.dumps(
        event.model_dump(mode="json", exclude_none=True),
        separators=(",", ":"),
        sort_keys=True,
    )


def _job_id(tenant_id: str, event_id: str) -> str:
    return hashlib.sha256(f"{tenant_id}:detect:{event_id}:v1".encode()).hexdigest()


class StandaloneStore:
    """Minimal repository for the durable standalone processing boundary."""

    def __init__(self, database: StandaloneDatabase) -> None:
        self._database = database

    def create_tenant(
        self,
        tenant_id: str,
        slug: str,
        display_name: str,
        now: datetime,
    ) -> None:
        with self._database.connect() as connection:
            connection.execute(
                """
                INSERT INTO tenants(tenant_id, slug, display_name, status, created_at)
                VALUES (?, ?, ?, 'active', ?)
                """,
                (tenant_id, slug, display_name, _utc_text(now)),
            )

    def active_tenant_ids(self) -> list[str]:
        with self._database.connect() as connection:
            rows = connection.execute(
                "SELECT tenant_id FROM tenants WHERE status = 'active' ORDER BY tenant_id"
            ).fetchall()
        return [str(row["tenant_id"]) for row in rows]

    def register_device(
        self,
        tenant_id: str,
        device_id: str,
        display_name: str,
        platform: str,
        now: datetime,
    ) -> None:
        timestamp = _utc_text(now)
        with self._database.connect() as connection:
            connection.execute(
                """
                INSERT INTO devices(
                    tenant_id, device_id, display_name, platform, status, enrolled_at, last_seen_at
                ) VALUES (?, ?, ?, ?, 'active', ?, ?)
                """,
                (tenant_id, device_id, display_name, platform, timestamp, timestamp),
            )

    def register_device_credential(
        self,
        credential_id: str,
        tenant_id: str,
        device_id: str,
        name: str,
        secret_ciphertext: str,
        secret_iv: str,
        created_at: datetime,
        expires_at: datetime,
    ) -> None:
        """Persist encrypted credential material bound to exactly one device."""

        with self._database.connect() as connection:
            connection.execute(
                """
                INSERT INTO device_credentials(
                    credential_id, tenant_id, device_id, name, secret_ciphertext,
                    secret_iv, created_at, expires_at, activated_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    credential_id,
                    tenant_id,
                    device_id,
                    name,
                    secret_ciphertext,
                    secret_iv,
                    _utc_text(created_at),
                    _utc_text(expires_at),
                    _utc_text(created_at),
                ),
            )

    def ingest_event(
        self,
        tenant_id: str,
        event: SecurityEvent,
        received_at: datetime,
    ) -> IngestResult:
        """Persist an event and its detection job in one immediate transaction."""

        timestamp = _utc_text(received_at)
        with self._database.connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            try:
                result = self._ingest_on_connection(connection, tenant_id, event, timestamp)
                connection.execute("COMMIT")
            except Exception:
                if connection.in_transaction:
                    connection.execute("ROLLBACK")
                raise
        return result

    def ingest_events(
        self,
        tenant_id: str,
        events: list[SecurityEvent],
        received_at: datetime,
    ) -> list[IngestResult]:
        """Persist a validated batch and all corresponding jobs atomically."""

        if not events:
            raise ValueError("event batch must not be empty")
        if len(events) > 1_000:
            raise ValueError("event batch must contain at most 1000 events")
        timestamp = _utc_text(received_at)
        with self._database.connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            try:
                results = [
                    self._ingest_on_connection(connection, tenant_id, event, timestamp)
                    for event in events
                ]
                connection.execute("COMMIT")
            except Exception:
                if connection.in_transaction:
                    connection.execute("ROLLBACK")
                raise
        return results

    @staticmethod
    def _ingest_on_connection(
        connection: sqlite3.Connection,
        tenant_id: str,
        event: SecurityEvent,
        received_at: str,
    ) -> IngestResult:
        payload = _canonical_event(event)
        payload_sha256 = hashlib.sha256(payload.encode()).hexdigest()
        job_id = _job_id(tenant_id, event.event_id)
        cursor = connection.execute(
            """
            INSERT OR IGNORE INTO events(
                tenant_id, event_id, event_type, occurred_at, received_at, actor,
                source_ip, target, device_id, payload_json, payload_sha256
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                tenant_id,
                event.event_id,
                event.event_type,
                _utc_text(event.timestamp),
                received_at,
                event.actor,
                event.source_ip,
                event.target,
                event.device_id,
                payload,
                payload_sha256,
            ),
        )
        accepted = cursor.rowcount == 1
        if accepted:
            connection.execute(
                """
                INSERT INTO detection_jobs(
                    tenant_id, job_id, event_id, status, available_at,
                    created_at, updated_at
                ) VALUES (?, ?, ?, 'pending', ?, ?, ?)
                """,
                (tenant_id, job_id, event.event_id, received_at, received_at, received_at),
            )
        else:
            existing = connection.execute(
                """
                SELECT payload_sha256 FROM events
                WHERE tenant_id = ? AND event_id = ?
                """,
                (tenant_id, event.event_id),
            ).fetchone()
            if existing is None or existing["payload_sha256"] != payload_sha256:
                raise EventIdentityConflict("event identity already exists with different content")
        return IngestResult(accepted=accepted, event_id=event.event_id, job_id=job_id)

    def load_event(self, tenant_id: str, event_id: str) -> Optional[SecurityEvent]:
        with self._database.connect() as connection:
            row = connection.execute(
                "SELECT payload_json FROM events WHERE tenant_id = ? AND event_id = ?",
                (tenant_id, event_id),
            ).fetchone()
        if row is None:
            return None
        return SecurityEvent.model_validate_json(str(row["payload_json"]))

    def load_detection_history(
        self,
        tenant_id: str,
        event: SecurityEvent,
        limit: int = 10_000,
    ) -> list[SecurityEvent]:
        """Load bounded, tenant-scoped event-time history for one correlation decision."""

        if limit < 1 or limit > 10_000:
            raise ValueError("correlation history limit must be between 1 and 10000")
        query: str
        parameters: tuple[object, ...]
        query_limit = limit + 1
        enforce_limit = True
        correlation = stateful_correlation_for_event(event.event_type)
        if event.event_type == "sensitive_data_access":
            if correlation is None or correlation.window_minutes is None:
                raise RuntimeError("bulk-access correlation contract is incomplete")
            cutoff = event.timestamp - timedelta(minutes=correlation.window_minutes)
            query = """
                SELECT payload_json FROM events
                WHERE tenant_id = ? AND event_id != ?
                  AND actor = ? AND event_type = ?
                  AND julianday(occurred_at) BETWEEN julianday(?) AND julianday(?)
                ORDER BY julianday(occurred_at) ASC, event_id ASC
                LIMIT ?
            """
            parameters = (
                event.actor,
                event.event_type,
                _utc_text(cutoff),
                _utc_text(event.timestamp),
            )
        elif event.event_type == "authentication_success":
            query = """
                SELECT payload_json FROM events
                WHERE tenant_id = ? AND event_id != ?
                  AND actor = ? AND event_type = ?
                  AND julianday(occurred_at) < julianday(?)
                ORDER BY julianday(occurred_at) DESC, event_id DESC
                LIMIT ?
            """
            parameters = (event.actor, event.event_type, _utc_text(event.timestamp))
            query_limit = 1
            enforce_limit = False
        elif event.event_type == "edge_auth_failure" and event.source_ip:
            if correlation is None or correlation.window_minutes is None:
                raise RuntimeError("credential-stuffing correlation contract is incomplete")
            cutoff = event.timestamp - timedelta(minutes=correlation.window_minutes)
            query = """
                SELECT payload_json FROM events
                WHERE tenant_id = ? AND event_id != ?
                  AND source_ip = ? AND event_type = ?
                  AND julianday(occurred_at) BETWEEN julianday(?) AND julianday(?)
                ORDER BY julianday(occurred_at) ASC, event_id ASC
                LIMIT ?
            """
            parameters = (
                event.source_ip,
                event.event_type,
                _utc_text(cutoff),
                _utc_text(event.timestamp),
            )
        elif event.event_type == "edge_session_use":
            session_hash = event.attributes.get("session_id_hash")
            if not isinstance(session_hash, str) or len(session_hash) < 12:
                return []
            if correlation is None or correlation.window_minutes is None:
                raise RuntimeError("session-replay correlation contract is incomplete")
            cutoff = event.timestamp - timedelta(minutes=correlation.window_minutes)
            query = """
                SELECT payload_json FROM events
                WHERE tenant_id = ? AND event_id != ? AND event_type = ?
                  AND json_extract(payload_json, '$.attributes.session_id_hash') = ?
                  AND julianday(occurred_at) >= julianday(?)
                  AND julianday(occurred_at) < julianday(?)
                ORDER BY julianday(occurred_at) DESC, event_id DESC
                LIMIT ?
            """
            parameters = (
                event.event_type,
                session_hash,
                _utc_text(cutoff),
                _utc_text(event.timestamp),
            )
            query_limit = 1
            enforce_limit = False
        else:
            return []
        with self._database.connect() as connection:
            rows = connection.execute(
                query,
                (tenant_id, event.event_id, *parameters, query_limit),
            ).fetchall()
        if enforce_limit and len(rows) > limit:
            raise RuntimeError("correlation history exceeds the safe 10000-event bound")
        return [SecurityEvent.model_validate_json(str(row["payload_json"])) for row in rows]

    def persist_alerts_and_complete_job(
        self,
        tenant_id: str,
        job_id: str,
        worker_id: str,
        alerts: list[DetectionAlert],
        now: datetime,
        rule_versions: Mapping[str, str],
        detector_version: str,
        rule_digests: Optional[Mapping[str, str]] = None,
        rule_snapshots: Optional[Mapping[str, str]] = None,
    ) -> AlertPersistenceResult:
        """Persist decisions, cases, and job success as one idempotent transaction."""

        timestamp = _utc_text(now)
        inserted_alerts = 0
        with self._database.connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            try:
                job = connection.execute(
                    """
                    SELECT j.event_id, j.status, j.lease_owner, j.lease_expires_at,
                           e.payload_sha256, e.device_id
                    FROM detection_jobs j
                    JOIN events e
                      ON e.tenant_id = j.tenant_id AND e.event_id = j.event_id
                    WHERE j.tenant_id = ? AND j.job_id = ?
                    """,
                    (tenant_id, job_id),
                ).fetchone()
                if (
                    job is None
                    or job["status"] != "leased"
                    or job["lease_owner"] != worker_id
                    or str(job["lease_expires_at"]) <= timestamp
                ):
                    raise LeaseOwnershipError("worker does not own a current job lease")
                event_id = str(job["event_id"])
                for alert in alerts:
                    if alert.event_id != event_id:
                        raise ValueError("alert source event does not match the leased job")
                    reasons_json = json.dumps(alert.reasons, separators=(",", ":"))
                    tags_json = json.dumps(alert.tags, separators=(",", ":"))
                    evidence_json = json.dumps(
                        {
                            "source_event_id": event_id,
                            "source_event_sha256": str(job["payload_sha256"]),
                            "matched_evidence": alert.reasons,
                        },
                        separators=(",", ":"),
                        sort_keys=True,
                    )
                    rule_version = rule_versions.get(alert.rule_id, "stateful-v1")
                    rule_digest = (rule_digests or {}).get(
                        alert.rule_id,
                        f"builtin:{alert.rule_id}:{rule_version}",
                    )
                    rule_snapshot = (rule_snapshots or {}).get(alert.rule_id, "{}")
                    cursor = connection.execute(
                        """
                        INSERT OR IGNORE INTO alerts(
                            tenant_id, alert_id, event_id, rule_id, rule_version, rule_digest,
                            rule_snapshot_json, fingerprint_version, detector_version, title,
                            severity, actor, reasons_json, tags_json, evidence_json, created_at
                        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                        """,
                        (
                            tenant_id,
                            alert.alert_id,
                            event_id,
                            alert.rule_id,
                            rule_version,
                            rule_digest,
                            rule_snapshot,
                            "legacy-local-v0",
                            detector_version,
                            alert.title,
                            alert.severity.value,
                            alert.actor,
                            reasons_json,
                            tags_json,
                            evidence_json,
                            _utc_text(alert.created_at),
                        ),
                    )
                    inserted_alerts += cursor.rowcount
                    if cursor.rowcount != 1:
                        continue
                    semantic_key = self._case_semantic_key(
                        tenant_id,
                        alert.rule_id,
                        str(job["device_id"]) if job["device_id"] is not None else None,
                        alert.actor,
                    )
                    case_id = hashlib.sha256(
                        f"{tenant_id}:case:{alert.alert_id}".encode()
                    ).hexdigest()[:32]
                    case_cursor = connection.execute(
                        """
                        INSERT OR IGNORE INTO cases(
                            tenant_id, case_id, semantic_key, title, priority,
                            status, opened_at, updated_at
                        ) VALUES (?, ?, ?, ?, ?, 'open', ?, ?)
                        """,
                        (
                            tenant_id,
                            case_id,
                            semantic_key,
                            alert.title,
                            self._case_priority(alert.severity.value),
                            timestamp,
                            timestamp,
                        ),
                    )
                    active_case = connection.execute(
                        """
                        SELECT case_id FROM cases
                        WHERE tenant_id = ? AND semantic_key = ? AND status != 'closed'
                        """,
                        (tenant_id, semantic_key),
                    ).fetchone()
                    if active_case is None:
                        raise RuntimeError("active semantic case was not persisted")
                    case_id = str(active_case["case_id"])
                    connection.execute(
                        """
                        INSERT OR IGNORE INTO case_alerts(
                            tenant_id, case_id, alert_id, linked_at
                        ) VALUES (?, ?, ?, ?)
                        """,
                        (tenant_id, case_id, alert.alert_id, timestamp),
                    )
                    if case_cursor.rowcount != 1:
                        priority = self._case_priority(alert.severity.value)
                        connection.execute(
                            """
                            UPDATE cases
                            SET updated_at = ?, version = version + 1,
                                priority = CASE
                                    WHEN priority = 'critical' OR ? = 'critical' THEN 'critical'
                                    WHEN priority = 'high' OR ? = 'high' THEN 'high'
                                    WHEN priority = 'medium' OR ? = 'medium' THEN 'medium'
                                    ELSE 'low'
                                END
                            WHERE tenant_id = ? AND case_id = ?
                            """,
                            (
                                timestamp,
                                priority,
                                priority,
                                priority,
                                tenant_id,
                                case_id,
                            ),
                        )
                connection.execute(
                    """
                    UPDATE detection_jobs
                    SET status = 'succeeded', lease_owner = NULL, lease_expires_at = NULL,
                        last_error = NULL, updated_at = ?
                    WHERE tenant_id = ? AND job_id = ?
                    """,
                    (timestamp, tenant_id, job_id),
                )
                connection.execute("COMMIT")
            except Exception:
                if connection.in_transaction:
                    connection.execute("ROLLBACK")
                raise
        return AlertPersistenceResult(inserted_alerts, "succeeded")

    @staticmethod
    def _case_priority(severity: str) -> str:
        if severity in {"critical", "high", "medium"}:
            return severity
        return "low"

    @staticmethod
    def _case_semantic_key(
        tenant_id: str,
        rule_id: str,
        device_id: Optional[str],
        actor: str,
    ) -> str:
        entity = ["device", device_id] if device_id is not None else ["actor", actor.casefold()]
        canonical = json.dumps(
            ["controlforge-case", 1, tenant_id, rule_id, entity],
            ensure_ascii=False,
            separators=(",", ":"),
        )
        return hashlib.sha256(canonical.encode()).hexdigest()

    def lease_jobs(
        self,
        tenant_id: str,
        worker_id: str,
        limit: int,
        now: datetime,
        lease_seconds: int,
    ) -> list[JobLease]:
        """Atomically claim ready jobs, including leases abandoned by dead workers."""

        if not worker_id or len(worker_id) > 128:
            raise ValueError("worker_id must contain between 1 and 128 characters")
        if limit < 1 or limit > 100:
            raise ValueError("lease limit must be between 1 and 100")
        if lease_seconds < 5 or lease_seconds > 3_600:
            raise ValueError("lease_seconds must be between 5 and 3600")
        now_text = _utc_text(now)
        lease_expires = now + timedelta(seconds=lease_seconds)
        lease_expires_text = _utc_text(lease_expires)
        with self._database.connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            try:
                rows = connection.execute(
                    """
                    SELECT j.job_id FROM detection_jobs j
                    JOIN events e
                      ON e.tenant_id = j.tenant_id AND e.event_id = j.event_id
                    WHERE j.tenant_id = ? AND (
                        (j.status IN ('pending', 'retry') AND j.available_at <= ?)
                        OR (j.status = 'leased' AND j.lease_expires_at <= ?)
                    )
                    ORDER BY e.occurred_at, e.received_at, j.created_at, j.job_id
                    LIMIT ?
                    """,
                    (tenant_id, now_text, now_text, limit),
                ).fetchall()
                job_ids = [str(row["job_id"]) for row in rows]
                for job_id in job_ids:
                    connection.execute(
                        """
                        UPDATE detection_jobs
                        SET status = 'leased', attempts = attempts + 1,
                            lease_owner = ?, lease_expires_at = ?, updated_at = ?
                        WHERE tenant_id = ? AND job_id = ?
                        """,
                        (worker_id, lease_expires_text, now_text, tenant_id, job_id),
                    )
                leased_rows = [
                    connection.execute(
                        """
                        SELECT tenant_id, job_id, event_id, attempts,
                               lease_owner, lease_expires_at
                        FROM detection_jobs
                        WHERE tenant_id = ? AND job_id = ?
                        """,
                        (tenant_id, job_id),
                    ).fetchone()
                    for job_id in job_ids
                ]
                connection.execute("COMMIT")
            except Exception:
                if connection.in_transaction:
                    connection.execute("ROLLBACK")
                raise
        return [
            JobLease(
                tenant_id=str(row["tenant_id"]),
                job_id=str(row["job_id"]),
                event_id=str(row["event_id"]),
                attempts=int(row["attempts"]),
                lease_owner=str(row["lease_owner"]),
                lease_expires_at=_parse_utc(str(row["lease_expires_at"])),
            )
            for row in leased_rows
            if row is not None
        ]

    def complete_job(
        self,
        tenant_id: str,
        job_id: str,
        worker_id: str,
        now: datetime,
    ) -> JobTransition:
        """Mark a job successful only when the caller owns its active lease."""

        return self._transition_owned_job(
            tenant_id,
            job_id,
            worker_id,
            now,
            succeeded=True,
            error=None,
            max_attempts=1,
            retry_delay_seconds=0,
        )

    def fail_job(
        self,
        tenant_id: str,
        job_id: str,
        worker_id: str,
        now: datetime,
        error: str,
        max_attempts: int,
        retry_delay_seconds: int,
    ) -> JobTransition:
        """Schedule an owned job for retry or dead-letter it after the attempt cap."""

        if max_attempts < 1 or max_attempts > 100:
            raise ValueError("max_attempts must be between 1 and 100")
        if retry_delay_seconds < 0 or retry_delay_seconds > 86_400:
            raise ValueError("retry_delay_seconds must be between 0 and 86400")
        return self._transition_owned_job(
            tenant_id,
            job_id,
            worker_id,
            now,
            succeeded=False,
            error=error[:1_000],
            max_attempts=max_attempts,
            retry_delay_seconds=retry_delay_seconds,
        )

    def _transition_owned_job(
        self,
        tenant_id: str,
        job_id: str,
        worker_id: str,
        now: datetime,
        *,
        succeeded: bool,
        error: Optional[str],
        max_attempts: int,
        retry_delay_seconds: int,
    ) -> JobTransition:
        now_text = _utc_text(now)
        with self._database.connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            try:
                row = connection.execute(
                    """
                    SELECT status, attempts, lease_owner FROM detection_jobs
                    WHERE tenant_id = ? AND job_id = ?
                    """,
                    (tenant_id, job_id),
                ).fetchone()
                if row is None or row["status"] != "leased" or row["lease_owner"] != worker_id:
                    connection.execute("COMMIT")
                    current_status: JobStatus = "dead" if row is None else row["status"]
                    attempts = 0 if row is None else int(row["attempts"])
                    return JobTransition(False, current_status, attempts)
                attempts = int(row["attempts"])
                if succeeded:
                    status: JobStatus = "succeeded"
                    available_at = now_text
                    stored_error = None
                elif attempts >= max_attempts:
                    status = "dead"
                    available_at = now_text
                    stored_error = error
                else:
                    status = "retry"
                    available_at = _utc_text(now + timedelta(seconds=retry_delay_seconds))
                    stored_error = error
                connection.execute(
                    """
                    UPDATE detection_jobs
                    SET status = ?, available_at = ?, lease_owner = NULL,
                        lease_expires_at = NULL, last_error = ?, updated_at = ?
                    WHERE tenant_id = ? AND job_id = ?
                    """,
                    (status, available_at, stored_error, now_text, tenant_id, job_id),
                )
                connection.execute("COMMIT")
            except Exception:
                if connection.in_transaction:
                    connection.execute("ROLLBACK")
                raise
        return JobTransition(True, status, attempts)

    def job_status(self, tenant_id: str, job_id: str) -> Optional[JobStatus]:
        with self._database.connect() as connection:
            row = connection.execute(
                "SELECT status FROM detection_jobs WHERE tenant_id = ? AND job_id = ?",
                (tenant_id, job_id),
            ).fetchone()
        if row is None:
            return None
        status: JobStatus = row["status"]
        return status

    def job_counts(self, tenant_id: str) -> dict[JobStatus, int]:
        counts: dict[JobStatus, int] = {
            "pending": 0,
            "leased": 0,
            "retry": 0,
            "succeeded": 0,
            "dead": 0,
        }
        with self._database.connect() as connection:
            rows = connection.execute(
                """
                SELECT status, COUNT(*) AS count FROM detection_jobs
                WHERE tenant_id = ? GROUP BY status
                """,
                (tenant_id,),
            ).fetchall()
        for row in rows:
            status: JobStatus = row["status"]
            counts[status] = int(row["count"])
        return counts
