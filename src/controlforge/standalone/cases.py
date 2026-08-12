"""Tenant-scoped, audited standalone case-management workflow."""

from __future__ import annotations

import hashlib
import json
import sqlite3
import uuid
from dataclasses import dataclass
from datetime import datetime
from typing import ClassVar, Literal, Optional, cast

from .audit import AuditVerification, StandaloneAuditLog
from .database import StandaloneDatabase
from .identity import Capability, HumanIdentityService, SessionPrincipal
from .store import _utc_text

CaseStatus = Literal["open", "investigating", "contained", "closed"]
DispositionStatus = Literal["true_positive", "false_positive", "benign", "inconclusive"]


class CaseError(RuntimeError):
    """Base class for bounded case-management failures."""


class CaseNotFoundError(CaseError):
    """Raised when a case is unavailable in the principal's tenant."""


class CaseTransitionError(CaseError):
    """Raised when a requested case transition violates the state machine."""


class CaseValidationError(CaseError):
    """Raised when case content does not satisfy the durable contract."""


@dataclass(frozen=True)
class CaseActivityRecord:
    activity_id: str
    activity_type: str
    actor_id: str
    body: dict[str, object]
    created_at: datetime


@dataclass(frozen=True)
class DispositionRecord:
    disposition_id: str
    status: DispositionStatus
    rationale: str
    false_positive_reason: Optional[str]
    rule_version: str
    created_by: str
    created_at: datetime


@dataclass(frozen=True)
class CaseDetail:
    case_id: str
    title: str
    priority: str
    status: CaseStatus
    assignee_user_id: Optional[str]
    version: int
    opened_at: datetime
    updated_at: datetime
    closed_at: Optional[datetime]
    alert_ids: tuple[str, ...]
    alert_count: int
    alerts_truncated: bool
    activity: tuple[CaseActivityRecord, ...]
    activity_count: int
    activity_truncated: bool
    dispositions: tuple[DispositionRecord, ...]
    disposition_count: int
    dispositions_truncated: bool


class StandaloneCaseService:
    """Apply the analyst case state machine with RBAC and atomic audit lineage."""

    _TRANSITIONS: ClassVar[dict[CaseStatus, frozenset[CaseStatus]]] = {
        "open": frozenset({"investigating", "closed"}),
        "investigating": frozenset({"contained", "closed"}),
        "contained": frozenset({"investigating", "closed"}),
        "closed": frozenset({"open"}),
    }
    _DISPOSITIONS = frozenset({"true_positive", "false_positive", "benign", "inconclusive"})

    def __init__(
        self,
        database: StandaloneDatabase,
        identity: HumanIdentityService,
        audit: StandaloneAuditLog,
    ) -> None:
        self._database = database
        self._identity = identity
        self._audit = audit

    def get_case(self, principal: SessionPrincipal, case_id: str) -> CaseDetail:
        self._identity.require_capability(principal, principal.tenant_id, Capability.VIEW)
        with self._database.connect() as connection:
            case = connection.execute(
                "SELECT * FROM cases WHERE tenant_id = ? AND case_id = ?",
                (principal.tenant_id, case_id),
            ).fetchone()
            if case is None:
                raise CaseNotFoundError("case is unavailable")
            counts = connection.execute(
                """
                SELECT
                  (SELECT COUNT(*) FROM case_alerts
                   WHERE tenant_id = ? AND case_id = ?) AS alert_count,
                  (SELECT COUNT(*) FROM case_activity
                   WHERE tenant_id = ? AND case_id = ?) AS activity_count,
                  (SELECT COUNT(*) FROM dispositions
                   WHERE tenant_id = ? AND case_id = ?) AS disposition_count
                """,
                (
                    principal.tenant_id,
                    case_id,
                    principal.tenant_id,
                    case_id,
                    principal.tenant_id,
                    case_id,
                ),
            ).fetchone()
            if counts is None:
                raise CaseValidationError("stored case counts are unavailable")
            alerts = connection.execute(
                """
                SELECT alert_id FROM (
                  SELECT alert_id, linked_at FROM case_alerts
                  WHERE tenant_id = ? AND case_id = ?
                  ORDER BY linked_at DESC, alert_id DESC LIMIT 200
                ) ORDER BY linked_at, alert_id
                """,
                (principal.tenant_id, case_id),
            ).fetchall()
            activity = connection.execute(
                """
                SELECT activity_id, activity_type, actor_id, body_json, created_at
                FROM (
                  SELECT activity_id, activity_type, actor_id, body_json, created_at
                  FROM case_activity WHERE tenant_id = ? AND case_id = ?
                  ORDER BY created_at DESC, activity_id DESC LIMIT 500
                ) ORDER BY created_at, activity_id
                """,
                (principal.tenant_id, case_id),
            ).fetchall()
            dispositions = connection.execute(
                """
                SELECT disposition_id, status, rationale, false_positive_reason,
                       rule_version, created_by, created_at
                FROM (
                  SELECT disposition_id, status, rationale, false_positive_reason,
                         rule_version, created_by, created_at
                  FROM dispositions WHERE tenant_id = ? AND case_id = ?
                  ORDER BY created_at DESC, disposition_id DESC LIMIT 200
                ) ORDER BY created_at, disposition_id
                """,
                (principal.tenant_id, case_id),
            ).fetchall()
        return self._case_detail(case, counts, alerts, activity, dispositions)

    def add_note(
        self,
        principal: SessionPrincipal,
        case_id: str,
        note: str,
        now: datetime,
    ) -> CaseActivityRecord:
        self._identity.require_capability(principal, principal.tenant_id, Capability.TRIAGE)
        normalized_note = note.strip()
        if not normalized_note or len(normalized_note) > 4_000:
            raise CaseValidationError("case note must contain between 1 and 4000 characters")
        activity_id = str(uuid.uuid4())
        body: dict[str, object] = {"note": normalized_note}
        with self._database.connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            try:
                self._require_case(connection, principal.tenant_id, case_id)
                connection.execute(
                    """
                    INSERT INTO case_activity(
                        tenant_id, activity_id, case_id, activity_type,
                        actor_id, body_json, created_at
                    ) VALUES (?, ?, ?, 'note', ?, ?, ?)
                    """,
                    (
                        principal.tenant_id,
                        activity_id,
                        case_id,
                        principal.user_id,
                        self._json(body),
                        _utc_text(now),
                    ),
                )
                self._touch_case(connection, principal.tenant_id, case_id, now)
                self._audit.append(
                    connection,
                    principal.tenant_id,
                    "case.note_added",
                    "user",
                    principal.user_id,
                    "case",
                    case_id,
                    {
                        "activity_id": activity_id,
                        "note_sha256": hashlib.sha256(normalized_note.encode()).hexdigest(),
                    },
                    now,
                )
                connection.execute("COMMIT")
            except Exception:
                if connection.in_transaction:
                    connection.execute("ROLLBACK")
                raise
        return CaseActivityRecord(activity_id, "note", principal.user_id, body, now)

    def assign(
        self,
        principal: SessionPrincipal,
        case_id: str,
        assignee_user_id: Optional[str],
        now: datetime,
    ) -> CaseDetail:
        """Assign or unassign a case to an active investigation-capable human."""

        self._identity.require_capability(principal, principal.tenant_id, Capability.TRIAGE)
        normalized_assignee = assignee_user_id.strip() if assignee_user_id is not None else None
        if normalized_assignee == "":
            normalized_assignee = None
        if normalized_assignee is not None and len(normalized_assignee) > 128:
            raise CaseValidationError("case assignee identifier is invalid")

        activity_id = str(uuid.uuid4())
        with self._database.connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            try:
                case = self._require_case(connection, principal.tenant_id, case_id)
                previous_assignee = (
                    str(case["assignee_user_id"]) if case["assignee_user_id"] is not None else None
                )
                if normalized_assignee == previous_assignee:
                    raise CaseValidationError("case is already assigned to that user")
                if normalized_assignee is not None:
                    candidate = connection.execute(
                        """
                        SELECT role, status FROM users
                        WHERE tenant_id = ? AND user_id = ?
                        """,
                        (principal.tenant_id, normalized_assignee),
                    ).fetchone()
                    if (
                        candidate is None
                        or str(candidate["status"]) != "active"
                        or str(candidate["role"]) not in {"analyst", "responder", "admin"}
                    ):
                        raise CaseValidationError("case assignee is unavailable")

                connection.execute(
                    """
                    UPDATE cases
                    SET assignee_user_id = ?, updated_at = ?, version = version + 1
                    WHERE tenant_id = ? AND case_id = ?
                    """,
                    (
                        normalized_assignee,
                        _utc_text(now),
                        principal.tenant_id,
                        case_id,
                    ),
                )
                body: dict[str, object] = {
                    "from_user_id": previous_assignee,
                    "to_user_id": normalized_assignee,
                }
                connection.execute(
                    """
                    INSERT INTO case_activity(
                        tenant_id, activity_id, case_id, activity_type,
                        actor_id, body_json, created_at
                    ) VALUES (?, ?, ?, 'assignment', ?, ?, ?)
                    """,
                    (
                        principal.tenant_id,
                        activity_id,
                        case_id,
                        principal.user_id,
                        self._json(body),
                        _utc_text(now),
                    ),
                )
                self._audit.append(
                    connection,
                    principal.tenant_id,
                    "case.assignment_changed",
                    "user",
                    principal.user_id,
                    "case",
                    case_id,
                    {"activity_id": activity_id, **body},
                    now,
                )
                connection.execute("COMMIT")
            except Exception:
                if connection.in_transaction:
                    connection.execute("ROLLBACK")
                raise
        return self.get_case(principal, case_id)

    def transition(
        self,
        principal: SessionPrincipal,
        case_id: str,
        target_status: CaseStatus,
        now: datetime,
    ) -> CaseDetail:
        self._identity.require_capability(principal, principal.tenant_id, Capability.TRIAGE)
        if target_status not in self._TRANSITIONS:
            raise CaseTransitionError("case target status is invalid")
        activity_id = str(uuid.uuid4())
        with self._database.connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            try:
                case = self._require_case(connection, principal.tenant_id, case_id)
                current_status = self._case_status(str(case["status"]))
                if target_status not in self._TRANSITIONS[current_status]:
                    raise CaseTransitionError(
                        f"case cannot transition from {current_status} to {target_status}"
                    )
                if current_status == "closed" and target_status == "open":
                    semantic_key = (
                        str(case["semantic_key"]) if case["semantic_key"] is not None else None
                    )
                    if semantic_key is not None:
                        active_successor = connection.execute(
                            """
                            SELECT 1 FROM cases
                            WHERE tenant_id = ? AND semantic_key = ?
                              AND status != 'closed' AND case_id != ?
                            LIMIT 1
                            """,
                            (principal.tenant_id, semantic_key, case_id),
                        ).fetchone()
                        if active_successor is not None:
                            raise CaseTransitionError(
                                "case cannot reopen while a successor case is active"
                            )
                if target_status == "closed":
                    disposition = connection.execute(
                        """
                        SELECT 1 FROM dispositions
                        WHERE tenant_id = ? AND case_id = ?
                          AND investigation_cycle = ?
                        LIMIT 1
                        """,
                        (
                            principal.tenant_id,
                            case_id,
                            case["investigation_cycle"],
                        ),
                    ).fetchone()
                    if disposition is None:
                        raise CaseTransitionError(
                            "case cannot close without a current-cycle disposition"
                        )
                closed_at = _utc_text(now) if target_status == "closed" else None
                investigation_cycle = int(case["investigation_cycle"]) + (
                    1 if current_status == "closed" and target_status == "open" else 0
                )
                connection.execute(
                    """
                    UPDATE cases SET
                        status = ?, updated_at = ?, closed_at = ?,
                        investigation_cycle = ?, version = version + 1
                    WHERE tenant_id = ? AND case_id = ?
                    """,
                    (
                        target_status,
                        _utc_text(now),
                        closed_at,
                        investigation_cycle,
                        principal.tenant_id,
                        case_id,
                    ),
                )
                body: dict[str, object] = {
                    "from": current_status,
                    "to": target_status,
                }
                connection.execute(
                    """
                    INSERT INTO case_activity(
                        tenant_id, activity_id, case_id, activity_type,
                        actor_id, body_json, created_at
                    ) VALUES (?, ?, ?, 'state_transition', ?, ?, ?)
                    """,
                    (
                        principal.tenant_id,
                        activity_id,
                        case_id,
                        principal.user_id,
                        self._json(body),
                        _utc_text(now),
                    ),
                )
                self._audit.append(
                    connection,
                    principal.tenant_id,
                    "case.status_changed",
                    "user",
                    principal.user_id,
                    "case",
                    case_id,
                    {"activity_id": activity_id, **body},
                    now,
                )
                connection.execute("COMMIT")
            except Exception:
                if connection.in_transaction:
                    connection.execute("ROLLBACK")
                raise
        return self.get_case(principal, case_id)

    def record_disposition(
        self,
        principal: SessionPrincipal,
        case_id: str,
        status: DispositionStatus,
        rationale: str,
        false_positive_reason: Optional[str],
        now: datetime,
    ) -> DispositionRecord:
        self._identity.require_capability(
            principal,
            principal.tenant_id,
            Capability.DISPOSITION,
        )
        if status not in self._DISPOSITIONS:
            raise CaseValidationError("case disposition is invalid")
        normalized_rationale = rationale.strip()
        if not normalized_rationale or len(normalized_rationale) > 4_000:
            raise CaseValidationError(
                "disposition rationale must contain between 1 and 4000 characters"
            )
        normalized_reason = (
            false_positive_reason.strip() if false_positive_reason is not None else None
        )
        if status == "false_positive":
            if not normalized_reason or len(normalized_reason) > 1_000:
                raise CaseValidationError("false-positive dispositions require a bounded reason")
        elif normalized_reason is not None:
            raise CaseValidationError(
                "false-positive reason is only valid for a false-positive disposition"
            )
        disposition_id = str(uuid.uuid4())
        activity_id = str(uuid.uuid4())
        with self._database.connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            try:
                case = self._require_case(connection, principal.tenant_id, case_id)
                rule_version = self._case_rule_version(
                    connection,
                    principal.tenant_id,
                    case_id,
                )
                investigation_cycle = int(case["investigation_cycle"])
                connection.execute(
                    """
                    INSERT INTO dispositions(
                        tenant_id, disposition_id, case_id, status, rationale,
                        rule_version, created_by, created_at, false_positive_reason,
                        investigation_cycle
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        principal.tenant_id,
                        disposition_id,
                        case_id,
                        status,
                        normalized_rationale,
                        rule_version,
                        principal.user_id,
                        _utc_text(now),
                        normalized_reason,
                        investigation_cycle,
                    ),
                )
                body: dict[str, object] = {
                    "disposition_id": disposition_id,
                    "status": status,
                    "rationale": normalized_rationale,
                    "false_positive_reason": normalized_reason,
                    "rule_version": rule_version,
                    "investigation_cycle": investigation_cycle,
                }
                connection.execute(
                    """
                    INSERT INTO case_activity(
                        tenant_id, activity_id, case_id, activity_type,
                        actor_id, body_json, created_at
                    ) VALUES (?, ?, ?, 'disposition', ?, ?, ?)
                    """,
                    (
                        principal.tenant_id,
                        activity_id,
                        case_id,
                        principal.user_id,
                        self._json(body),
                        _utc_text(now),
                    ),
                )
                self._touch_case(connection, principal.tenant_id, case_id, now)
                self._audit.append(
                    connection,
                    principal.tenant_id,
                    "case.disposition_recorded",
                    "user",
                    principal.user_id,
                    "case",
                    case_id,
                    {"activity_id": activity_id, **body},
                    now,
                )
                connection.execute("COMMIT")
            except Exception:
                if connection.in_transaction:
                    connection.execute("ROLLBACK")
                raise
        return DispositionRecord(
            disposition_id,
            status,
            normalized_rationale,
            normalized_reason,
            rule_version,
            principal.user_id,
            now,
        )

    def verify_audit(self, principal: SessionPrincipal) -> AuditVerification:
        self._identity.require_capability(principal, principal.tenant_id, Capability.VIEW)
        return self._audit.verify(principal.tenant_id)

    @staticmethod
    def _require_case(
        connection: sqlite3.Connection,
        tenant_id: str,
        case_id: str,
    ) -> sqlite3.Row:
        row = connection.execute(
            "SELECT * FROM cases WHERE tenant_id = ? AND case_id = ?",
            (tenant_id, case_id),
        ).fetchone()
        if row is None:
            raise CaseNotFoundError("case is unavailable")
        return cast(sqlite3.Row, row)

    @staticmethod
    def _touch_case(
        connection: sqlite3.Connection,
        tenant_id: str,
        case_id: str,
        now: datetime,
    ) -> None:
        connection.execute(
            """
            UPDATE cases SET updated_at = ?, version = version + 1
            WHERE tenant_id = ? AND case_id = ?
            """,
            (_utc_text(now), tenant_id, case_id),
        )

    @staticmethod
    def _case_rule_version(
        connection: sqlite3.Connection,
        tenant_id: str,
        case_id: str,
    ) -> str:
        row = connection.execute(
            """
            SELECT a.rule_version FROM case_alerts ca
            JOIN alerts a
              ON a.tenant_id = ca.tenant_id AND a.alert_id = ca.alert_id
            WHERE ca.tenant_id = ? AND ca.case_id = ?
            ORDER BY a.created_at DESC, a.alert_id DESC LIMIT 1
            """,
            (tenant_id, case_id),
        ).fetchone()
        return str(row["rule_version"]) if row is not None else "no-linked-alert"

    @classmethod
    def _case_detail(
        cls,
        case: sqlite3.Row,
        counts: sqlite3.Row,
        alerts: list[sqlite3.Row],
        activity: list[sqlite3.Row],
        dispositions: list[sqlite3.Row],
    ) -> CaseDetail:
        return CaseDetail(
            case_id=str(case["case_id"]),
            title=str(case["title"]),
            priority=str(case["priority"]),
            status=cls._case_status(str(case["status"])),
            assignee_user_id=(
                str(case["assignee_user_id"]) if case["assignee_user_id"] is not None else None
            ),
            version=int(case["version"]),
            opened_at=cls._parse_time(str(case["opened_at"])),
            updated_at=cls._parse_time(str(case["updated_at"])),
            closed_at=(
                cls._parse_time(str(case["closed_at"])) if case["closed_at"] is not None else None
            ),
            alert_ids=tuple(str(row["alert_id"]) for row in alerts),
            alert_count=int(counts["alert_count"]),
            alerts_truncated=int(counts["alert_count"]) > len(alerts),
            activity=tuple(
                CaseActivityRecord(
                    activity_id=str(row["activity_id"]),
                    activity_type=str(row["activity_type"]),
                    actor_id=str(row["actor_id"]),
                    body=cls._json_object(str(row["body_json"])),
                    created_at=cls._parse_time(str(row["created_at"])),
                )
                for row in activity
            ),
            activity_count=int(counts["activity_count"]),
            activity_truncated=int(counts["activity_count"]) > len(activity),
            dispositions=tuple(
                DispositionRecord(
                    disposition_id=str(row["disposition_id"]),
                    status=cls._disposition_status(str(row["status"])),
                    rationale=str(row["rationale"]),
                    false_positive_reason=(
                        str(row["false_positive_reason"])
                        if row["false_positive_reason"] is not None
                        else None
                    ),
                    rule_version=str(row["rule_version"]),
                    created_by=str(row["created_by"]),
                    created_at=cls._parse_time(str(row["created_at"])),
                )
                for row in dispositions
            ),
            disposition_count=int(counts["disposition_count"]),
            dispositions_truncated=int(counts["disposition_count"]) > len(dispositions),
        )

    @staticmethod
    def _json(value: dict[str, object]) -> str:
        return json.dumps(value, ensure_ascii=False, separators=(",", ":"), sort_keys=True)

    @staticmethod
    def _json_object(value: str) -> dict[str, object]:
        parsed = json.loads(value)
        if not isinstance(parsed, dict):
            raise CaseValidationError("stored case activity is invalid")
        return cast(dict[str, object], parsed)

    @staticmethod
    def _case_status(value: str) -> CaseStatus:
        if value not in {"open", "investigating", "contained", "closed"}:
            raise CaseValidationError("stored case status is invalid")
        return cast(CaseStatus, value)

    @staticmethod
    def _disposition_status(value: str) -> DispositionStatus:
        if value not in {"true_positive", "false_positive", "benign", "inconclusive"}:
            raise CaseValidationError("stored disposition status is invalid")
        return cast(DispositionStatus, value)

    @staticmethod
    def _parse_time(value: str) -> datetime:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))


__all__ = [
    "CaseActivityRecord",
    "CaseDetail",
    "CaseError",
    "CaseNotFoundError",
    "CaseStatus",
    "CaseTransitionError",
    "CaseValidationError",
    "DispositionRecord",
    "DispositionStatus",
    "StandaloneCaseService",
]
