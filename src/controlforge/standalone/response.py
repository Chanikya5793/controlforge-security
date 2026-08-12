"""Two-person, device-bound active-response governance for standalone mode."""

from __future__ import annotations

import json
import sqlite3
import uuid
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Literal, Optional, cast

from .audit import StandaloneAuditLog
from .auth import DeviceHmacAuthenticator, SignedCollectorRequest
from .database import StandaloneDatabase
from .identity import Capability, HumanAuthorizationError, HumanIdentityService, SessionPrincipal
from .store import _utc_text

ResponseActionType = Literal["isolate_endpoint", "release_endpoint"]
ResponseActionStatus = Literal[
    "proposed",
    "approved",
    "rejected",
    "dispatched",
    "succeeded",
    "failed",
    "expired",
]
ResponseResultStatus = Literal["succeeded", "failed"]


class ResponseGovernanceError(RuntimeError):
    """Base class for bounded active-response governance failures."""


class ResponseNotFoundError(ResponseGovernanceError):
    """Raised when an action is unavailable in the caller's tenant or device scope."""


class ResponseConflictError(ResponseGovernanceError):
    """Raised when an action cannot make the requested atomic transition."""


class ResponseExpiredError(ResponseConflictError):
    """Raised when a proposal missed its approval or dispatch deadline."""


class ResponseValidationError(ResponseGovernanceError):
    """Raised when response content exceeds the fixed contract."""


class DeviceActionBindingError(ResponseGovernanceError):
    """Raised when a signed collector requests another device's action."""


@dataclass(frozen=True)
class ResponseAction:
    action_id: str
    tenant_id: str
    case_id: str
    action_type: ResponseActionType
    target_id: str
    rationale: str
    status: ResponseActionStatus
    proposed_by: str
    proposed_at: datetime
    approved_by: Optional[str]
    approved_at: Optional[datetime]
    rejected_by: Optional[str]
    rejected_at: Optional[datetime]
    rejection_reason: Optional[str]
    dispatch_count: int
    dispatched_at: Optional[datetime]
    expires_at: datetime
    completed_at: Optional[datetime]
    result_summary: Optional[str]
    result_evidence: tuple[str, ...]


@dataclass(frozen=True)
class AgentResponseAction:
    action_id: str
    action_type: ResponseActionType
    target_type: Literal["device"]
    target_id: str
    rationale: str
    risk_level: Literal["active"]
    expires_at: datetime


@dataclass(frozen=True)
class ResponseResult:
    action_id: str
    status: ResponseResultStatus
    changed: bool


class StandaloneResponseService:
    """Enforce independent approval and signed, idempotent device dispatch."""

    _ACTION_TYPES = frozenset({"isolate_endpoint", "release_endpoint"})

    def __init__(
        self,
        database: StandaloneDatabase,
        identity: HumanIdentityService,
        audit: StandaloneAuditLog,
        authenticator: DeviceHmacAuthenticator,
        *,
        max_dispatch_attempts: int = 5,
    ) -> None:
        if max_dispatch_attempts < 1 or max_dispatch_attempts > 5:
            raise ValueError("max_dispatch_attempts must be between 1 and 5")
        self._database = database
        self._identity = identity
        self._audit = audit
        self._authenticator = authenticator
        self._max_dispatch_attempts = max_dispatch_attempts

    def propose(
        self,
        principal: SessionPrincipal,
        case_id: str,
        action_type: ResponseActionType,
        device_id: str,
        rationale: str,
        now: datetime,
        *,
        expires_in_seconds: int = 300,
    ) -> ResponseAction:
        self._identity.require_capability(
            principal,
            principal.tenant_id,
            Capability.PROPOSE_RESPONSE,
        )
        if action_type not in self._ACTION_TYPES:
            raise ResponseValidationError("response action type is not allowlisted")
        normalized_rationale = rationale.strip()
        if not normalized_rationale or len(normalized_rationale) > 500:
            raise ResponseValidationError(
                "response rationale must contain between 1 and 500 characters"
            )
        if expires_in_seconds < 60 or expires_in_seconds > 900:
            raise ResponseValidationError("response proposal expiry must be 60 to 900 seconds")
        action_id = str(uuid.uuid4())
        expires_at = now + timedelta(seconds=expires_in_seconds)
        with self._database.connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            try:
                self._expire_due(
                    connection,
                    principal.tenant_id,
                    now,
                    device_id=device_id,
                )
                self._expire_closed_case_actions(
                    connection,
                    principal.tenant_id,
                    now,
                    device_id=device_id,
                )
                case = connection.execute(
                    """
                    SELECT 1 FROM cases
                    WHERE tenant_id = ? AND case_id = ? AND status != 'closed'
                    """,
                    (principal.tenant_id, case_id),
                ).fetchone()
                device = connection.execute(
                    """
                    SELECT 1 FROM devices
                    WHERE tenant_id = ? AND device_id = ? AND status = 'active'
                    """,
                    (principal.tenant_id, device_id),
                ).fetchone()
                if case is None:
                    raise ResponseNotFoundError("response case is unavailable")
                if device is None:
                    raise ResponseNotFoundError("response target device is unavailable")
                try:
                    connection.execute(
                        """
                        INSERT INTO response_actions(
                            tenant_id, action_id, case_id, action_type, target_type,
                            target_id, rationale, risk_level, status, proposed_by,
                            proposed_at, expires_at
                        ) VALUES (?, ?, ?, ?, 'device', ?, ?, 'active', 'proposed', ?, ?, ?)
                        """,
                        (
                            principal.tenant_id,
                            action_id,
                            case_id,
                            action_type,
                            device_id,
                            normalized_rationale,
                            principal.user_id,
                            _utc_text(now),
                            _utc_text(expires_at),
                        ),
                    )
                except sqlite3.IntegrityError as exc:
                    raise ResponseConflictError(
                        "target device already has a live response action"
                    ) from exc
                self._audit.append(
                    connection,
                    principal.tenant_id,
                    "response.proposed",
                    "user",
                    principal.user_id,
                    "response_action",
                    action_id,
                    {
                        "action_type": action_type,
                        "case_id": case_id,
                        "expires_at": _utc_text(expires_at),
                        "target_id": device_id,
                    },
                    now,
                )
                connection.execute("COMMIT")
            except Exception:
                if connection.in_transaction:
                    connection.execute("ROLLBACK")
                raise
        return self.get(principal, action_id)

    def approve(
        self,
        principal: SessionPrincipal,
        action_id: str,
        now: datetime,
    ) -> ResponseAction:
        self._identity.require_capability(
            principal,
            principal.tenant_id,
            Capability.APPROVE_RESPONSE,
        )
        expired = False
        with self._database.connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            try:
                row = self._require_action(connection, principal.tenant_id, action_id)
                if str(row["proposed_by"]) == principal.user_id:
                    raise HumanAuthorizationError("response proposer cannot approve the action")
                if self._case_is_closed(connection, row):
                    self._expire_one(connection, row, now, reason="case_closed")
                    expired = True
                elif str(row["expires_at"]) <= _utc_text(now):
                    self._expire_one(connection, row, now)
                    expired = True
                elif row["status"] != "proposed":
                    raise ResponseConflictError("response action is not awaiting approval")
                else:
                    changed = connection.execute(
                        """
                        UPDATE response_actions
                        SET status = 'approved', approved_by = ?, approved_at = ?
                        WHERE tenant_id = ? AND action_id = ? AND status = 'proposed'
                          AND proposed_by != ? AND expires_at > ?
                        """,
                        (
                            principal.user_id,
                            _utc_text(now),
                            principal.tenant_id,
                            action_id,
                            principal.user_id,
                            _utc_text(now),
                        ),
                    )
                    if changed.rowcount != 1:
                        raise ResponseConflictError("response approval lost an atomic race")
                    self._audit.append(
                        connection,
                        principal.tenant_id,
                        "response.approved",
                        "user",
                        principal.user_id,
                        "response_action",
                        action_id,
                        {"proposed_by": str(row["proposed_by"])},
                        now,
                    )
                connection.execute("COMMIT")
            except Exception:
                if connection.in_transaction:
                    connection.execute("ROLLBACK")
                raise
        if expired:
            raise ResponseExpiredError("response proposal expired before approval")
        return self.get(principal, action_id)

    def reject(
        self,
        principal: SessionPrincipal,
        action_id: str,
        reason: str,
        now: datetime,
    ) -> ResponseAction:
        self._identity.require_capability(
            principal,
            principal.tenant_id,
            Capability.APPROVE_RESPONSE,
        )
        normalized_reason = reason.strip()
        if not normalized_reason or len(normalized_reason) > 500:
            raise ResponseValidationError(
                "rejection reason must contain between 1 and 500 characters"
            )
        expired = False
        with self._database.connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            try:
                row = self._require_action(connection, principal.tenant_id, action_id)
                if str(row["proposed_by"]) == principal.user_id:
                    raise HumanAuthorizationError("response proposer cannot reject the action")
                if str(row["expires_at"]) <= _utc_text(now):
                    self._expire_one(connection, row, now)
                    expired = True
                elif row["status"] != "proposed":
                    raise ResponseConflictError("response action is not awaiting review")
                else:
                    changed = connection.execute(
                        """
                        UPDATE response_actions
                        SET status = 'rejected', rejected_by = ?, rejected_at = ?,
                            rejection_reason = ?
                        WHERE tenant_id = ? AND action_id = ? AND status = 'proposed'
                          AND proposed_by != ? AND expires_at > ?
                        """,
                        (
                            principal.user_id,
                            _utc_text(now),
                            normalized_reason,
                            principal.tenant_id,
                            action_id,
                            principal.user_id,
                            _utc_text(now),
                        ),
                    )
                    if changed.rowcount != 1:
                        raise ResponseConflictError("response rejection lost an atomic race")
                    self._audit.append(
                        connection,
                        principal.tenant_id,
                        "response.rejected",
                        "user",
                        principal.user_id,
                        "response_action",
                        action_id,
                        {"reason": normalized_reason},
                        now,
                    )
                connection.execute("COMMIT")
            except Exception:
                if connection.in_transaction:
                    connection.execute("ROLLBACK")
                raise
        if expired:
            raise ResponseExpiredError("response proposal expired before review")
        return self.get(principal, action_id)

    def get(self, principal: SessionPrincipal, action_id: str) -> ResponseAction:
        self._identity.require_capability(principal, principal.tenant_id, Capability.VIEW)
        with self._database.connect() as connection:
            row = connection.execute(
                """
                SELECT * FROM response_actions
                WHERE tenant_id = ? AND action_id = ?
                """,
                (principal.tenant_id, action_id),
            ).fetchone()
        if row is None:
            raise ResponseNotFoundError("response action is unavailable")
        return self._action(row)

    def list_actions(
        self,
        principal: SessionPrincipal,
        now: datetime,
        *,
        limit: int = 100,
    ) -> list[ResponseAction]:
        self._identity.require_capability(principal, principal.tenant_id, Capability.VIEW)
        if limit < 1 or limit > 200:
            raise ResponseValidationError("response query limit must be between 1 and 200")
        with self._database.connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            try:
                self._expire_due(connection, principal.tenant_id, now)
                self._expire_closed_case_actions(connection, principal.tenant_id, now)
                rows = connection.execute(
                    """
                    SELECT * FROM response_actions
                    WHERE tenant_id = ?
                    ORDER BY proposed_at DESC, action_id DESC LIMIT ?
                    """,
                    (principal.tenant_id, limit),
                ).fetchall()
                connection.execute("COMMIT")
            except Exception:
                if connection.in_transaction:
                    connection.execute("ROLLBACK")
                raise
        return [self._action(row) for row in rows]

    def poll_device(
        self,
        request: SignedCollectorRequest,
        requested_device_id: str,
        now: datetime,
    ) -> list[AgentResponseAction]:
        device = self._authenticator.authenticate(request, now)
        if requested_device_id != device.device_id:
            raise DeviceActionBindingError("collector action poll target does not match credential")
        dispatched: list[AgentResponseAction] = []
        with self._database.connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            try:
                self._expire_due(
                    connection,
                    device.tenant_id,
                    now,
                    device_id=device.device_id,
                )
                self._expire_closed_case_actions(
                    connection,
                    device.tenant_id,
                    now,
                    device_id=device.device_id,
                )
                rows = connection.execute(
                    """
                    SELECT r.* FROM response_actions r
                    JOIN cases c ON c.tenant_id = r.tenant_id AND c.case_id = r.case_id
                    WHERE r.tenant_id = ? AND r.target_type = 'device' AND r.target_id = ?
                      AND c.status != 'closed'
                      AND r.status IN ('approved', 'dispatched') AND r.expires_at > ?
                      AND r.dispatch_count < ?
                    ORDER BY r.approved_at, r.action_id LIMIT 20
                    """,
                    (
                        device.tenant_id,
                        device.device_id,
                        _utc_text(now),
                        self._max_dispatch_attempts,
                    ),
                ).fetchall()
                for row in rows:
                    if row["status"] == "approved":
                        changed = connection.execute(
                            """
                            UPDATE response_actions
                            SET status = 'dispatched', dispatch_count = 1, dispatched_at = ?
                            WHERE tenant_id = ? AND action_id = ? AND status = 'approved'
                              AND expires_at > ?
                            """,
                            (
                                _utc_text(now),
                                device.tenant_id,
                                row["action_id"],
                                _utc_text(now),
                            ),
                        )
                        action = "response.dispatched"
                        dispatch_count = 1
                    else:
                        dispatch_count = int(row["dispatch_count"]) + 1
                        changed = connection.execute(
                            """
                            UPDATE response_actions SET dispatch_count = ?
                            WHERE tenant_id = ? AND action_id = ? AND status = 'dispatched'
                              AND dispatch_count = ? AND expires_at > ?
                            """,
                            (
                                dispatch_count,
                                device.tenant_id,
                                row["action_id"],
                                row["dispatch_count"],
                                _utc_text(now),
                            ),
                        )
                        action = "response.dispatch_retried"
                    if changed.rowcount != 1:
                        raise ResponseConflictError("response dispatch lost an atomic race")
                    self._audit.append(
                        connection,
                        device.tenant_id,
                        action,
                        "device",
                        device.device_id,
                        "response_action",
                        str(row["action_id"]),
                        {"dispatch_count": dispatch_count},
                        now,
                    )
                    dispatched.append(self._agent_action(row))
                connection.execute("COMMIT")
            except Exception:
                if connection.in_transaction:
                    connection.execute("ROLLBACK")
                raise
        return dispatched

    def submit_device_result(
        self,
        request: SignedCollectorRequest,
        action_id: str,
        status: ResponseResultStatus,
        summary: str,
        evidence: list[str],
        now: datetime,
    ) -> ResponseResult:
        device = self._authenticator.authenticate(request, now)
        if status not in {"succeeded", "failed"}:
            raise ResponseValidationError("response result status is invalid")
        normalized_summary = summary.strip()
        if not normalized_summary or len(normalized_summary) > 500:
            raise ResponseValidationError(
                "response result summary must contain between 1 and 500 characters"
            )
        if len(evidence) > 20 or any(
            not item.strip() or len(item.strip()) > 256 for item in evidence
        ):
            raise ResponseValidationError("response evidence is outside the bounded contract")
        normalized_evidence = [item.strip() for item in evidence]
        result_json = json.dumps(
            {
                "evidence": normalized_evidence,
                "status": status,
                "summary": normalized_summary,
            },
            ensure_ascii=False,
            separators=(",", ":"),
            sort_keys=True,
        )
        expired = False
        with self._database.connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            try:
                row = self._require_action(connection, device.tenant_id, action_id)
                if row["target_type"] != "device" or row["target_id"] != device.device_id:
                    raise DeviceActionBindingError(
                        "collector result does not match the response target"
                    )
                if row["status"] in {"succeeded", "failed"}:
                    if (
                        row["status"] == status
                        and row["result_device_id"] == device.device_id
                        and row["result_json"] == result_json
                    ):
                        connection.execute("COMMIT")
                        return ResponseResult(action_id, status, False)
                    raise ResponseConflictError("response action already has a different result")
                if row["status"] == "dispatched" and str(row["expires_at"]) <= _utc_text(now):
                    self._expire_one(connection, row, now)
                    expired = True
                elif row["status"] != "dispatched":
                    raise ResponseConflictError("response action was not dispatched")
                else:
                    changed = connection.execute(
                        """
                        UPDATE response_actions
                        SET status = ?, result_json = ?, result_device_id = ?, completed_at = ?
                        WHERE tenant_id = ? AND action_id = ? AND status = 'dispatched'
                          AND target_type = 'device' AND target_id = ? AND expires_at > ?
                        """,
                        (
                            status,
                            result_json,
                            device.device_id,
                            _utc_text(now),
                            device.tenant_id,
                            action_id,
                            device.device_id,
                            _utc_text(now),
                        ),
                    )
                    if changed.rowcount != 1:
                        raise ResponseConflictError("response result lost an atomic race")
                    self._audit.append(
                        connection,
                        device.tenant_id,
                        f"response.{status}",
                        "device",
                        device.device_id,
                        "response_action",
                        action_id,
                        {
                            "evidence": normalized_evidence,
                            "summary": normalized_summary,
                        },
                        now,
                    )
                connection.execute("COMMIT")
            except Exception:
                if connection.in_transaction:
                    connection.execute("ROLLBACK")
                raise
        if expired:
            raise ResponseExpiredError("response action expired before its result arrived")
        return ResponseResult(action_id, status, True)

    def _expire_due(
        self,
        connection: sqlite3.Connection,
        tenant_id: str,
        now: datetime,
        *,
        device_id: Optional[str] = None,
    ) -> None:
        if device_id is None:
            rows = connection.execute(
                """
                SELECT * FROM response_actions
                WHERE tenant_id = ? AND status IN ('proposed', 'approved', 'dispatched')
                  AND expires_at <= ?
                ORDER BY action_id
                """,
                (tenant_id, _utc_text(now)),
            ).fetchall()
        else:
            rows = connection.execute(
                """
                SELECT * FROM response_actions
                WHERE tenant_id = ? AND status IN ('proposed', 'approved', 'dispatched')
                  AND expires_at <= ? AND target_type = 'device' AND target_id = ?
                ORDER BY action_id
                """,
                (tenant_id, _utc_text(now), device_id),
            ).fetchall()
        for row in rows:
            self._expire_one(connection, row, now)

    def _expire_one(
        self,
        connection: sqlite3.Connection,
        row: sqlite3.Row,
        now: datetime,
        *,
        reason: str = "deadline",
    ) -> None:
        changed = connection.execute(
            """
            UPDATE response_actions SET status = 'expired', completed_at = ?
            WHERE tenant_id = ? AND action_id = ?
              AND status IN ('proposed', 'approved', 'dispatched')
            """,
            (_utc_text(now), row["tenant_id"], row["action_id"]),
        )
        if changed.rowcount == 1:
            self._audit.append(
                connection,
                str(row["tenant_id"]),
                "response.expired",
                "system",
                "standalone-response-governor",
                "response_action",
                str(row["action_id"]),
                {"previous_status": str(row["status"]), "reason": reason},
                now,
            )

    def _expire_closed_case_actions(
        self,
        connection: sqlite3.Connection,
        tenant_id: str,
        now: datetime,
        *,
        device_id: Optional[str] = None,
    ) -> None:
        if device_id is None:
            rows = connection.execute(
                """
                SELECT r.* FROM response_actions r
                JOIN cases c ON c.tenant_id = r.tenant_id AND c.case_id = r.case_id
                WHERE r.tenant_id = ? AND c.status = 'closed'
                  AND r.status IN ('proposed', 'approved')
                ORDER BY r.action_id
                """,
                (tenant_id,),
            ).fetchall()
        else:
            rows = connection.execute(
                """
                SELECT r.* FROM response_actions r
                JOIN cases c ON c.tenant_id = r.tenant_id AND c.case_id = r.case_id
                WHERE r.tenant_id = ? AND c.status = 'closed'
                  AND r.status IN ('proposed', 'approved')
                  AND r.target_type = 'device' AND r.target_id = ?
                ORDER BY r.action_id
                """,
                (tenant_id, device_id),
            ).fetchall()
        for row in rows:
            self._expire_one(connection, row, now, reason="case_closed")

    @staticmethod
    def _require_action(
        connection: sqlite3.Connection,
        tenant_id: str,
        action_id: str,
    ) -> sqlite3.Row:
        row = connection.execute(
            """
            SELECT * FROM response_actions
            WHERE tenant_id = ? AND action_id = ?
            """,
            (tenant_id, action_id),
        ).fetchone()
        if row is None:
            raise ResponseNotFoundError("response action is unavailable")
        return cast(sqlite3.Row, row)

    @staticmethod
    def _case_is_closed(connection: sqlite3.Connection, row: sqlite3.Row) -> bool:
        case = connection.execute(
            """
            SELECT status FROM cases WHERE tenant_id = ? AND case_id = ?
            """,
            (row["tenant_id"], row["case_id"]),
        ).fetchone()
        return case is None or case["status"] == "closed"

    @classmethod
    def _action(cls, row: sqlite3.Row) -> ResponseAction:
        result_summary, result_evidence = cls._stored_result(row["result_json"])
        return ResponseAction(
            action_id=str(row["action_id"]),
            tenant_id=str(row["tenant_id"]),
            case_id=str(row["case_id"]),
            action_type=cls._action_type(str(row["action_type"])),
            target_id=str(row["target_id"]),
            rationale=str(row["rationale"]),
            status=cls._status(str(row["status"])),
            proposed_by=str(row["proposed_by"]),
            proposed_at=cls._parse_time(str(row["proposed_at"])),
            approved_by=(str(row["approved_by"]) if row["approved_by"] is not None else None),
            approved_at=(
                cls._parse_time(str(row["approved_at"])) if row["approved_at"] is not None else None
            ),
            rejected_by=(str(row["rejected_by"]) if row["rejected_by"] is not None else None),
            rejected_at=(
                cls._parse_time(str(row["rejected_at"])) if row["rejected_at"] is not None else None
            ),
            rejection_reason=(
                str(row["rejection_reason"]) if row["rejection_reason"] is not None else None
            ),
            dispatch_count=int(row["dispatch_count"]),
            dispatched_at=(
                cls._parse_time(str(row["dispatched_at"]))
                if row["dispatched_at"] is not None
                else None
            ),
            expires_at=cls._parse_time(str(row["expires_at"])),
            completed_at=(
                cls._parse_time(str(row["completed_at"]))
                if row["completed_at"] is not None
                else None
            ),
            result_summary=result_summary,
            result_evidence=result_evidence,
        )

    @classmethod
    def _agent_action(cls, row: sqlite3.Row) -> AgentResponseAction:
        return AgentResponseAction(
            action_id=str(row["action_id"]),
            action_type=cls._action_type(str(row["action_type"])),
            target_type="device",
            target_id=str(row["target_id"]),
            rationale=str(row["rationale"]),
            risk_level="active",
            expires_at=cls._parse_time(str(row["expires_at"])),
        )

    @classmethod
    def _action_type(cls, value: str) -> ResponseActionType:
        if value not in cls._ACTION_TYPES:
            raise ResponseValidationError("stored response action type is invalid")
        return cast(ResponseActionType, value)

    @staticmethod
    def _status(value: str) -> ResponseActionStatus:
        if value not in {
            "proposed",
            "approved",
            "rejected",
            "dispatched",
            "succeeded",
            "failed",
            "expired",
        }:
            raise ResponseValidationError("stored response status is invalid")
        return cast(ResponseActionStatus, value)

    @staticmethod
    def _parse_time(value: str) -> datetime:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))

    @staticmethod
    def _stored_result(value: object) -> tuple[Optional[str], tuple[str, ...]]:
        if value is None:
            return None, ()
        try:
            payload = json.loads(str(value))
        except (TypeError, ValueError) as exc:
            raise ResponseValidationError("stored response result is invalid") from exc
        if not isinstance(payload, dict):
            raise ResponseValidationError("stored response result is invalid")
        summary = payload.get("summary")
        evidence = payload.get("evidence")
        if not isinstance(summary, str) or not isinstance(evidence, list):
            raise ResponseValidationError("stored response result is invalid")
        if not all(isinstance(item, str) for item in evidence):
            raise ResponseValidationError("stored response result is invalid")
        return summary, tuple(evidence)


__all__ = [
    "AgentResponseAction",
    "DeviceActionBindingError",
    "ResponseAction",
    "ResponseActionStatus",
    "ResponseActionType",
    "ResponseConflictError",
    "ResponseExpiredError",
    "ResponseGovernanceError",
    "ResponseNotFoundError",
    "ResponseResult",
    "ResponseResultStatus",
    "ResponseValidationError",
    "StandaloneResponseService",
]
