"""Evidence-preserving deterministic alert replay for standalone investigations."""

from __future__ import annotations

import json
import sqlite3
import uuid
from dataclasses import dataclass
from datetime import datetime
from typing import Literal, Optional

from controlforge.detections import SigmaRule, SigmaSubsetEvaluator, sigma_rule_digest
from controlforge.models import SecurityEvent

from .database import StandaloneDatabase
from .store import _utc_text

ReplayMode = Literal["original", "current"]
ReplayOutcome = Literal["same", "changed", "unavailable"]


class ReplayError(RuntimeError):
    """Raised when a requested replay cannot be resolved safely."""


@dataclass(frozen=True)
class ReplayResult:
    replay_id: str
    alert_id: str
    mode: ReplayMode
    outcome: ReplayOutcome
    matched: Optional[bool]
    rule_id: str
    rule_version: str
    rule_digest: str
    detector_version: str
    evidence: dict[str, object]


class DecisionReplayService:
    """Re-evaluate immutable event evidence against original or current rule content."""

    def __init__(
        self,
        database: StandaloneDatabase,
        current_rules: list[SigmaRule],
        detector_version: str,
    ) -> None:
        self._database = database
        self._current_rules = {rule.id: rule for rule in current_rules}
        self._detector_version = detector_version
        self._evaluator = SigmaSubsetEvaluator()

    def replay(
        self,
        tenant_id: str,
        alert_id: str,
        requested_by: str,
        mode: ReplayMode,
        now: datetime,
    ) -> ReplayResult:
        if mode not in {"original", "current"}:
            raise ValueError("replay mode must be original or current")
        with self._database.connect() as connection:
            row = connection.execute(
                """
                SELECT a.alert_id, a.rule_id, a.rule_version, a.rule_digest,
                       a.rule_snapshot_json, a.detector_version, a.title, a.severity,
                       a.reasons_json, a.tags_json, a.evidence_json, e.payload_json,
                       e.payload_sha256
                FROM alerts a
                JOIN events e
                  ON e.tenant_id = a.tenant_id AND e.event_id = a.event_id
                WHERE a.tenant_id = ? AND a.alert_id = ?
                """,
                (tenant_id, alert_id),
            ).fetchone()
        if row is None:
            raise ReplayError("alert evidence is unavailable")

        event = SecurityEvent.model_validate_json(str(row["payload_json"]))
        rule = self._resolve_rule(row, mode)
        if rule is None:
            result = self._unavailable_result(row, alert_id, mode)
        else:
            replayed = self._evaluator.evaluate(rule, event)
            digest = sigma_rule_digest(rule)
            stored_reasons = self._json_list(row["reasons_json"])
            stored_tags = self._json_list(row["tags_json"])
            matched = replayed is not None
            same_projection = bool(
                replayed is not None
                and replayed.title == row["title"]
                and replayed.severity.value == row["severity"]
                and replayed.reasons == stored_reasons
                and replayed.tags == stored_tags
            )
            outcome: ReplayOutcome = (
                "same" if same_projection and digest == row["rule_digest"] else "changed"
            )
            result = ReplayResult(
                replay_id=str(uuid.uuid4()),
                alert_id=alert_id,
                mode=mode,
                outcome=outcome,
                matched=matched,
                rule_id=rule.id,
                rule_version=str(rule.rule_version),
                rule_digest=digest,
                detector_version=(
                    str(row["detector_version"]) if mode == "original" else self._detector_version
                ),
                evidence={
                    "source_event_sha256": str(row["payload_sha256"]),
                    "stored_alert_evidence": json.loads(str(row["evidence_json"])),
                    "replayed_reasons": replayed.reasons if replayed is not None else [],
                    "replayed_tags": replayed.tags if replayed is not None else [],
                },
            )
        self._persist(tenant_id, requested_by, result, now)
        return result

    def _resolve_rule(self, row: sqlite3.Row, mode: ReplayMode) -> Optional[SigmaRule]:
        if mode == "current":
            return self._current_rules.get(str(row["rule_id"]))
        try:
            snapshot = json.loads(str(row["rule_snapshot_json"]))
            if not isinstance(snapshot, dict) or not snapshot:
                return None
            return SigmaRule.model_validate(snapshot)
        except (ValueError, TypeError):
            return None

    def _unavailable_result(
        self,
        row: sqlite3.Row,
        alert_id: str,
        mode: ReplayMode,
    ) -> ReplayResult:
        return ReplayResult(
            replay_id=str(uuid.uuid4()),
            alert_id=alert_id,
            mode=mode,
            outcome="unavailable",
            matched=None,
            rule_id=str(row["rule_id"]),
            rule_version=str(row["rule_version"]),
            rule_digest=str(row["rule_digest"]),
            detector_version=(
                str(row["detector_version"]) if mode == "original" else self._detector_version
            ),
            evidence={"reason": "requested rule content is unavailable"},
        )

    def _persist(
        self,
        tenant_id: str,
        requested_by: str,
        result: ReplayResult,
        now: datetime,
    ) -> None:
        payload = {
            "matched": result.matched,
            "outcome": result.outcome,
            "evidence": result.evidence,
        }
        with self._database.connect() as connection:
            connection.execute(
                """
                INSERT INTO detection_replays(
                    tenant_id, replay_id, alert_id, requested_by, replay_mode,
                    rule_id, rule_version, rule_digest, detector_version,
                    outcome, result_json, created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    tenant_id,
                    result.replay_id,
                    result.alert_id,
                    requested_by,
                    result.mode,
                    result.rule_id,
                    result.rule_version,
                    result.rule_digest,
                    result.detector_version,
                    result.outcome,
                    json.dumps(payload, separators=(",", ":"), sort_keys=True),
                    _utc_text(now),
                ),
            )

    @staticmethod
    def _json_list(raw: object) -> list[str]:
        parsed = json.loads(str(raw))
        if not isinstance(parsed, list) or not all(isinstance(item, str) for item in parsed):
            raise ReplayError("stored alert evidence is invalid")
        return parsed


__all__ = ["DecisionReplayService", "ReplayError", "ReplayResult"]
