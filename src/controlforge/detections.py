"""Sigma-style stateless and stateful security-event detections."""

from __future__ import annotations

import fnmatch
import hashlib
import ipaddress
import json
import math
import re
from collections import defaultdict, deque
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import asdict, dataclass
from datetime import datetime, timedelta
from pathlib import Path
from typing import ClassVar, Optional, Protocol

import yaml
from pydantic import BaseModel, ConfigDict, Field

from .models import DetectionAlert, SecurityEvent, Severity


@dataclass(frozen=True)
class StatefulCorrelationSpec:
    rule_id: str
    rule_version: int
    title: str
    severity: Severity
    tags: tuple[str, ...]
    event_type: str
    window_minutes: Optional[int] = None
    event_threshold: Optional[int] = None
    distinct_threshold: Optional[int] = None
    byte_threshold: Optional[int] = None
    maximum_speed_kph: Optional[float] = None


@dataclass(frozen=True)
class BuiltinOutcome:
    value: str
    title: str
    severity: Severity


@dataclass(frozen=True)
class BuiltinDetectionSpec:
    rule_id: str
    rule_version: int
    event_type: str
    attribute: str
    outcomes: tuple[BuiltinOutcome, ...]
    tags: tuple[str, ...]


BUILTIN_DETECTIONS: tuple[BuiltinDetectionSpec, ...] = (
    BuiltinDetectionSpec(
        rule_id="CF-CONTROL-001",
        rule_version=1,
        event_type="endpoint_control_status",
        attribute="status",
        outcomes=(
            BuiltinOutcome(
                value="failed",
                title="Required endpoint security control failed",
                severity=Severity.HIGH,
            ),
            BuiltinOutcome(
                value="degraded",
                title="Endpoint security control degraded",
                severity=Severity.MEDIUM,
            ),
        ),
        tags=("control-assurance", "endpoint-security", "defense-evasion"),
    ),
)


STATEFUL_CORRELATIONS: tuple[StatefulCorrelationSpec, ...] = (
    StatefulCorrelationSpec(
        rule_id="CF-INSIDER-001",
        rule_version=1,
        title="Unusual sensitive-data access volume",
        severity=Severity.HIGH,
        tags=("insider-risk", "financial-data", "behavioral-analytics"),
        event_type="sensitive_data_access",
        window_minutes=15,
        event_threshold=10,
        byte_threshold=50_000_000,
    ),
    StatefulCorrelationSpec(
        rule_id="CF-IDENTITY-001",
        rule_version=1,
        title="Impossible-travel authentication",
        severity=Severity.HIGH,
        tags=("identity", "account-takeover", "behavioral-analytics"),
        event_type="authentication_success",
        maximum_speed_kph=900.0,
    ),
    StatefulCorrelationSpec(
        rule_id="CF-EDGE-002",
        rule_version=1,
        title="Credential-stuffing pattern at the authentication edge",
        severity=Severity.HIGH,
        tags=("edge-security", "credential-access", "account-takeover", "attack.t1110"),
        event_type="edge_auth_failure",
        window_minutes=5,
        event_threshold=20,
        distinct_threshold=10,
    ),
    StatefulCorrelationSpec(
        rule_id="CF-EDGE-003",
        rule_version=1,
        title="Possible session replay across source addresses",
        severity=Severity.HIGH,
        tags=("edge-security", "session-hijacking", "account-takeover"),
        event_type="edge_session_use",
        window_minutes=10,
    ),
)

_STATEFUL_BY_EVENT = {spec.event_type: spec for spec in STATEFUL_CORRELATIONS}


def stateful_correlation_for_event(event_type: str) -> Optional[StatefulCorrelationSpec]:
    """Return the canonical correlation contract for an event type, when present."""

    return _STATEFUL_BY_EVENT.get(event_type)


def canonical_stateful_correlations() -> list[dict[str, object]]:
    """Return the portable correlation metadata compiled into the Cloud artifact."""

    return [
        {
            **asdict(spec),
            "severity": spec.severity.value,
            "tags": list(spec.tags),
        }
        for spec in STATEFUL_CORRELATIONS
    ]


def canonical_builtin_detections() -> list[dict[str, object]]:
    """Return portable non-Sigma decisions with data-dependent outcomes."""

    return [
        {
            "rule_id": spec.rule_id,
            "rule_version": spec.rule_version,
            "event_type": spec.event_type,
            "attribute": spec.attribute,
            "outcomes": [
                {
                    "value": outcome.value,
                    "title": outcome.title,
                    "severity": outcome.severity.value,
                }
                for outcome in spec.outcomes
            ],
            "tags": list(spec.tags),
        }
        for spec in BUILTIN_DETECTIONS
    ]


def canonical_contract_digest(payload: Mapping[str, object]) -> str:
    """Hash a non-Sigma detection contract with portable canonical JSON."""

    canonical = json.dumps(
        payload,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode()
    return f"sha256:{hashlib.sha256(canonical).hexdigest()}"


def canonical_non_sigma_provenance() -> dict[str, tuple[str, str, str]]:
    """Return version, digest, and snapshot metadata for built-ins and correlations."""

    provenance: dict[str, tuple[str, str, str]] = {}
    for payload in [*canonical_builtin_detections(), *canonical_stateful_correlations()]:
        rule_id = str(payload["rule_id"])
        snapshot = json.dumps(
            payload,
            ensure_ascii=False,
            separators=(",", ":"),
            sort_keys=True,
        )
        provenance[rule_id] = (
            str(payload["rule_version"]),
            canonical_contract_digest(payload),
            snapshot,
        )
    return provenance


class SigmaRule(BaseModel):
    model_config = ConfigDict(extra="forbid")

    id: str = Field(min_length=1)
    rule_version: int = Field(ge=1)
    title: str = Field(min_length=1)
    description: str = ""
    status: str = "experimental"
    logsource: dict[str, str] = Field(default_factory=dict)
    detection: dict[str, object]
    level: Severity = Severity.MEDIUM
    tags: list[str] = Field(default_factory=list)


def canonical_sigma_rule(rule: SigmaRule) -> dict[str, object]:
    """Return the normalized rule object used for portable provenance digests."""

    return rule.model_dump(mode="json")


def sigma_rule_digest(rule: SigmaRule) -> str:
    """Hash rule semantics independently of YAML formatting or file location."""

    canonical = json.dumps(
        canonical_sigma_rule(rule),
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode()
    return f"sha256:{hashlib.sha256(canonical).hexdigest()}"


def alert_fingerprint_v1(tenant_id: str, rule_id: str, event_id: str) -> str:
    """Return the portable v1 occurrence ID without changing legacy persistence IDs."""

    payload = json.dumps(
        ["controlforge-alert", 1, tenant_id, rule_id, event_id],
        ensure_ascii=False,
        separators=(",", ":"),
    ).encode()
    return hashlib.sha256(payload).hexdigest()[:32]


def evaluate_builtin_stateless_event(event: SecurityEvent) -> list[DetectionAlert]:
    """Evaluate canonical built-ins that require data-dependent decision metadata."""

    alerts: list[DetectionAlert] = []
    for spec in BUILTIN_DETECTIONS:
        if event.event_type != spec.event_type:
            continue
        raw_value = event.attributes.get(spec.attribute)
        value = raw_value.casefold() if isinstance(raw_value, str) else ""
        outcome = next((item for item in spec.outcomes if item.value == value), None)
        if outcome is None:
            continue

        def evidence_value(raw: object) -> str:
            if isinstance(raw, bool):
                return "true" if raw else "false"
            return "unknown"

        installed = evidence_value(event.attributes.get("installed"))
        running = evidence_value(event.attributes.get("running"))
        fingerprint = f"{spec.rule_id}:{event.event_id}".encode()
        alerts.append(
            DetectionAlert(
                alert_id=hashlib.sha256(fingerprint).hexdigest()[:20],
                rule_id=spec.rule_id,
                title=outcome.title,
                severity=outcome.severity,
                event_id=event.event_id,
                actor=event.actor,
                reasons=[
                    f"endpoint control {event.target or 'unknown'} reported {value}",
                    f"installed={installed} running={running}",
                ],
                tags=list(spec.tags),
                created_at=event.timestamp,
            )
        )
    return alerts


def load_rules(directory: Path) -> list[SigmaRule]:
    """Load and validate all YAML detection rules in deterministic order."""

    rules: list[SigmaRule] = []
    rule_paths: dict[str, Path] = {}
    for path in sorted([*directory.glob("*.yml"), *directory.glob("*.yaml")]):
        raw = yaml.safe_load(path.read_text(encoding="utf-8"))
        if not isinstance(raw, dict):
            raise ValueError(f"{path}: rule must be a YAML mapping")
        rule = SigmaRule.model_validate(raw)
        normalized_id = rule.id.casefold()
        if normalized_id in rule_paths:
            raise ValueError(
                f"{path}: duplicate rule id {rule.id!r}; first defined in "
                f"{rule_paths[normalized_id]}"
            )
        rule_paths[normalized_id] = path
        rules.append(rule)
    if not rules:
        raise ValueError(f"no detection rules found in {directory}")
    return rules


class SigmaSubsetEvaluator:
    """Evaluate an intentionally documented, testable subset of Sigma syntax."""

    _SUPPORTED_OPERATORS: ClassVar[set[str]] = {
        "contains",
        "startswith",
        "endswith",
        "re",
        "cidr",
    }
    _CONDITION_TOKEN: ClassVar[re.Pattern[str]] = re.compile(
        r"\s*("
        r"1\s+of\s+[a-zA-Z0-9_*?-]+|"
        r"all\s+of\s+[a-zA-Z0-9_*?-]+|"
        r"and\b|or\b|not\b|"
        r"\(|\)|"
        r"[a-zA-Z0-9_*?-]+"
        r")",
        flags=re.IGNORECASE,
    )

    def evaluate(self, rule: SigmaRule, event: SecurityEvent) -> Optional[DetectionAlert]:
        raw_condition = rule.detection.get("condition")
        if not isinstance(raw_condition, str):
            raise ValueError(f"{rule.id}: detection.condition must be a string")

        selections = {
            key: value
            for key, value in rule.detection.items()
            if key not in {"condition", "timeframe"}
        }
        matched, reasons = self._evaluate_condition(raw_condition, selections, event)
        if not matched:
            return None

        fingerprint = f"{rule.id}:{event.event_id}".encode()
        return DetectionAlert(
            alert_id=hashlib.sha256(fingerprint).hexdigest()[:20],
            rule_id=rule.id,
            title=rule.title,
            severity=rule.level,
            event_id=event.event_id,
            actor=event.actor,
            reasons=reasons,
            tags=rule.tags,
            created_at=event.timestamp,
        )

    def _evaluate_condition(
        self,
        condition: str,
        selections: Mapping[str, object],
        event: SecurityEvent,
    ) -> tuple[bool, list[str]]:
        tokens = self._tokenize_condition(condition)
        position = 0

        def current() -> Optional[str]:
            return tokens[position] if position < len(tokens) else None

        def parse_primary() -> tuple[bool, list[str]]:
            nonlocal position
            symbol = current()
            if symbol is None:
                raise ValueError("unexpected end of Sigma condition")
            if symbol == "(":
                position += 1
                result = parse_or()
                if current() != ")":
                    raise ValueError("unclosed parenthesis in Sigma condition")
                position += 1
                return result
            if symbol == ")":
                raise ValueError("unexpected closing parenthesis in Sigma condition")

            position += 1
            one_of_match = re.fullmatch(r"1 of ([a-zA-Z0-9_*?-]+)", symbol)
            if one_of_match:
                pattern = one_of_match.group(1)
                candidates = [name for name in selections if fnmatch.fnmatch(name, pattern)]
                return self._evaluate_any(candidates, selections, event)

            all_of_match = re.fullmatch(r"all of ([a-zA-Z0-9_*?-]+)", symbol)
            if all_of_match:
                pattern = all_of_match.group(1)
                candidates = [name for name in selections if fnmatch.fnmatch(name, pattern)]
                return self._evaluate_all(candidates, selections, event)

            return self._evaluate_named(symbol, selections, event)

        def parse_not() -> tuple[bool, list[str]]:
            nonlocal position
            if current() == "not":
                position += 1
                matched, _ = parse_not()
                return not matched, []
            return parse_primary()

        def parse_and() -> tuple[bool, list[str]]:
            nonlocal position
            matched, reasons = parse_not()
            while current() == "and":
                position += 1
                right_matched, right_reasons = parse_not()
                if matched and right_matched:
                    reasons = [*reasons, *right_reasons]
                else:
                    matched, reasons = False, []
            return matched, reasons

        def parse_or() -> tuple[bool, list[str]]:
            nonlocal position
            matched, reasons = parse_and()
            while current() == "or":
                position += 1
                right_matched, right_reasons = parse_and()
                if not matched and right_matched:
                    matched, reasons = True, right_reasons
            return matched, reasons

        result = parse_or()
        if position != len(tokens):
            raise ValueError(f"unexpected token in Sigma condition: {tokens[position]}")
        return result

    def _tokenize_condition(self, condition: str) -> list[str]:
        tokens: list[str] = []
        position = 0
        while position < len(condition):
            match = self._CONDITION_TOKEN.match(condition, position)
            if match is None:
                if condition[position:].strip() == "":
                    break
                raise ValueError(f"unsupported Sigma condition near: {condition[position:]}")
            token = re.sub(r"\s+", " ", match.group(1).strip())
            lowered = token.casefold()
            tokens.append(lowered if lowered in {"and", "or", "not"} else token)
            position = match.end()
        if not tokens:
            raise ValueError("Sigma condition cannot be empty")
        return tokens

    def _evaluate_any(
        self,
        names: Sequence[str],
        selections: Mapping[str, object],
        event: SecurityEvent,
    ) -> tuple[bool, list[str]]:
        for name in names:
            matched, reasons = self._evaluate_named(name.strip(), selections, event)
            if matched:
                return True, reasons
        return False, []

    def _evaluate_all(
        self,
        names: Sequence[str],
        selections: Mapping[str, object],
        event: SecurityEvent,
    ) -> tuple[bool, list[str]]:
        all_reasons: list[str] = []
        for name in names:
            matched, reasons = self._evaluate_named(name.strip(), selections, event)
            if not matched:
                return False, []
            all_reasons.extend(reasons)
        return bool(names), all_reasons

    def _evaluate_named(
        self,
        name: str,
        selections: Mapping[str, object],
        event: SecurityEvent,
    ) -> tuple[bool, list[str]]:
        if name not in selections:
            raise ValueError(f"unknown selection in condition: {name}")
        selection = selections[name]
        branches = selection if isinstance(selection, list) else [selection]
        for branch in branches:
            if not isinstance(branch, dict):
                raise ValueError(f"selection {name} must be a mapping or list of mappings")
            matched, reasons = self._match_mapping(branch, event)
            if matched:
                return True, reasons
        return False, []

    def _match_mapping(
        self, criteria: Mapping[str, object], event: SecurityEvent
    ) -> tuple[bool, list[str]]:
        reasons: list[str] = []
        for expression, expected in criteria.items():
            field, operator = self._parse_expression(expression)
            actual = self._field_value(event, field)
            if not self._match_value(actual, expected, operator):
                return False, []
            reasons.append(f"{expression} matched {self._safe_expected(expected)}")
        return True, reasons

    def _parse_expression(self, expression: str) -> tuple[str, str]:
        field, separator, operator = expression.partition("|")
        if not separator:
            return field, "equals"
        if operator not in self._SUPPORTED_OPERATORS:
            raise ValueError(f"unsupported Sigma modifier: {operator}")
        return field, operator

    @staticmethod
    def _field_value(event: SecurityEvent, field: str) -> object:
        direct_fields: dict[str, object] = {
            "event_id": event.event_id,
            "event_type": event.event_type,
            "timestamp": event.timestamp.isoformat(),
            "actor": event.actor,
            "source_ip": event.source_ip or "",
            "target": event.target or "",
        }
        return direct_fields.get(field, event.attributes.get(field, ""))

    def _match_value(self, actual: object, expected: object, operator: str) -> bool:
        values = expected if isinstance(expected, list) else [expected]
        actual_values = actual if isinstance(actual, list) else [actual]
        return any(
            self._match_scalar(actual_value, expected_value, operator)
            for actual_value in actual_values
            for expected_value in values
        )

    @staticmethod
    def _match_scalar(actual: object, expected: object, operator: str) -> bool:
        actual_text = str(actual).casefold()
        expected_text = str(expected).casefold()
        if operator == "equals":
            return actual == expected or fnmatch.fnmatch(actual_text, expected_text)
        if operator == "contains":
            return expected_text in actual_text
        if operator == "startswith":
            return actual_text.startswith(expected_text)
        if operator == "endswith":
            return actual_text.endswith(expected_text)
        if operator == "re":
            return re.search(str(expected), str(actual), flags=re.IGNORECASE) is not None
        if operator == "cidr":
            try:
                return ipaddress.ip_address(str(actual)) in ipaddress.ip_network(
                    str(expected), strict=False
                )
            except ValueError:
                return False
        raise ValueError(f"unsupported operator: {operator}")

    @staticmethod
    def _safe_expected(expected: object) -> str:
        rendered = json.dumps(expected, ensure_ascii=False, separators=(",", ":"))
        return rendered if len(rendered) <= 80 else f"{rendered[:77]}..."


class BulkAccessDetector:
    """Stateful insider-risk signal for unusual data access volume."""

    def __init__(
        self,
        event_threshold: int = 10,
        byte_threshold: int = 50_000_000,
        window: timedelta = timedelta(minutes=15),
    ) -> None:
        self._event_threshold = event_threshold
        self._byte_threshold = byte_threshold
        self._window = window
        self._history: dict[str, deque[tuple[datetime, int, str]]] = defaultdict(deque)

    def evaluate(self, event: SecurityEvent) -> Optional[DetectionAlert]:
        if event.event_type != "sensitive_data_access":
            return None
        raw_bytes = event.attributes.get("bytes", 0)
        if (
            isinstance(raw_bytes, bool)
            or not isinstance(raw_bytes, (int, float))
            or not math.isfinite(float(raw_bytes))
        ):
            return None

        history = self._history[event.actor]
        history.append((event.timestamp, int(raw_bytes), event.event_id))
        cutoff = event.timestamp - self._window
        while history and history[0][0] < cutoff:
            history.popleft()

        total_bytes = sum(item[1] for item in history)
        if len(history) < self._event_threshold and total_bytes < self._byte_threshold:
            return None

        fingerprint = f"bulk-sensitive-access:{event.actor}:{event.event_id}".encode()
        spec = _STATEFUL_BY_EVENT[event.event_type]
        return DetectionAlert(
            alert_id=hashlib.sha256(fingerprint).hexdigest()[:20],
            rule_id=spec.rule_id,
            title=spec.title,
            severity=spec.severity,
            event_id=event.event_id,
            actor=event.actor,
            reasons=[
                f"{len(history)} access events within {int(self._window.total_seconds() / 60)}m",
                f"{total_bytes} bytes accessed",
            ],
            tags=list(spec.tags),
            created_at=event.timestamp,
        )


class ImpossibleTravelDetector:
    """Stateful identity signal based on geospatial login velocity."""

    def __init__(self, maximum_speed_kph: float = 900.0) -> None:
        self._maximum_speed_kph = maximum_speed_kph
        self._previous: dict[str, tuple[datetime, float, float, str]] = {}

    def evaluate(self, event: SecurityEvent) -> Optional[DetectionAlert]:
        if event.event_type != "authentication_success":
            return None
        latitude = event.attributes.get("latitude")
        longitude = event.attributes.get("longitude")
        if (
            isinstance(latitude, bool)
            or isinstance(longitude, bool)
            or not isinstance(latitude, (int, float))
            or not isinstance(longitude, (int, float))
            or not math.isfinite(float(latitude))
            or not math.isfinite(float(longitude))
        ):
            return None

        current = (event.timestamp, float(latitude), float(longitude), event.event_id)
        previous = self._previous.get(event.actor)
        self._previous[event.actor] = current
        if previous is None or event.timestamp <= previous[0]:
            return None

        hours = (event.timestamp - previous[0]).total_seconds() / 3600
        distance = self._haversine_km(previous[1], previous[2], current[1], current[2])
        speed = distance / hours
        if speed <= self._maximum_speed_kph:
            return None

        fingerprint = f"impossible-travel:{event.actor}:{event.event_id}".encode()
        spec = _STATEFUL_BY_EVENT[event.event_type]
        return DetectionAlert(
            alert_id=hashlib.sha256(fingerprint).hexdigest()[:20],
            rule_id=spec.rule_id,
            title=spec.title,
            severity=spec.severity,
            event_id=event.event_id,
            actor=event.actor,
            reasons=[
                f"calculated travel velocity {speed:.0f} km/h",
                f"distance {distance:.0f} km over {hours:.2f}h",
            ],
            tags=list(spec.tags),
            created_at=event.timestamp,
        )

    @staticmethod
    def _haversine_km(lat1: float, lon1: float, lat2: float, lon2: float) -> float:
        radius_km = 6371.0
        phi1, phi2 = math.radians(lat1), math.radians(lat2)
        delta_phi = math.radians(lat2 - lat1)
        delta_lambda = math.radians(lon2 - lon1)
        value = (
            math.sin(delta_phi / 2) ** 2
            + math.cos(phi1) * math.cos(phi2) * math.sin(delta_lambda / 2) ** 2
        )
        return radius_km * 2 * math.atan2(math.sqrt(value), math.sqrt(1 - value))


class CredentialStuffingDetector:
    """Detect one edge source failing authentication across many accounts."""

    def __init__(
        self,
        failure_threshold: int = 20,
        account_threshold: int = 10,
        window: timedelta = timedelta(minutes=5),
    ) -> None:
        self._failure_threshold = failure_threshold
        self._account_threshold = account_threshold
        self._window = window
        self._history: dict[str, deque[tuple[datetime, str, str]]] = defaultdict(deque)

    def evaluate(self, event: SecurityEvent) -> Optional[DetectionAlert]:
        if event.event_type != "edge_auth_failure" or not event.source_ip:
            return None

        history = self._history[event.source_ip]
        history.append((event.timestamp, event.actor, event.event_id))
        cutoff = event.timestamp - self._window
        while history and history[0][0] < cutoff:
            history.popleft()

        distinct_accounts = {item[1].casefold() for item in history}
        if (
            len(history) < self._failure_threshold
            or len(distinct_accounts) < self._account_threshold
        ):
            return None

        fingerprint = f"credential-stuffing:{event.source_ip}:{event.event_id}".encode()
        spec = _STATEFUL_BY_EVENT[event.event_type]
        return DetectionAlert(
            alert_id=hashlib.sha256(fingerprint).hexdigest()[:20],
            rule_id=spec.rule_id,
            title=spec.title,
            severity=spec.severity,
            event_id=event.event_id,
            actor=event.actor,
            reasons=[
                f"{len(history)} failed authentications from {event.source_ip}",
                f"{len(distinct_accounts)} distinct accounts within "
                f"{int(self._window.total_seconds() / 60)}m",
            ],
            tags=list(spec.tags),
            created_at=event.timestamp,
        )


class SessionReplayDetector:
    """Detect a hashed session identifier reused from a different source address."""

    def __init__(self, window: timedelta = timedelta(minutes=10)) -> None:
        self._window = window
        self._previous: dict[str, tuple[datetime, str, str, str]] = {}

    def evaluate(self, event: SecurityEvent) -> Optional[DetectionAlert]:
        if event.event_type != "edge_session_use" or not event.source_ip:
            return None
        session_hash = event.attributes.get("session_id_hash")
        if not isinstance(session_hash, str) or len(session_hash) < 12:
            return None

        previous = self._previous.get(session_hash)
        self._previous[session_hash] = (
            event.timestamp,
            event.source_ip,
            event.actor,
            event.event_id,
        )
        if previous is None or event.timestamp <= previous[0]:
            return None
        if event.timestamp - previous[0] > self._window or event.source_ip == previous[1]:
            return None

        fingerprint = f"session-replay:{session_hash}:{event.event_id}".encode()
        spec = _STATEFUL_BY_EVENT[event.event_type]
        return DetectionAlert(
            alert_id=hashlib.sha256(fingerprint).hexdigest()[:20],
            rule_id=spec.rule_id,
            title=spec.title,
            severity=spec.severity,
            event_id=event.event_id,
            actor=event.actor,
            reasons=[
                f"session hash reused from {previous[1]} and {event.source_ip}",
                f"reuse occurred within {int(self._window.total_seconds() / 60)}m",
            ],
            tags=list(spec.tags),
            created_at=event.timestamp,
        )


def _stateful_alert(
    event: SecurityEvent,
    spec: StatefulCorrelationSpec,
    fingerprint_scope: str,
    reasons: list[str],
) -> DetectionAlert:
    fingerprint = f"{fingerprint_scope}:{event.event_id}".encode()
    return DetectionAlert(
        alert_id=hashlib.sha256(fingerprint).hexdigest()[:20],
        rule_id=spec.rule_id,
        title=spec.title,
        severity=spec.severity,
        event_id=event.event_id,
        actor=event.actor,
        reasons=reasons,
        tags=list(spec.tags),
        created_at=event.timestamp,
    )


def evaluate_stateful_event(
    event: SecurityEvent,
    prior_events: Iterable[SecurityEvent],
) -> list[DetectionAlert]:
    """Evaluate one event against durable, tenant-scoped prior event-time history.

    The caller owns tenant isolation. Duplicate event identities are collapsed and the
    current persisted event is authoritative. Time windows include their lower bound;
    predecessor correlations require a strictly earlier timestamp.
    """

    spec = _STATEFUL_BY_EVENT.get(event.event_type)
    if spec is None:
        return []
    history_by_id = {
        item.event_id: item for item in prior_events if item.event_id != event.event_id
    }
    history = [*history_by_id.values(), event]

    if event.event_type == "sensitive_data_access":
        raw_bytes = event.attributes.get("bytes")
        if (
            isinstance(raw_bytes, bool)
            or not isinstance(raw_bytes, (int, float))
            or not math.isfinite(float(raw_bytes))
        ):
            return []
        if (
            spec.window_minutes is None
            or spec.event_threshold is None
            or spec.byte_threshold is None
        ):
            raise RuntimeError("bulk-access correlation contract is incomplete")
        cutoff = event.timestamp - timedelta(minutes=spec.window_minutes)
        samples: list[int] = []
        for item in history:
            value = item.attributes.get("bytes")
            if (
                item.event_type != event.event_type
                or item.actor != event.actor
                or item.timestamp < cutoff
                or item.timestamp > event.timestamp
                or isinstance(value, bool)
                or not isinstance(value, (int, float))
                or not math.isfinite(float(value))
            ):
                continue
            samples.append(int(value))
        total_bytes = sum(samples)
        if len(samples) < spec.event_threshold and total_bytes < spec.byte_threshold:
            return []
        return [
            _stateful_alert(
                event,
                spec,
                f"bulk-sensitive-access:{event.actor}",
                [
                    f"{len(samples)} access events within {spec.window_minutes}m",
                    f"{total_bytes} bytes accessed",
                ],
            )
        ]

    if event.event_type == "authentication_success":
        latitude = event.attributes.get("latitude")
        longitude = event.attributes.get("longitude")
        if (
            isinstance(latitude, bool)
            or isinstance(longitude, bool)
            or not isinstance(latitude, (int, float))
            or not isinstance(longitude, (int, float))
            or not math.isfinite(float(latitude))
            or not math.isfinite(float(longitude))
        ):
            return []
        candidates = [
            item
            for item in history
            if item.event_id != event.event_id
            and item.event_type == event.event_type
            and item.actor == event.actor
            and item.timestamp < event.timestamp
        ]
        if not candidates:
            return []
        previous = max(candidates, key=lambda item: (item.timestamp, item.event_id))
        previous_latitude = previous.attributes.get("latitude")
        previous_longitude = previous.attributes.get("longitude")
        if (
            isinstance(previous_latitude, bool)
            or isinstance(previous_longitude, bool)
            or not isinstance(previous_latitude, (int, float))
            or not isinstance(previous_longitude, (int, float))
            or not math.isfinite(float(previous_latitude))
            or not math.isfinite(float(previous_longitude))
        ):
            return []
        if spec.maximum_speed_kph is None:
            raise RuntimeError("impossible-travel correlation contract is incomplete")
        hours = (event.timestamp - previous.timestamp).total_seconds() / 3600
        distance = ImpossibleTravelDetector._haversine_km(
            float(previous_latitude),
            float(previous_longitude),
            float(latitude),
            float(longitude),
        )
        speed = distance / hours
        if speed <= spec.maximum_speed_kph:
            return []
        return [
            _stateful_alert(
                event,
                spec,
                f"impossible-travel:{event.actor}",
                [
                    f"calculated travel velocity {speed:.0f} km/h",
                    f"distance {distance:.0f} km over {hours:.2f}h",
                ],
            )
        ]

    if event.event_type == "edge_auth_failure":
        if not event.source_ip:
            return []
        if (
            spec.window_minutes is None
            or spec.event_threshold is None
            or spec.distinct_threshold is None
        ):
            raise RuntimeError("credential-stuffing correlation contract is incomplete")
        cutoff = event.timestamp - timedelta(minutes=spec.window_minutes)
        failure_events = [
            item
            for item in history
            if item.event_type == event.event_type
            and item.source_ip == event.source_ip
            and cutoff <= item.timestamp <= event.timestamp
        ]
        distinct_accounts = {item.actor.casefold() for item in failure_events}
        if (
            len(failure_events) < spec.event_threshold
            or len(distinct_accounts) < spec.distinct_threshold
        ):
            return []
        return [
            _stateful_alert(
                event,
                spec,
                f"credential-stuffing:{event.source_ip}",
                [
                    f"{len(failure_events)} failed authentications from {event.source_ip}",
                    f"{len(distinct_accounts)} distinct accounts within {spec.window_minutes}m",
                ],
            )
        ]

    if event.event_type == "edge_session_use":
        if not event.source_ip or spec.window_minutes is None:
            return []
        session_hash = event.attributes.get("session_id_hash")
        if not isinstance(session_hash, str) or len(session_hash) < 12:
            return []
        cutoff = event.timestamp - timedelta(minutes=spec.window_minutes)
        candidates = [
            item
            for item in history
            if item.event_id != event.event_id
            and item.event_type == event.event_type
            and item.attributes.get("session_id_hash") == session_hash
            and cutoff <= item.timestamp < event.timestamp
        ]
        if not candidates:
            return []
        previous = max(candidates, key=lambda item: (item.timestamp, item.event_id))
        if not previous.source_ip or previous.source_ip == event.source_ip:
            return []
        return [
            _stateful_alert(
                event,
                spec,
                f"session-replay:{session_hash}",
                [
                    f"session hash reused from {previous.source_ip} and {event.source_ip}",
                    f"reuse occurred within {spec.window_minutes}m",
                ],
            )
        ]
    return []


class StatefulDetector(Protocol):
    def evaluate(self, event: SecurityEvent) -> Optional[DetectionAlert]:
        """Evaluate one event while retaining bounded detector state."""


class DetectionPipeline:
    def __init__(self, rules: Iterable[SigmaRule]) -> None:
        self._rules = list(rules)
        self._sigma = SigmaSubsetEvaluator()
        bulk = _STATEFUL_BY_EVENT["sensitive_data_access"]
        travel = _STATEFUL_BY_EVENT["authentication_success"]
        stuffing = _STATEFUL_BY_EVENT["edge_auth_failure"]
        replay = _STATEFUL_BY_EVENT["edge_session_use"]
        if (
            bulk.event_threshold is None
            or bulk.byte_threshold is None
            or bulk.window_minutes is None
            or travel.maximum_speed_kph is None
            or stuffing.event_threshold is None
            or stuffing.distinct_threshold is None
            or stuffing.window_minutes is None
            or replay.window_minutes is None
        ):
            raise RuntimeError("stateful correlation contract is incomplete")
        self._stateful: list[StatefulDetector] = [
            BulkAccessDetector(
                event_threshold=bulk.event_threshold,
                byte_threshold=bulk.byte_threshold,
                window=timedelta(minutes=bulk.window_minutes),
            ),
            ImpossibleTravelDetector(maximum_speed_kph=travel.maximum_speed_kph),
            CredentialStuffingDetector(
                failure_threshold=stuffing.event_threshold,
                account_threshold=stuffing.distinct_threshold,
                window=timedelta(minutes=stuffing.window_minutes),
            ),
            SessionReplayDetector(window=timedelta(minutes=replay.window_minutes)),
        ]

    def evaluate(self, event: SecurityEvent) -> list[DetectionAlert]:
        alerts = evaluate_builtin_stateless_event(event)
        alerts.extend(
            [
                alert
                for rule in self._rules
                if (alert := self._sigma.evaluate(rule, event)) is not None
            ]
        )
        alerts.extend(
            alert for detector in self._stateful if (alert := detector.evaluate(event)) is not None
        )
        return alerts

    def evaluate_with_history(
        self,
        event: SecurityEvent,
        prior_events: Iterable[SecurityEvent],
    ) -> list[DetectionAlert]:
        """Evaluate using caller-provided durable correlation history."""

        alerts = evaluate_builtin_stateless_event(event)
        alerts.extend(
            [
                alert
                for rule in self._rules
                if (alert := self._sigma.evaluate(rule, event)) is not None
            ]
        )
        alerts.extend(evaluate_stateful_event(event, prior_events))
        return alerts
