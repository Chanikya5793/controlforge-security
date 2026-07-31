"""Sigma-style stateless and stateful security-event detections."""

from __future__ import annotations

import fnmatch
import hashlib
import ipaddress
import math
import re
from collections import defaultdict, deque
from collections.abc import Iterable, Mapping, Sequence
from datetime import datetime, timedelta
from pathlib import Path
from typing import ClassVar, Optional, Protocol

import yaml
from pydantic import BaseModel, Field

from .models import DetectionAlert, SecurityEvent, Severity


class SigmaRule(BaseModel):
    id: str = Field(min_length=1)
    title: str = Field(min_length=1)
    description: str = ""
    status: str = "experimental"
    logsource: dict[str, str] = Field(default_factory=dict)
    detection: dict[str, object]
    level: Severity = Severity.MEDIUM
    tags: list[str] = Field(default_factory=list)


def load_rules(directory: Path) -> list[SigmaRule]:
    """Load and validate all YAML detection rules in deterministic order."""

    rules: list[SigmaRule] = []
    for path in sorted([*directory.glob("*.yml"), *directory.glob("*.yaml")]):
        raw = yaml.safe_load(path.read_text(encoding="utf-8"))
        if not isinstance(raw, dict):
            raise ValueError(f"{path}: rule must be a YAML mapping")
        rules.append(SigmaRule.model_validate(raw))
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
        normalized = condition.strip()
        or_parts = normalized.split(" or ")
        if len(or_parts) > 1:
            results = [self._evaluate_condition(part, selections, event) for part in or_parts]
            for matched, reasons in results:
                if matched:
                    return True, reasons
            return False, []

        and_parts = normalized.split(" and ")
        if len(and_parts) > 1 and " and not " not in normalized:
            results = [self._evaluate_condition(part, selections, event) for part in and_parts]
            if not all(result[0] for result in results):
                return False, []
            return True, [reason for result in results for reason in result[1]]

        one_of_match = re.fullmatch(r"1 of ([a-zA-Z0-9_*?-]+)", normalized)
        if one_of_match:
            pattern = one_of_match.group(1)
            candidates = [name for name in selections if fnmatch.fnmatch(name, pattern)]
            return self._evaluate_any(candidates, selections, event)

        all_of_match = re.fullmatch(r"all of ([a-zA-Z0-9_*?-]+)", normalized)
        if all_of_match:
            pattern = all_of_match.group(1)
            candidates = [name for name in selections if fnmatch.fnmatch(name, pattern)]
            return self._evaluate_all(candidates, selections, event)

        and_not = normalized.split(" and not ")
        if len(and_not) == 2:
            positive, positive_reasons = self._evaluate_named(and_not[0], selections, event)
            negative, _ = self._evaluate_named(and_not[1], selections, event)
            return positive and not negative, positive_reasons if positive and not negative else []

        return self._evaluate_named(normalized, selections, event)

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
        rendered = str(expected)
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
        if not isinstance(raw_bytes, (int, float)):
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
        return DetectionAlert(
            alert_id=hashlib.sha256(fingerprint).hexdigest()[:20],
            rule_id="CF-INSIDER-001",
            title="Unusual sensitive-data access volume",
            severity=Severity.HIGH,
            event_id=event.event_id,
            actor=event.actor,
            reasons=[
                f"{len(history)} access events within {int(self._window.total_seconds() / 60)}m",
                f"{total_bytes} bytes accessed",
            ],
            tags=["insider-risk", "financial-data", "behavioral-analytics"],
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
        if not isinstance(latitude, (int, float)) or not isinstance(longitude, (int, float)):
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
        return DetectionAlert(
            alert_id=hashlib.sha256(fingerprint).hexdigest()[:20],
            rule_id="CF-IDENTITY-001",
            title="Impossible-travel authentication",
            severity=Severity.HIGH,
            event_id=event.event_id,
            actor=event.actor,
            reasons=[
                f"calculated travel velocity {speed:.0f} km/h",
                f"distance {distance:.0f} km over {hours:.2f}h",
            ],
            tags=["identity", "account-takeover", "behavioral-analytics"],
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


class StatefulDetector(Protocol):
    def evaluate(self, event: SecurityEvent) -> Optional[DetectionAlert]:
        """Evaluate one event while retaining bounded detector state."""


class DetectionPipeline:
    def __init__(self, rules: Iterable[SigmaRule]) -> None:
        self._rules = list(rules)
        self._sigma = SigmaSubsetEvaluator()
        self._stateful: list[StatefulDetector] = [
            BulkAccessDetector(),
            ImpossibleTravelDetector(),
        ]

    def evaluate(self, event: SecurityEvent) -> list[DetectionAlert]:
        alerts = [
            alert
            for rule in self._rules
            if (alert := self._sigma.evaluate(rule, event)) is not None
        ]
        alerts.extend(
            alert for detector in self._stateful if (alert := detector.evaluate(event)) is not None
        )
        return alerts
