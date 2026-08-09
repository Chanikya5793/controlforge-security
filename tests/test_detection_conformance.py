from __future__ import annotations

import hashlib
import json
import subprocess
import sys
from pathlib import Path

import pytest
from pydantic import ValidationError

from controlforge.detections import (
    DetectionPipeline,
    SigmaRule,
    alert_fingerprint_v1,
    canonical_builtin_detections,
    canonical_non_sigma_provenance,
    canonical_stateful_correlations,
    evaluate_stateful_event,
    load_rules,
)
from controlforge.models import SecurityEvent


def _load_json(path: Path) -> dict[str, object]:
    loaded = json.loads(path.read_text(encoding="utf-8"))
    assert isinstance(loaded, dict)
    return loaded


def _normalized_timestamp(event: SecurityEvent) -> str:
    return event.timestamp.isoformat().replace("+00:00", "Z")


def test_generated_cloud_rules_are_current(project_root: Path) -> None:
    subprocess.run(  # noqa: S603 -- executable and script are fixed local paths
        [sys.executable, str(project_root / "tools" / "compile_detection_rules.py"), "--check"],
        cwd=project_root,
        check=True,
    )


def test_python_alert_fingerprint_matches_shared_vectors(project_root: Path) -> None:
    fixture = _load_json(
        project_root / "tests" / "fixtures" / "detection_conformance" / "fingerprints.v1.json"
    )
    vectors = fixture["vectors"]
    assert isinstance(vectors, list)
    for vector in vectors:
        assert isinstance(vector, dict)
        assert alert_fingerprint_v1(
            str(vector["tenant_id"]), str(vector["rule_id"]), str(vector["event_id"])
        ) == str(vector["expected_alert_id"])


def test_compiled_builtin_contract_and_python_decision_match(project_root: Path) -> None:
    generated = _load_json(project_root / "cloud" / "src" / "generated" / "rules.v1.json")
    compiled = generated["builtins"]
    assert isinstance(compiled, list)
    assert [
        {key: value for key, value in item.items() if key != "rule_digest"}
        for item in compiled
        if isinstance(item, dict)
    ] == canonical_builtin_detections()
    assert all(
        isinstance(item, dict)
        and isinstance(item.get("rule_digest"), str)
        and str(item["rule_digest"]).startswith("sha256:")
        for item in compiled
    )

    event = SecurityEvent.model_validate(
        {
            "event_id": "control-failed",
            "event_type": "endpoint_control_status",
            "timestamp": "2026-08-22T12:00:00Z",
            "actor": "device:mac-1",
            "target": "microsoft-defender",
            "attributes": {"status": "failed", "installed": False, "running": False},
        }
    )
    alert = DetectionPipeline([]).evaluate(event)
    assert [(item.rule_id, item.title, item.severity.value) for item in alert] == [
        ("CF-CONTROL-001", "Required endpoint security control failed", "high")
    ]
    assert alert[0].reasons == [
        "endpoint control microsoft-defender reported failed",
        "installed=false running=false",
    ]


def test_python_stateless_decisions_match_shared_vectors(project_root: Path) -> None:
    fixture = _load_json(
        project_root / "tests" / "fixtures" / "detection_conformance" / "stateless.v1.json"
    )
    generated = _load_json(project_root / "cloud" / "src" / "generated" / "rules.v1.json")
    correlations = generated["correlations"]
    assert isinstance(correlations, list)
    assert [
        {key: value for key, value in item.items() if key != "rule_digest"}
        for item in correlations
        if isinstance(item, dict)
    ] == canonical_stateful_correlations()
    assert all(
        isinstance(item, dict)
        and isinstance(item.get("rule_digest"), str)
        and str(item["rule_digest"]).startswith("sha256:")
        for item in correlations
    )
    rules = load_rules(project_root / "rules")
    rules_by_id = {rule.id: rule for rule in rules}
    compiled_rules = generated["rules"]
    assert isinstance(compiled_rules, list)
    compiled_by_id = {
        item["id"]: item for item in compiled_rules if isinstance(item, dict) and "id" in item
    }
    expected_rule_metadata = fixture["rules"]
    assert isinstance(expected_rule_metadata, dict)

    actual_rule_metadata = {
        rule.id: {
            "rule_version": rule.rule_version,
            "rule_digest": compiled_by_id[rule.id]["rule_digest"],
            "title": rule.title,
            "severity": rule.level.value,
            "tags": rule.tags,
        }
        for rule in rules
    }
    assert actual_rule_metadata == expected_rule_metadata

    vectors = fixture["vectors"]
    assert isinstance(vectors, list)
    for vector in vectors:
        assert isinstance(vector, dict)
        raw_event = vector["event"]
        expected_rule_ids = vector["expected_rule_ids"]
        assert isinstance(raw_event, dict)
        assert isinstance(expected_rule_ids, list)
        event = SecurityEvent.model_validate(raw_event)
        alerts = DetectionPipeline(rules).evaluate(event)
        actual = [
            {
                "contract_version": "1.0",
                "matched": True,
                "rule_id": alert.rule_id,
                "rule_version": rules_by_id[alert.rule_id].rule_version,
                "rule_digest": compiled_by_id[alert.rule_id]["rule_digest"],
                "title": alert.title,
                "severity": alert.severity.value,
                "event_id": alert.event_id,
                "actor": alert.actor,
                "reasons": alert.reasons,
                "tags": alert.tags,
                "created_at": _normalized_timestamp(event),
            }
            for alert in alerts
        ]
        expected = [
            {
                "contract_version": "1.0",
                "matched": True,
                "rule_id": rule_id,
                **expected_rule_metadata[rule_id],
                "event_id": raw_event["event_id"],
                "actor": raw_event["actor"],
                "reasons": vector["expected_reasons"],
                "created_at": raw_event["timestamp"],
            }
            for rule_id in expected_rule_ids
            if isinstance(rule_id, str)
        ]
        assert actual == expected, vector["id"]


def test_python_stateful_decisions_match_shared_vectors(project_root: Path) -> None:
    fixture = _load_json(
        project_root / "tests" / "fixtures" / "detection_conformance" / "stateful.v1.json"
    )
    provenance = canonical_non_sigma_provenance()
    vectors = fixture["vectors"]
    assert isinstance(vectors, list)
    for vector in vectors:
        assert isinstance(vector, dict)
        raw_event = vector["event"]
        raw_history = vector["prior_events"]
        expected = vector["expected"]
        assert isinstance(raw_event, dict)
        assert isinstance(raw_history, list)
        assert isinstance(expected, dict)
        event = SecurityEvent.model_validate(raw_event)
        history = [SecurityEvent.model_validate(item) for item in raw_history]
        alerts = evaluate_stateful_event(event, history)
        actual = [
            {
                "rule_id": alert.rule_id,
                "rule_version": int(provenance[alert.rule_id][0]),
                "rule_digest": provenance[alert.rule_id][1],
                "title": alert.title,
                "severity": alert.severity.value,
                "reasons": alert.reasons,
                "tags": alert.tags,
            }
            for alert in alerts
        ]
        assert actual == [expected], vector["id"]


def test_rule_model_rejects_unknown_top_level_fields() -> None:
    with pytest.raises(ValidationError, match="Extra inputs are not permitted"):
        SigmaRule.model_validate(
            {
                "id": "TEST-STRICT-001",
                "rule_version": 1,
                "title": "Strict rule",
                "detection": {"selection": {"event_type": "test"}, "condition": "selection"},
                "unexpected": "not allowed",
            }
        )


def test_rule_loader_rejects_case_insensitive_duplicate_ids(tmp_path: Path) -> None:
    template = (
        "id: {rule_id}\n"
        "rule_version: 1\n"
        "title: Duplicate test\n"
        "detection:\n"
        "  selection:\n"
        "    event_type: test\n"
        "  condition: selection\n"
    )
    (tmp_path / "first.yml").write_text(template.format(rule_id="TEST-DUP-001"), encoding="utf-8")
    (tmp_path / "second.yml").write_text(template.format(rule_id="test-dup-001"), encoding="utf-8")

    with pytest.raises(ValueError, match="duplicate rule id"):
        load_rules(tmp_path)


def test_rule_digest_ignores_yaml_formatting() -> None:
    first = SigmaRule(
        id="TEST-DIGEST-001",
        rule_version=1,
        title="Digest test",
        detection={"selection": {"event_type": "test"}, "condition": "selection"},
    )
    second = SigmaRule.model_validate_json(first.model_dump_json(indent=2))
    canonical = json.dumps(
        first.model_dump(mode="json"), ensure_ascii=False, separators=(",", ":"), sort_keys=True
    ).encode()
    second_canonical = json.dumps(
        second.model_dump(mode="json"), ensure_ascii=False, separators=(",", ":"), sort_keys=True
    ).encode()
    assert hashlib.sha256(canonical).digest() == hashlib.sha256(second_canonical).digest()
