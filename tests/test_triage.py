import json
from datetime import datetime, timezone

import pytest

from controlforge.models import DetectionAlert, Severity
from controlforge.triage import (
    GeminiTriageProvider,
    TriageAssessment,
    TriageError,
    TriageService,
)


class FixtureTransport:
    def __init__(self, assessment: dict[str, object]) -> None:
        text = json.dumps(assessment)
        self.response = json.dumps(
            {"candidates": [{"content": {"parts": [{"text": text}]}}]}
        ).encode()
        self.request_payload = b""

    def post(self, path, headers, payload, timeout_seconds):  # type: ignore[no-untyped-def]
        assert path == "/v1beta/models/gemini-3.5-flash:generateContent"
        assert headers["x-goog-api-key"] == "a" * 32
        assert timeout_seconds == 15.0
        self.request_payload = payload
        return 200, self.response


class FixtureProvider:
    model_name = "fixture-security-model"

    def __init__(self, assessment: TriageAssessment) -> None:
        self.assessment = assessment

    def analyze(self, alert: DetectionAlert) -> TriageAssessment:
        return self.assessment


@pytest.fixture
def alert() -> DetectionAlert:
    return DetectionAlert(
        alert_id="alert-1",
        rule_id="CF-EDGE-002",
        title="Credential stuffing",
        severity=Severity.HIGH,
        event_id="event-1",
        actor="user@example.com",
        reasons=["20 failures from one IP", "12 accounts targeted"],
        tags=["edge-security", "account-takeover"],
        created_at=datetime(2026, 8, 12, 15, 0, tzinfo=timezone.utc),
    )


def test_gemini_triage_uses_structured_output_and_marks_evidence_untrusted(alert) -> None:  # type: ignore[no-untyped-def]
    transport = FixtureTransport(
        {
            "summary": "Pattern warrants analyst review.",
            "confidence": 0.8,
            "evidence_refs": [1, 2],
            "hypotheses": ["Credential-stuffing attempt"],
            "next_steps": ["Review source reputation"],
            "requires_human_review": True,
        }
    )
    assessment = GeminiTriageProvider("a" * 32, transport=transport).analyze(alert)
    request = json.loads(transport.request_payload)

    assert assessment.evidence_refs == [1, 2]
    assert "UNTRUSTED_EVIDENCE" in request["contents"][0]["parts"][0]["text"]
    assert request["generationConfig"]["responseMimeType"] == "application/json"


def test_triage_service_rejects_hallucinated_evidence_reference(alert) -> None:  # type: ignore[no-untyped-def]
    assessment = TriageAssessment(
        summary="Unsupported conclusion",
        confidence=0.5,
        evidence_refs=[3],
        requires_human_review=True,
    )
    with pytest.raises(TriageError, match="outside the supplied alert"):
        TriageService(FixtureProvider(assessment)).triage(alert)


def test_triage_service_requires_human_review(alert) -> None:  # type: ignore[no-untyped-def]
    assessment = TriageAssessment(
        summary="Review this alert",
        confidence=0.7,
        evidence_refs=[1],
        requires_human_review=False,
    )
    with pytest.raises(TriageError, match="bypass human review"):
        TriageService(FixtureProvider(assessment)).triage(alert)
