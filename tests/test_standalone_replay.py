from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path

from controlforge.detections import (
    DetectionPipeline,
    canonical_sigma_rule,
    load_rules,
    sigma_rule_digest,
)
from controlforge.models import SecurityEvent
from controlforge.standalone.database import StandaloneDatabase
from controlforge.standalone.replay import DecisionReplayService
from controlforge.standalone.settings import StandaloneSettings
from controlforge.standalone.store import StandaloneStore
from controlforge.standalone.worker import StandaloneDetectionWorker

NOW = datetime(2026, 8, 22, 21, 0, tzinfo=timezone.utc)
TENANT_ID = "00000000-0000-4000-8000-000000000030"


def test_original_and_current_rule_replay_preserve_provenance(tmp_path: Path) -> None:
    rules = load_rules(Path("rules"))
    rule = next(item for item in rules if item.id == "CF-ENDPOINT-001")
    database = StandaloneDatabase(StandaloneSettings(database_path=tmp_path / "replay.db"))
    database.initialize()
    store = StandaloneStore(database)
    store.create_tenant(TENANT_ID, "replay", "Replay", NOW)
    store.register_device(TENANT_ID, "mac-replay", "Replay Mac", "macos", NOW)
    event = SecurityEvent(
        event_id="replay-event-1",
        event_type="process_start",
        timestamp=NOW,
        actor="device:mac-replay",
        device_id="mac-replay",
        attributes={
            "process_name": "powershell.exe",
            "command_line": "powershell.exe -enc SQBFAFgA",
        },
    )
    store.ingest_event(TENANT_ID, event, NOW)
    snapshot = json.dumps(
        canonical_sigma_rule(rule),
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    )
    worker = StandaloneDetectionWorker(
        store,
        DetectionPipeline([rule]),
        StandaloneSettings(database_path=tmp_path / "replay.db"),
        {rule.id: str(rule.rule_version)},
        "standalone-test-v1",
        rule_digests={rule.id: sigma_rule_digest(rule)},
        rule_snapshots={rule.id: snapshot},
    )

    result = worker.run_once(TENANT_ID, "worker-replay", NOW)

    assert result.alerts_inserted == 1
    with database.connect() as connection:
        alert = connection.execute(
            """
            SELECT alert_id, rule_digest, rule_snapshot_json, fingerprint_version,
                   evidence_json FROM alerts WHERE tenant_id = ?
            """,
            (TENANT_ID,),
        ).fetchone()
    assert alert["rule_digest"] == sigma_rule_digest(rule)
    assert alert["rule_snapshot_json"] == snapshot
    assert alert["fingerprint_version"] == "legacy-local-v0"
    assert "source_event_sha256" in json.loads(alert["evidence_json"])

    original = DecisionReplayService(
        database,
        [rule],
        "standalone-current-v1",
    ).replay(TENANT_ID, alert["alert_id"], "analyst-1", "original", NOW)
    assert original.outcome == "same"
    assert original.matched is True
    assert original.rule_digest == alert["rule_digest"]

    changed_rule = rule.model_copy(update={"title": "Updated encoded PowerShell decision"})
    current = DecisionReplayService(
        database,
        [changed_rule],
        "standalone-current-v2",
    ).replay(TENANT_ID, alert["alert_id"], "analyst-1", "current", NOW)
    assert current.outcome == "changed"
    assert current.matched is True
    assert current.rule_digest != original.rule_digest

    unavailable = DecisionReplayService(
        database,
        [],
        "standalone-current-v3",
    ).replay(TENANT_ID, alert["alert_id"], "analyst-1", "current", NOW)
    assert unavailable.outcome == "unavailable"
    assert unavailable.matched is None
    with database.connect() as connection:
        assert connection.execute("SELECT COUNT(*) FROM detection_replays").fetchone()[0] == 3
