"""Bounded, non-production endurance evidence for one standalone appliance."""

from __future__ import annotations

import json
import time
from dataclasses import asdict, dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Optional

from controlforge import __version__
from controlforge.detections import (
    DetectionPipeline,
    canonical_non_sigma_provenance,
    canonical_sigma_rule,
    load_rules,
    sigma_rule_digest,
)
from controlforge.models import SecurityEvent

from .backup import ApplianceOperationLock, RestoreOfflineError, StandaloneBackupService
from .database import StandaloneDatabase
from .secrets import StandaloneSecretBundle
from .settings import StandaloneSettings
from .store import StandaloneStore
from .worker import StandaloneDetectionWorker

_TENANT_ID = "00000000-0000-4000-8000-00000000e001"
_DEVICE_ID = "endurance-mac-1"
_START = datetime(2026, 8, 24, 0, 0, tzinfo=timezone.utc)


@dataclass(frozen=True)
class EnduranceDatabaseState:
    events: int
    jobs_succeeded: int
    jobs_nonterminal: int
    alerts: int
    active_cases: int
    case_alert_links: int
    integrity: str
    foreign_key_violations: int


@dataclass(frozen=True)
class StandaloneEnduranceReport:
    schema_version: str
    generated_at: str
    application_version: str
    event_count: int
    duplicate_count: int
    batch_size: int
    worker_reconstructed: bool
    online_backup_verified: bool
    live_restore_rejected: bool
    live: EnduranceDatabaseState
    restored_midpoint: EnduranceDatabaseState
    elapsed_seconds: float
    passed: bool

    def as_dict(self) -> dict[str, object]:
        result = asdict(self)
        result["live"] = asdict(self.live)
        result["restored_midpoint"] = asdict(self.restored_midpoint)
        return result


def run_standalone_endurance(
    root: Path,
    rules_directory: Path,
    *,
    event_count: int = 2_000,
    batch_size: int = 100,
    alert_every: int = 50,
    generated_at: Optional[datetime] = None,
) -> StandaloneEnduranceReport:
    """Exercise durable ingestion, restart, aggregation, and backup in isolated state."""

    if event_count < 200 or event_count > 10_000:
        raise ValueError("event_count must be between 200 and 10000")
    if batch_size < 1 or batch_size > 1_000:
        raise ValueError("batch_size must be between 1 and 1000")
    if alert_every < 2 or alert_every > event_count // 2:
        raise ValueError("alert_every must produce at least one alert in each half")
    _prepare_empty_root(root)
    started = time.monotonic()
    midpoint = event_count // 2
    live_database = StandaloneDatabase(
        StandaloneSettings(
            database_path=root / "live.db",
            worker_lease_seconds=30,
            worker_max_attempts=3,
        )
    )
    live_database.initialize()
    secrets = StandaloneSecretBundle.load_or_create(root / "secrets")
    store = StandaloneStore(live_database)
    store.create_tenant(_TENANT_ID, "endurance", "Endurance tenant", _START)
    store.register_device(_TENANT_ID, _DEVICE_ID, "Endurance Mac", "macos", _START)
    worker = _worker(store, live_database.settings, rules_directory)
    runtime_lock = ApplianceOperationLock(live_database.settings.database_path)
    runtime_lock.acquire_shared()
    try:
        first_events = _events(0, midpoint, alert_every)
        first_accepted, first_duplicates = _ingest_with_duplicates(
            store,
            first_events,
            batch_size,
        )
        _drain(worker, store, "endurance-before-restart", event_count)

        backups = StandaloneBackupService(live_database, secrets, root / "backups")
        backup = backups.create_backup(
            _TENANT_ID,
            _START + timedelta(seconds=event_count + 1),
        )
        artifact = backups.backup_directory / backup.filename
        verified = backups.verify_backup(artifact)
        live_restore_rejected = False
        try:
            backups.restore_backup(
                artifact,
                _START + timedelta(seconds=event_count + 2),
            )
        except RestoreOfflineError:
            live_restore_rejected = True

        second_events = _events(midpoint, event_count, alert_every)
        second_accepted, second_duplicates = _ingest_with_duplicates(
            store,
            second_events,
            batch_size,
        )
        reopened_database = StandaloneDatabase(live_database.settings)
        reopened_store = StandaloneStore(reopened_database)
        restarted_worker = _worker(
            reopened_store,
            reopened_database.settings,
            rules_directory,
        )
        _drain(restarted_worker, reopened_store, "endurance-after-restart", event_count)
        live_state = _database_state(reopened_database)
    finally:
        runtime_lock.release()

    restored_database = StandaloneDatabase(
        StandaloneSettings(database_path=root / "restored-midpoint.db")
    )
    restored_backups = StandaloneBackupService(restored_database, secrets, root / "backups")
    restored_backups.restore_backup(
        artifact,
        _START + timedelta(seconds=event_count + 3),
    )
    restored_state = _database_state(restored_database)

    accepted = first_accepted + second_accepted
    duplicates = first_duplicates + second_duplicates
    expected_alerts = event_count // alert_every
    expected_midpoint_alerts = midpoint // alert_every
    passed = (
        accepted == event_count
        and duplicates == event_count
        and verified.artifact_sha256 == backup.artifact_sha256
        and live_restore_rejected
        and live_state
        == EnduranceDatabaseState(
            events=event_count,
            jobs_succeeded=event_count,
            jobs_nonterminal=0,
            alerts=expected_alerts,
            active_cases=1,
            case_alert_links=expected_alerts,
            integrity="ok",
            foreign_key_violations=0,
        )
        and restored_state
        == EnduranceDatabaseState(
            events=midpoint,
            jobs_succeeded=midpoint,
            jobs_nonterminal=0,
            alerts=expected_midpoint_alerts,
            active_cases=1,
            case_alert_links=expected_midpoint_alerts,
            integrity="ok",
            foreign_key_violations=0,
        )
    )
    report_time = generated_at or datetime.now(timezone.utc)
    if report_time.tzinfo is None:
        raise ValueError("generated_at must be timezone-aware")
    return StandaloneEnduranceReport(
        schema_version="controlforge-standalone-endurance.v1",
        generated_at=report_time.astimezone(timezone.utc).isoformat().replace("+00:00", "Z"),
        application_version=__version__,
        event_count=accepted,
        duplicate_count=duplicates,
        batch_size=batch_size,
        worker_reconstructed=True,
        online_backup_verified=verified.verified,
        live_restore_rejected=live_restore_rejected,
        live=live_state,
        restored_midpoint=restored_state,
        elapsed_seconds=round(time.monotonic() - started, 3),
        passed=passed,
    )


def _prepare_empty_root(root: Path) -> None:
    try:
        root.mkdir(mode=0o700, parents=True, exist_ok=True)
        if any(root.iterdir()):
            raise ValueError("endurance work directory must be empty")
        root.chmod(0o700)
    except OSError as exc:
        raise ValueError("endurance work directory is unavailable") from exc


def _events(start: int, stop: int, alert_every: int) -> list[SecurityEvent]:
    return [
        SecurityEvent(
            event_id=f"endurance-event-{index:05d}",
            event_type="endpoint_control_status",
            timestamp=_START + timedelta(seconds=index),
            actor=f"device:{_DEVICE_ID}",
            device_id=_DEVICE_ID,
            attributes={"status": "failed" if (index + 1) % alert_every == 0 else "healthy"},
        )
        for index in range(start, stop)
    ]


def _ingest_with_duplicates(
    store: StandaloneStore,
    events: list[SecurityEvent],
    batch_size: int,
) -> tuple[int, int]:
    accepted = 0
    duplicates = 0
    for offset in range(0, len(events), batch_size):
        batch = events[offset : offset + batch_size]
        received_at = _START + timedelta(hours=1, seconds=offset)
        accepted += sum(
            result.accepted for result in store.ingest_events(_TENANT_ID, batch, received_at)
        )
        duplicates += sum(
            not result.accepted
            for result in store.ingest_events(
                _TENANT_ID,
                batch,
                received_at + timedelta(microseconds=1),
            )
        )
    return accepted, duplicates


def _worker(
    store: StandaloneStore,
    settings: StandaloneSettings,
    rules_directory: Path,
) -> StandaloneDetectionWorker:
    rules = load_rules(rules_directory)
    versions = {rule.id: str(rule.rule_version) for rule in rules}
    digests = {rule.id: sigma_rule_digest(rule) for rule in rules}
    snapshots = {
        rule.id: json.dumps(
            canonical_sigma_rule(rule),
            ensure_ascii=False,
            separators=(",", ":"),
            sort_keys=True,
        )
        for rule in rules
    }
    for rule_id, (version, digest, snapshot) in canonical_non_sigma_provenance().items():
        versions[rule_id] = version
        digests[rule_id] = digest
        snapshots[rule_id] = snapshot
    return StandaloneDetectionWorker(
        store,
        DetectionPipeline(rules),
        settings,
        versions,
        detector_version=f"controlforge-{__version__}-endurance",
        rule_digests=digests,
        rule_snapshots=snapshots,
    )


def _drain(
    worker: StandaloneDetectionWorker,
    store: StandaloneStore,
    worker_id: str,
    event_count: int,
) -> None:
    now = _START + timedelta(hours=2, seconds=event_count)
    cycles = 0
    while True:
        result = worker.run_once(_TENANT_ID, worker_id, now, limit=100)
        cycles += 1
        if result.leased == 0:
            break
        if result.retried or result.dead or cycles > event_count + 1:
            raise RuntimeError("endurance worker did not converge cleanly")
    counts = store.job_counts(_TENANT_ID)
    if counts["pending"] or counts["leased"] or counts["retry"] or counts["dead"]:
        raise RuntimeError("endurance workload retained nonterminal jobs")


def _database_state(database: StandaloneDatabase) -> EnduranceDatabaseState:
    with database.connect() as connection:
        integrity = str(connection.execute("PRAGMA integrity_check").fetchone()[0])
        foreign_keys = len(connection.execute("PRAGMA foreign_key_check").fetchall())
        row = connection.execute(
            """
            SELECT
              (SELECT COUNT(*) FROM events) AS events,
              (SELECT COUNT(*) FROM detection_jobs WHERE status = 'succeeded')
                AS jobs_succeeded,
              (SELECT COUNT(*) FROM detection_jobs WHERE status != 'succeeded')
                AS jobs_nonterminal,
              (SELECT COUNT(*) FROM alerts) AS alerts,
              (SELECT COUNT(*) FROM cases WHERE status != 'closed') AS active_cases,
              (SELECT COUNT(*) FROM case_alerts) AS case_alert_links
            """
        ).fetchone()
    if row is None:
        raise RuntimeError("endurance database state is unavailable")
    return EnduranceDatabaseState(
        events=int(row["events"]),
        jobs_succeeded=int(row["jobs_succeeded"]),
        jobs_nonterminal=int(row["jobs_nonterminal"]),
        alerts=int(row["alerts"]),
        active_cases=int(row["active_cases"]),
        case_alert_links=int(row["case_alert_links"]),
        integrity=integrity,
        foreign_key_violations=foreign_keys,
    )


__all__ = [
    "EnduranceDatabaseState",
    "StandaloneEnduranceReport",
    "run_standalone_endurance",
]
