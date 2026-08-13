"""Bounded operator diagnostics for the standalone appliance."""

from __future__ import annotations

import os
import sqlite3
import stat
from dataclasses import asdict, dataclass
from typing import Literal

from controlforge import __version__

from .backup import BackupError, StandaloneBackupService
from .database import StandaloneDatabase


@dataclass(frozen=True)
class DatabaseDiagnostics:
    exists: bool
    private_mode: bool
    size_bytes: int
    wal_size_bytes: int
    integrity_ok: bool
    foreign_key_violations: int
    schema_versions: tuple[int, ...]


@dataclass(frozen=True)
class WorkloadDiagnostics:
    tenants: int
    devices: int
    events: int
    alerts: int
    cases: int
    pending_jobs: int
    dead_jobs: int


@dataclass(frozen=True)
class BackupDiagnostics:
    verified_backups: int
    invalid_artifacts: int
    latest_verified_at: str | None


@dataclass(frozen=True)
class OperatorDiagnostics:
    status: Literal["healthy", "degraded"]
    application_version: str
    database: DatabaseDiagnostics
    workload: WorkloadDiagnostics
    backups: BackupDiagnostics
    findings: tuple[str, ...]

    def as_dict(self) -> dict[str, object]:
        return asdict(self)


class StandaloneDiagnosticsService:
    """Inspect availability and durability without exposing records or secrets."""

    def __init__(
        self,
        database: StandaloneDatabase,
        backups: StandaloneBackupService,
    ) -> None:
        self._database = database
        self._backups = backups

    def collect(self) -> OperatorDiagnostics:
        findings: list[str] = []
        database_report, workload = self._database_report(findings)
        backup_report = self._backup_report(findings)
        return OperatorDiagnostics(
            status="healthy" if not findings else "degraded",
            application_version=__version__,
            database=database_report,
            workload=workload,
            backups=backup_report,
            findings=tuple(findings),
        )

    def _database_report(
        self,
        findings: list[str],
    ) -> tuple[DatabaseDiagnostics, WorkloadDiagnostics]:
        path = self._database.settings.database_path
        if not path.exists():
            findings.append("database_missing")
            return (
                DatabaseDiagnostics(False, False, 0, 0, False, 0, ()),
                WorkloadDiagnostics(0, 0, 0, 0, 0, 0, 0),
            )
        try:
            metadata = path.lstat()
        except OSError:
            findings.append("database_metadata_unavailable")
            return (
                DatabaseDiagnostics(True, False, 0, 0, False, 0, ()),
                WorkloadDiagnostics(0, 0, 0, 0, 0, 0, 0),
            )
        private_mode = (
            stat.S_ISREG(metadata.st_mode)
            and not path.is_symlink()
            and metadata.st_uid == os.geteuid()
            and stat.S_IMODE(metadata.st_mode) == 0o600
        )
        if not private_mode:
            findings.append("database_permissions_weak")
        wal_path = path.with_name(f"{path.name}-wal")
        wal_size = wal_path.stat().st_size if wal_path.exists() else 0
        integrity_ok = False
        foreign_key_violations = 0
        versions: tuple[int, ...] = ()
        workload = WorkloadDiagnostics(0, 0, 0, 0, 0, 0, 0)
        try:
            with self._database.connect() as connection:
                integrity = connection.execute("PRAGMA integrity_check").fetchone()
                integrity_ok = integrity is not None and str(integrity[0]).casefold() == "ok"
                foreign_key_violations = len(
                    connection.execute("PRAGMA foreign_key_check").fetchmany(1_001)
                )
                versions = tuple(
                    int(row[0])
                    for row in connection.execute(
                        "SELECT version FROM schema_migrations ORDER BY version"
                    ).fetchall()
                )
                counts = connection.execute(
                    """
                    SELECT
                      (SELECT COUNT(*) FROM tenants) AS tenants,
                      (SELECT COUNT(*) FROM devices) AS devices,
                      (SELECT COUNT(*) FROM events) AS events,
                      (SELECT COUNT(*) FROM alerts) AS alerts,
                      (SELECT COUNT(*) FROM cases) AS cases,
                      (SELECT COUNT(*) FROM detection_jobs
                       WHERE status IN ('pending', 'leased', 'retry')) AS pending_jobs,
                      (SELECT COUNT(*) FROM detection_jobs WHERE status = 'dead') AS dead_jobs
                    """
                ).fetchone()
                if counts is not None:
                    workload = WorkloadDiagnostics(
                        tenants=int(counts["tenants"]),
                        devices=int(counts["devices"]),
                        events=int(counts["events"]),
                        alerts=int(counts["alerts"]),
                        cases=int(counts["cases"]),
                        pending_jobs=int(counts["pending_jobs"]),
                        dead_jobs=int(counts["dead_jobs"]),
                    )
        except sqlite3.Error:
            findings.append("database_query_failed")
        if not integrity_ok:
            findings.append("database_integrity_failed")
        if foreign_key_violations:
            findings.append("database_foreign_key_violation")
        if not versions:
            findings.append("database_schema_unknown")
        return (
            DatabaseDiagnostics(
                exists=True,
                private_mode=private_mode,
                size_bytes=metadata.st_size,
                wal_size_bytes=wal_size,
                integrity_ok=integrity_ok,
                foreign_key_violations=min(foreign_key_violations, 1_001),
                schema_versions=versions,
            ),
            workload,
        )

    def _backup_report(self, findings: list[str]) -> BackupDiagnostics:
        backup_directory = self._backups.backup_directory
        artifacts = list(backup_directory.glob("controlforge-*.cfbackup"))
        try:
            entries = self._backups.inventory(limit=1_000)
        except BackupError:
            entries = []
            findings.append("backup_inventory_failed")
        invalid = max(0, len(artifacts) - len(entries))
        if not entries:
            findings.append("backup_missing")
        if invalid:
            findings.append("backup_artifact_invalid")
        latest = entries[0].created_at.isoformat() if entries else None
        return BackupDiagnostics(len(entries), invalid, latest)


__all__ = [
    "BackupDiagnostics",
    "DatabaseDiagnostics",
    "OperatorDiagnostics",
    "StandaloneDiagnosticsService",
    "WorkloadDiagnostics",
]
