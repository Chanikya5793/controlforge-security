"""SQLite audit storage for events and alerts."""

from __future__ import annotations

import sqlite3
from pathlib import Path

from .models import DetectionAlert, SecurityEvent


class AuditStore:
    def __init__(self, database_path: Path) -> None:
        self._database_path = database_path
        self._initialize()

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self._database_path)
        connection.row_factory = sqlite3.Row
        return connection

    def _initialize(self) -> None:
        with self._connect() as connection:
            connection.executescript(
                """
                CREATE TABLE IF NOT EXISTS events (
                    event_id TEXT PRIMARY KEY,
                    event_type TEXT NOT NULL,
                    actor TEXT NOT NULL,
                    timestamp TEXT NOT NULL,
                    payload_json TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS alerts (
                    alert_id TEXT PRIMARY KEY,
                    rule_id TEXT NOT NULL,
                    event_id TEXT NOT NULL,
                    actor TEXT NOT NULL,
                    severity TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    payload_json TEXT NOT NULL,
                    FOREIGN KEY(event_id) REFERENCES events(event_id)
                );
                CREATE INDEX IF NOT EXISTS idx_alerts_created_at ON alerts(created_at DESC);
                CREATE INDEX IF NOT EXISTS idx_alerts_actor ON alerts(actor);
                """
            )

    def save_event(self, event: SecurityEvent) -> None:
        with self._connect() as connection:
            connection.execute(
                """
                INSERT OR IGNORE INTO events(event_id, event_type, actor, timestamp, payload_json)
                VALUES (?, ?, ?, ?, ?)
                """,
                (
                    event.event_id,
                    event.event_type,
                    event.actor,
                    event.timestamp.isoformat(),
                    event.model_dump_json(),
                ),
            )

    def save_alerts(self, alerts: list[DetectionAlert]) -> None:
        if not alerts:
            return
        with self._connect() as connection:
            connection.executemany(
                """
                INSERT OR IGNORE INTO alerts(
                    alert_id, rule_id, event_id, actor, severity, created_at, payload_json
                ) VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                [
                    (
                        alert.alert_id,
                        alert.rule_id,
                        alert.event_id,
                        alert.actor,
                        alert.severity.value,
                        alert.created_at.isoformat(),
                        alert.model_dump_json(),
                    )
                    for alert in alerts
                ],
            )

    def recent_alerts(self, limit: int = 100) -> list[DetectionAlert]:
        if limit < 1 or limit > 1000:
            raise ValueError("limit must be between 1 and 1000")
        with self._connect() as connection:
            rows = connection.execute(
                "SELECT payload_json FROM alerts ORDER BY created_at DESC LIMIT ?", (limit,)
            ).fetchall()
        return [DetectionAlert.model_validate_json(row["payload_json"]) for row in rows]
