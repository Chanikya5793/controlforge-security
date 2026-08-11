"""SQLite lifecycle and migration support for a single ControlForge appliance."""

from __future__ import annotations

import os
import sqlite3
import stat
import time
from collections.abc import Iterator
from contextlib import contextmanager
from datetime import datetime, timezone

from .migrations import MIGRATIONS, Migration
from .settings import StandaloneSettings


class StandaloneDatabaseSecurityError(RuntimeError):
    """Raised when the appliance database path is not a trusted private file."""


def _utc_now_text() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="microseconds").replace("+00:00", "Z")


class StandaloneDatabase:
    """Own connections and ordered migrations for local SQLite persistence."""

    def __init__(self, settings: StandaloneSettings) -> None:
        self.settings = settings

    def _open(self) -> sqlite3.Connection:
        self._validate_database_file()
        connection = sqlite3.connect(
            self.settings.database_path,
            timeout=self.settings.busy_timeout_ms / 1_000,
            isolation_level=None,
        )
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA foreign_keys = ON")
        connection.execute(f"PRAGMA busy_timeout = {self.settings.busy_timeout_ms:d}")
        deadline = time.monotonic() + (self.settings.busy_timeout_ms / 1_000)
        while True:
            try:
                connection.execute("PRAGMA journal_mode = WAL")
                break
            except sqlite3.OperationalError as exc:
                if "locked" not in str(exc).casefold() or time.monotonic() >= deadline:
                    connection.close()
                    raise
                time.sleep(0.01)
        connection.execute("PRAGMA synchronous = FULL")
        return connection

    @contextmanager
    def connect(self) -> Iterator[sqlite3.Connection]:
        """Yield a configured connection and always close it."""

        connection = self._open()
        try:
            yield connection
        finally:
            connection.close()

    def initialize(self) -> None:
        """Create the migration ledger and apply every pending migration in order."""

        self._prepare_database_file()
        with self.connect() as connection:
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS schema_migrations (
                    version INTEGER PRIMARY KEY,
                    name TEXT NOT NULL,
                    applied_at TEXT NOT NULL
                )
                """
            )
            for migration in MIGRATIONS:
                self._apply_migration(connection, migration)

    def _prepare_database_file(self) -> None:
        path = self.settings.database_path
        path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        try:
            descriptor = os.open(path, os.O_RDWR | os.O_CREAT | os.O_EXCL, 0o600)
        except FileExistsError:
            descriptor = None
        except OSError as exc:
            raise StandaloneDatabaseSecurityError(
                "standalone database could not be created"
            ) from exc
        if descriptor is not None:
            try:
                os.fsync(descriptor)
            finally:
                os.close(descriptor)
            directory_descriptor = os.open(path.parent, os.O_RDONLY)
            try:
                os.fsync(directory_descriptor)
            finally:
                os.close(directory_descriptor)
        self._validate_database_file()

    def _validate_database_file(self) -> None:
        path = self.settings.database_path
        try:
            metadata = path.lstat()
        except OSError as exc:
            raise StandaloneDatabaseSecurityError(
                "standalone database metadata is unavailable"
            ) from exc
        if not stat.S_ISREG(metadata.st_mode) or path.is_symlink():
            raise StandaloneDatabaseSecurityError("standalone database path is not a regular file")
        if metadata.st_uid != os.geteuid() or stat.S_IMODE(metadata.st_mode) != 0o600:
            raise StandaloneDatabaseSecurityError(
                "standalone database must be owned by the runtime user with mode 0600"
            )

    def _apply_migration(self, connection: sqlite3.Connection, migration: Migration) -> None:
        # The version check belongs inside the write lock so independently started API
        # and worker processes cannot both decide to apply the same migration.
        connection.execute("BEGIN IMMEDIATE")
        try:
            applied = connection.execute(
                "SELECT 1 FROM schema_migrations WHERE version = ?",
                (migration.version,),
            ).fetchone()
            if applied is None:
                for statement in self._migration_statements(migration.sql):
                    connection.execute(statement)
                connection.execute(
                    """
                    INSERT INTO schema_migrations(version, name, applied_at)
                    VALUES (?, ?, ?)
                    """,
                    (migration.version, migration.name, _utc_now_text()),
                )
            connection.execute("COMMIT")
        except (sqlite3.Error, ValueError):
            if connection.in_transaction:
                connection.execute("ROLLBACK")
            raise

    @staticmethod
    def _migration_statements(script: str) -> Iterator[str]:
        """Split a trusted migration while preserving compound trigger statements."""

        pending = ""
        for line in script.splitlines():
            pending += f"{line}\n"
            if sqlite3.complete_statement(pending):
                statement = pending.strip()
                if statement:
                    yield statement
                pending = ""
        if pending.strip():
            raise ValueError("migration contains an incomplete SQL statement")

    def applied_versions(self) -> tuple[int, ...]:
        """Return the ordered schema versions recorded by the appliance."""

        with self.connect() as connection:
            rows = connection.execute(
                "SELECT version FROM schema_migrations ORDER BY version"
            ).fetchall()
        return tuple(int(row["version"]) for row in rows)
