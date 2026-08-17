"""Encrypted standalone database backup, retention, verification, and restore."""

from __future__ import annotations

import base64
import fcntl
import hashlib
import json
import os
import sqlite3
import stat
import struct
import tempfile
import uuid
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import BinaryIO, Literal, Optional

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from pydantic import BaseModel, ConfigDict, Field, ValidationError, model_validator

from controlforge import __version__

from .database import StandaloneDatabase
from .migrations import MIGRATIONS
from .secrets import StandaloneSecretBundle

_MAGIC = b"CFBACKUP\x01\n"
_LENGTH = struct.Struct(">I")
_TAG_BYTES = 16
_NONCE_BYTES = 12
_SALT_BYTES = 32
_CHUNK_BYTES = 1024 * 1024
_MAX_MANIFEST_BYTES = 64 * 1024
_KEY_CONTEXT = b"controlforge/standalone/database-backup/v1"
_KDF_SALT_CONTEXT = b"controlforge/standalone/backup-hkdf-salt/v1"


class BackupError(RuntimeError):
    """Raised when an encrypted backup cannot be created or trusted."""


class RestoreOfflineError(BackupError):
    """Raised when restore cannot prove exclusive appliance ownership."""


class BackupManifest(BaseModel):
    """Authenticated metadata stored ahead of the encrypted SQLite bytes."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    format: Literal["controlforge-standalone-backup"]
    format_version: Literal[1, 2]
    backup_id: str = Field(pattern=r"^[0-9a-f-]{36}$")
    tenant_id: str = Field(min_length=1, max_length=128)
    tenant_ids: list[str] = Field(default_factory=list, max_length=200)
    created_at: datetime
    application_version: str = Field(min_length=1, max_length=64)
    schema_versions: list[int] = Field(min_length=1, max_length=1_000)
    database_sha256: str = Field(pattern=r"^[a-f0-9]{64}$")
    database_size_bytes: int = Field(ge=1)
    encryption_algorithm: Literal["AES-256-GCM"]
    key_derivation: Literal["HKDF-SHA256"]
    key_context: Literal["controlforge/standalone/database-backup/v1"]
    salt: str = Field(min_length=43, max_length=44)
    nonce: str = Field(min_length=16, max_length=16)

    @model_validator(mode="after")
    def validate_scope(self) -> BackupManifest:
        if self.format_version == 1:
            if self.tenant_ids:
                raise ValueError("legacy backups cannot declare a multi-network scope")
        elif (
            not self.tenant_ids
            or self.tenant_ids != sorted(set(self.tenant_ids))
            or self.tenant_id not in self.tenant_ids
            or any(not value or len(value) > 128 for value in self.tenant_ids)
        ):
            raise ValueError("backup network inventory is invalid")
        return self

    @property
    def network_ids(self) -> tuple[str, ...]:
        return tuple(self.tenant_ids) if self.format_version == 2 else (self.tenant_id,)


@dataclass(frozen=True)
class BackupInventoryEntry:
    backup_id: str
    tenant_id: str
    tenant_ids: tuple[str, ...]
    created_at: datetime
    filename: str
    artifact_sha256: str
    artifact_size_bytes: int
    database_size_bytes: int
    schema_versions: tuple[int, ...]
    verified: bool


@dataclass(frozen=True)
class RestoreResult:
    backup_id: str
    restored_at: datetime
    database_sha256: str
    schema_versions: tuple[int, ...]


class ApplianceOperationLock:
    """Coordinate online runtime readers with an exclusive offline restore."""

    def __init__(self, database_path: Path) -> None:
        self.path = database_path.with_name(f"{database_path.name}.operation.lock")
        self._descriptor: Optional[int] = None

    def acquire_shared(self) -> None:
        self._acquire(fcntl.LOCK_SH, "appliance operation lock is unavailable")

    def acquire_exclusive(self) -> None:
        self._acquire(
            fcntl.LOCK_EX | fcntl.LOCK_NB,
            "standalone runtime must be stopped before restore",
            offline_error=True,
        )

    def _acquire(self, operation: int, message: str, *, offline_error: bool = False) -> None:
        if self._descriptor is not None:
            raise BackupError("appliance operation lock is already held")
        self.path.parent.mkdir(parents=True, exist_ok=True)
        try:
            descriptor = os.open(
                self.path,
                os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW,
                0o600,
            )
        except OSError as exc:
            raise BackupError(message) from exc
        try:
            metadata = os.fstat(descriptor)
            if not stat.S_ISREG(metadata.st_mode):
                raise BackupError("appliance operation lock is not a regular file")
            if metadata.st_uid != os.geteuid() or stat.S_IMODE(metadata.st_mode) != 0o600:
                raise BackupError("appliance operation lock ownership or mode is unsafe")
            try:
                fcntl.flock(descriptor, operation)
            except BlockingIOError as exc:
                if offline_error:
                    raise RestoreOfflineError(message) from exc
                raise BackupError(message) from exc
        except Exception:
            os.close(descriptor)
            raise
        self._descriptor = descriptor

    def release(self) -> None:
        if self._descriptor is None:
            return
        descriptor = self._descriptor
        self._descriptor = None
        try:
            fcntl.flock(descriptor, fcntl.LOCK_UN)
        finally:
            os.close(descriptor)

    @contextmanager
    def shared(self) -> Iterator[None]:
        self.acquire_shared()
        try:
            yield
        finally:
            self.release()

    @contextmanager
    def exclusive(self) -> Iterator[None]:
        self.acquire_exclusive()
        try:
            yield
        finally:
            self.release()


class StandaloneBackupService:
    """Operator-only whole-appliance backup; never a tenant-scoped export."""

    def __init__(
        self,
        database: StandaloneDatabase,
        secret_bundle: StandaloneSecretBundle,
        backup_directory: Path,
        *,
        retention_count: int = 10,
    ) -> None:
        if retention_count < 1 or retention_count > 1_000:
            raise ValueError("backup retention count must be between 1 and 1000")
        self._database = database
        self._source_key = secret_bundle.credential_key
        self._backup_directory = backup_directory
        self._retention_count = retention_count
        self._prepare_backup_directory()

    @property
    def backup_directory(self) -> Path:
        return self._backup_directory

    def _prepare_backup_directory(self) -> None:
        try:
            self._backup_directory.mkdir(mode=0o700, parents=True, exist_ok=True)
            metadata = self._backup_directory.lstat()
        except OSError as exc:
            raise BackupError("backup directory is unavailable") from exc
        if not stat.S_ISDIR(metadata.st_mode) or self._backup_directory.is_symlink():
            raise BackupError("backup path is not a trusted directory")
        if metadata.st_uid != os.geteuid() or stat.S_IMODE(metadata.st_mode) != 0o700:
            raise BackupError("backup directory must be owned by the runtime user with mode 0700")

    def create_backup(
        self,
        tenant_id: Optional[str] = None,
        now: Optional[datetime] = None,
    ) -> BackupInventoryEntry:
        with ApplianceOperationLock(self._database.settings.database_path).shared():
            return self._create_backup(tenant_id, now)

    def _create_backup(
        self, tenant_id: Optional[str], now: Optional[datetime]
    ) -> BackupInventoryEntry:
        created_at = _utc_now() if now is None else _require_utc(now)
        selected_tenant = self._history_tenant_id(tenant_id)
        backup_id = str(uuid.uuid4())
        filename = f"controlforge-{created_at.strftime('%Y%m%dT%H%M%SZ')}-{backup_id}.cfbackup"
        destination = self._backup_directory / filename
        try:
            self._record_started(backup_id, selected_tenant, filename, created_at)
            with tempfile.TemporaryDirectory(
                prefix=".controlforge-snapshot-", dir=self._backup_directory
            ) as temporary_directory:
                snapshot = Path(temporary_directory) / "database.sqlite3"
                self._snapshot_database(snapshot)
                # Scope is taken from the consistent snapshot, not a pre-snapshot
                # live query that can race with owner network creation.
                tenant_ids = self._snapshot_tenant_ids(snapshot)
                if tenant_id is not None and tenant_ids != (tenant_id,):
                    raise BackupError("tenant-scoped export is not supported by appliance backups")
                schema_versions = self._verify_database(
                    snapshot, tenant_ids, history=(backup_id, selected_tenant)
                )
                database_sha256, database_size = _sha256_file(snapshot)
                salt = os.urandom(_SALT_BYTES)
                nonce = os.urandom(_NONCE_BYTES)
                manifest = BackupManifest(
                    format="controlforge-standalone-backup",
                    format_version=2 if len(tenant_ids) > 1 else 1,
                    backup_id=backup_id,
                    tenant_id=selected_tenant,
                    tenant_ids=list(tenant_ids) if len(tenant_ids) > 1 else [],
                    created_at=created_at,
                    application_version=__version__,
                    schema_versions=list(schema_versions),
                    database_sha256=database_sha256,
                    database_size_bytes=database_size,
                    encryption_algorithm="AES-256-GCM",
                    key_derivation="HKDF-SHA256",
                    key_context="controlforge/standalone/database-backup/v1",
                    salt=_base64url(salt),
                    nonce=_base64url(nonce),
                )
                self._encrypt_snapshot(snapshot, destination, manifest, salt, nonce)
            artifact_sha256, artifact_size = _sha256_file(destination)
            self._record_succeeded(
                backup_id,
                artifact_sha256,
                artifact_size,
                created_at,
            )
            self.prune()
            return BackupInventoryEntry(
                backup_id=backup_id,
                tenant_id=selected_tenant,
                tenant_ids=tenant_ids,
                created_at=created_at,
                filename=filename,
                artifact_sha256=artifact_sha256,
                artifact_size_bytes=artifact_size,
                database_size_bytes=database_size,
                schema_versions=schema_versions,
                verified=True,
            )
        except Exception as exc:
            destination.unlink(missing_ok=True)
            self._record_failed(backup_id, _safe_error_code(exc), created_at)
            if isinstance(exc, BackupError):
                raise
            raise BackupError("backup could not be created") from exc

    def verify_backup(self, path: Path) -> BackupInventoryEntry:
        artifact = self._trusted_artifact_path(path)
        with tempfile.TemporaryDirectory(
            prefix=".controlforge-verify-",
            dir=self._backup_directory,
        ) as temporary_directory:
            plaintext = Path(temporary_directory) / "database.sqlite3"
            manifest = self._decrypt_artifact(artifact, plaintext)
            schema_versions = self._verify_database(
                plaintext, manifest.network_ids, history=(manifest.backup_id, manifest.tenant_id)
            )
            if tuple(manifest.schema_versions) != schema_versions:
                raise BackupError("backup schema manifest does not match the database")
        artifact_sha256, artifact_size = _sha256_file(artifact)
        return BackupInventoryEntry(
            backup_id=manifest.backup_id,
            tenant_id=manifest.tenant_id,
            tenant_ids=manifest.network_ids,
            created_at=manifest.created_at,
            filename=artifact.name,
            artifact_sha256=artifact_sha256,
            artifact_size_bytes=artifact_size,
            database_size_bytes=manifest.database_size_bytes,
            schema_versions=schema_versions,
            verified=True,
        )

    def inventory(self, limit: int = 100) -> list[BackupInventoryEntry]:
        if limit < 1 or limit > 1_000:
            raise ValueError("backup inventory limit must be between 1 and 1000")
        entries: list[BackupInventoryEntry] = []
        candidates = sorted(
            self._backup_directory.glob("controlforge-*.cfbackup"),
            key=lambda path: path.name,
            reverse=True,
        )
        for candidate in candidates[:limit]:
            try:
                entries.append(self.verify_backup(candidate))
            except BackupError:
                continue
        return sorted(entries, key=lambda entry: entry.created_at, reverse=True)

    def prune(self, retention_count: Optional[int] = None) -> tuple[str, ...]:
        retain = self._retention_count if retention_count is None else retention_count
        if retain < 1 or retain > 1_000:
            raise ValueError("backup retention count must be between 1 and 1000")
        entries = self.inventory(limit=1_000)
        removed: list[str] = []
        for entry in entries[retain:]:
            artifact = self._trusted_artifact_path(self._backup_directory / entry.filename)
            artifact.unlink()
            removed.append(entry.filename)
        if removed:
            _fsync_directory(self._backup_directory)
        return tuple(removed)

    def restore_backup(
        self,
        path: Path,
        now: Optional[datetime] = None,
    ) -> RestoreResult:
        restored_at = _utc_now() if now is None else _require_utc(now)
        artifact = self._trusted_artifact_path(path)
        target = self._database.settings.database_path
        lock = ApplianceOperationLock(target)
        with lock.exclusive():
            target.parent.mkdir(parents=True, exist_ok=True)
            descriptor, temporary_name = tempfile.mkstemp(
                prefix=f".{target.name}.restore-",
                dir=target.parent,
            )
            os.close(descriptor)
            temporary_path = Path(temporary_name)
            try:
                manifest = self._decrypt_artifact(artifact, temporary_path)
                schema_versions = self._verify_database(
                    temporary_path,
                    manifest.network_ids,
                    history=(manifest.backup_id, manifest.tenant_id),
                )
                if tuple(manifest.schema_versions) != schema_versions:
                    raise BackupError("backup schema manifest does not match the database")
                latest_supported = max(migration.version for migration in MIGRATIONS)
                if max(schema_versions) > latest_supported:
                    raise BackupError("backup schema is newer than this ControlForge version")
                self._validate_restore_tenant(manifest.network_ids)
                self._checkpoint_live_database()
                temporary_path.chmod(0o600)
                os.replace(temporary_path, target)
                _fsync_directory(target.parent)
                restored_versions = self._verify_database(
                    target, manifest.network_ids, history=(manifest.backup_id, manifest.tenant_id)
                )
                if restored_versions != schema_versions:
                    raise BackupError("restored database verification failed")
                self._record_restored(manifest.backup_id, restored_at)
                return RestoreResult(
                    backup_id=manifest.backup_id,
                    restored_at=restored_at,
                    database_sha256=manifest.database_sha256,
                    schema_versions=schema_versions,
                )
            except InvalidTag as exc:
                raise BackupError("backup authentication failed") from exc
            finally:
                temporary_path.unlink(missing_ok=True)

    def _history_tenant_id(self, requested: Optional[str]) -> str:
        with self._database.connect() as connection:
            rows = connection.execute(
                "SELECT tenant_id FROM tenants ORDER BY tenant_id LIMIT 201"
            ).fetchall()
            owner = None
            if connection.execute(
                "SELECT 1 FROM sqlite_master WHERE type='table' AND name='platform_owners'"
            ).fetchone():
                owner = connection.execute("SELECT home_tenant_id FROM platform_owners").fetchone()
        tenant_ids = [str(row["tenant_id"]) for row in rows]
        if not 1 <= len(tenant_ids) <= 200:
            raise BackupError("appliance backup requires between 1 and 200 configured networks")
        if requested is not None and len(tenant_ids) != 1:
            raise BackupError("tenant-scoped export is not supported by appliance backups")
        if requested is not None and requested != tenant_ids[0]:
            raise BackupError("requested tenant does not match the standalone appliance")
        return str(owner[0]) if owner is not None else tenant_ids[0]

    @staticmethod
    def _snapshot_tenant_ids(path: Path) -> tuple[str, ...]:
        try:
            connection = sqlite3.connect(path)
            try:
                connection.execute("PRAGMA query_only = ON")
                rows = connection.execute(
                    "SELECT tenant_id FROM tenants ORDER BY tenant_id LIMIT 201"
                ).fetchall()
            finally:
                connection.close()
        except sqlite3.Error as exc:
            raise BackupError("snapshot network inventory could not be verified") from exc
        if not 1 <= len(rows) <= 200:
            raise BackupError("appliance backup requires between 1 and 200 configured networks")
        return tuple(str(row[0]) for row in rows)

    def _snapshot_database(self, destination: Path) -> None:
        try:
            with self._database.connect() as source:
                target = sqlite3.connect(destination)
                try:
                    source.backup(target)
                finally:
                    target.close()
            destination.chmod(0o600)
        except sqlite3.Error as exc:
            raise BackupError("consistent SQLite snapshot failed") from exc

    def _verify_database(
        self,
        path: Path,
        expected_tenant_ids: tuple[str, ...],
        *,
        history: tuple[str, str],
    ) -> tuple[int, ...]:
        try:
            connection = sqlite3.connect(path)
            try:
                connection.execute("PRAGMA query_only = ON")
                integrity = connection.execute("PRAGMA integrity_check").fetchone()
                if integrity is None or str(integrity[0]).casefold() != "ok":
                    raise BackupError("database integrity verification failed")
                if connection.execute("PRAGMA foreign_key_check").fetchone() is not None:
                    raise BackupError("database foreign-key verification failed")
                rows = connection.execute(
                    "SELECT version FROM schema_migrations ORDER BY version"
                ).fetchall()
                tenant_rows = connection.execute(
                    "SELECT tenant_id FROM tenants ORDER BY tenant_id LIMIT 201"
                ).fetchall()
                history_row = connection.execute(
                    "SELECT tenant_id FROM backup_history WHERE backup_id = ?", (history[0],)
                ).fetchone()
                if history_row is None or str(history_row[0]) != history[1]:
                    raise BackupError("backup history manifest does not match the database")
            finally:
                connection.close()
        except sqlite3.Error as exc:
            raise BackupError("database verification failed") from exc
        versions = tuple(int(row[0]) for row in rows)
        if not versions:
            raise BackupError("database has no schema migration ledger")
        supported_versions = tuple(migration.version for migration in MIGRATIONS)
        if versions != supported_versions[: len(versions)]:
            raise BackupError("database schema migration ledger is unsupported")
        tenant_ids = tuple(str(row[0]) for row in tenant_rows)
        if tenant_ids != expected_tenant_ids:
            raise BackupError("backup tenant manifest does not match the database")
        return versions

    def _validate_restore_tenant(self, expected_tenant_ids: tuple[str, ...]) -> None:
        target = self._database.settings.database_path
        if not target.exists():
            return
        try:
            with self._database.connect() as connection:
                rows = connection.execute(
                    "SELECT tenant_id FROM tenants ORDER BY tenant_id LIMIT 201"
                ).fetchall()
        except sqlite3.Error as exc:
            raise BackupError("live appliance tenant could not be verified") from exc
        tenant_ids = tuple(str(row[0]) for row in rows)
        if tenant_ids and tenant_ids != expected_tenant_ids:
            raise BackupError("backup tenant does not match the live appliance")

    def _encrypt_snapshot(
        self,
        source: Path,
        destination: Path,
        manifest: BackupManifest,
        salt: bytes,
        nonce: bytes,
    ) -> None:
        manifest_bytes = _manifest_bytes(manifest)
        key = _derive_key(self._source_key, salt)
        encryptor = Cipher(algorithms.AES(key), modes.GCM(nonce)).encryptor()
        encryptor.authenticate_additional_data(manifest_bytes)
        descriptor, temporary_name = tempfile.mkstemp(
            prefix=f".{destination.name}.",
            dir=self._backup_directory,
        )
        temporary_path = Path(temporary_name)
        try:
            with os.fdopen(descriptor, "wb") as output, source.open("rb") as plaintext:
                output.write(_MAGIC)
                output.write(_LENGTH.pack(len(manifest_bytes)))
                output.write(manifest_bytes)
                for chunk in iter(lambda: plaintext.read(_CHUNK_BYTES), b""):
                    output.write(encryptor.update(chunk))
                output.write(encryptor.finalize())
                output.write(encryptor.tag)
                output.flush()
                os.fsync(output.fileno())
            temporary_path.chmod(0o600)
            if destination.exists():
                raise BackupError("backup destination already exists")
            os.replace(temporary_path, destination)
            _fsync_directory(self._backup_directory)
        finally:
            temporary_path.unlink(missing_ok=True)

    def _decrypt_artifact(self, artifact: Path, destination: Path) -> BackupManifest:
        with artifact.open("rb") as source:
            manifest, manifest_bytes, ciphertext_start, ciphertext_bytes, tag = (
                self._read_artifact_header(source, artifact.stat().st_size)
            )
            key = _derive_key(self._source_key, _decode_base64url(manifest.salt, _SALT_BYTES))
            nonce = _decode_base64url(manifest.nonce, _NONCE_BYTES)
            decryptor = Cipher(algorithms.AES(key), modes.GCM(nonce, tag)).decryptor()
            decryptor.authenticate_additional_data(manifest_bytes)
            digest = hashlib.sha256()
            written = 0
            source.seek(ciphertext_start)
            remaining = ciphertext_bytes
            with destination.open("wb") as plaintext:
                destination.chmod(0o600)
                while remaining > 0:
                    chunk = source.read(min(_CHUNK_BYTES, remaining))
                    if not chunk:
                        raise BackupError("backup ciphertext is truncated")
                    decoded = decryptor.update(chunk)
                    plaintext.write(decoded)
                    digest.update(decoded)
                    written += len(decoded)
                    remaining -= len(chunk)
                try:
                    final = decryptor.finalize()
                except InvalidTag as exc:
                    raise BackupError("backup authentication failed") from exc
                plaintext.write(final)
                digest.update(final)
                written += len(final)
                plaintext.flush()
                os.fsync(plaintext.fileno())
        if (
            written != manifest.database_size_bytes
            or digest.hexdigest() != manifest.database_sha256
        ):
            raise BackupError("backup database checksum verification failed")
        return manifest

    @staticmethod
    def _read_artifact_header(
        source: BinaryIO,
        artifact_size: int,
    ) -> tuple[BackupManifest, bytes, int, int, bytes]:
        if source.read(len(_MAGIC)) != _MAGIC:
            raise BackupError("backup format is not recognized")
        length_bytes = source.read(_LENGTH.size)
        if len(length_bytes) != _LENGTH.size:
            raise BackupError("backup manifest length is truncated")
        manifest_length = _LENGTH.unpack(length_bytes)[0]
        if manifest_length < 2 or manifest_length > _MAX_MANIFEST_BYTES:
            raise BackupError("backup manifest length is invalid")
        manifest_bytes = source.read(manifest_length)
        if len(manifest_bytes) != manifest_length:
            raise BackupError("backup manifest is truncated")
        try:
            manifest = BackupManifest.model_validate_json(manifest_bytes)
        except ValidationError as exc:
            raise BackupError("backup manifest failed validation") from exc
        ciphertext_start = len(_MAGIC) + _LENGTH.size + manifest_length
        ciphertext_bytes = artifact_size - ciphertext_start - _TAG_BYTES
        if ciphertext_bytes < 1:
            raise BackupError("backup ciphertext is missing")
        source.seek(-_TAG_BYTES, os.SEEK_END)
        tag = source.read(_TAG_BYTES)
        if len(tag) != _TAG_BYTES:
            raise BackupError("backup authentication tag is missing")
        return manifest, manifest_bytes, ciphertext_start, ciphertext_bytes, tag

    def _trusted_artifact_path(self, path: Path) -> Path:
        candidate = path if path.is_absolute() else self._backup_directory / path
        try:
            if candidate.resolve().parent != self._backup_directory.resolve():
                raise BackupError("backup artifact must be inside the configured backup directory")
            metadata = candidate.lstat()
        except FileNotFoundError as exc:
            raise BackupError("backup artifact does not exist") from exc
        if candidate.is_symlink() or not stat.S_ISREG(metadata.st_mode):
            raise BackupError("backup artifact is not a trusted regular file")
        if metadata.st_uid != os.geteuid() or stat.S_IMODE(metadata.st_mode) != 0o600:
            raise BackupError("backup artifact ownership or mode is unsafe")
        if candidate.suffix != ".cfbackup":
            raise BackupError("backup artifact extension is invalid")
        return candidate

    def _checkpoint_live_database(self) -> None:
        target = self._database.settings.database_path
        if not target.exists():
            return
        try:
            with self._database.connect() as connection:
                row = connection.execute("PRAGMA wal_checkpoint(TRUNCATE)").fetchone()
                if row is not None and int(row[0]) != 0:
                    raise RestoreOfflineError("live database could not be checkpointed for restore")
        except sqlite3.Error as exc:
            raise RestoreOfflineError(
                "live database could not be checkpointed for restore"
            ) from exc
        for suffix in ("-wal", "-shm"):
            sidecar = target.with_name(f"{target.name}{suffix}")
            sidecar.unlink(missing_ok=True)

    def _record_started(
        self,
        backup_id: str,
        tenant_id: str,
        destination: str,
        now: datetime,
    ) -> None:
        with self._database.connect() as connection:
            connection.execute(
                """
                INSERT INTO backup_history(
                    backup_id, tenant_id, status, destination, started_at
                ) VALUES (?, ?, 'started', ?, ?)
                """,
                (backup_id, tenant_id, destination, _utc_text(now)),
            )

    def _record_succeeded(
        self,
        backup_id: str,
        sha256: str,
        size_bytes: int,
        now: datetime,
    ) -> None:
        with self._database.connect() as connection:
            connection.execute(
                """
                UPDATE backup_history
                SET status = 'succeeded', sha256 = ?, size_bytes = ?, completed_at = ?
                WHERE backup_id = ? AND status = 'started'
                """,
                (sha256, size_bytes, _utc_text(now), backup_id),
            )

    def _record_failed(self, backup_id: str, error_code: str, now: datetime) -> None:
        try:
            with self._database.connect() as connection:
                connection.execute(
                    """
                    UPDATE backup_history
                    SET status = 'failed', error_summary = ?, completed_at = ?
                    WHERE backup_id = ? AND status = 'started'
                    """,
                    (error_code, _utc_text(now), backup_id),
                )
        except sqlite3.Error:
            return

    def _record_restored(self, backup_id: str, now: datetime) -> None:
        with self._database.connect() as connection:
            cursor = connection.execute(
                """
                UPDATE backup_history SET status = 'restored', completed_at = ?
                WHERE backup_id = ?
                """,
                (_utc_text(now), backup_id),
            )
            if cursor.rowcount != 1:
                raise BackupError("restored database is missing its backup history record")


def _derive_key(source_key: bytes, salt: bytes) -> bytes:
    if len(source_key) != 32:
        raise BackupError("backup source key has an invalid length")
    return HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=hashlib.sha256(_KDF_SALT_CONTEXT + salt).digest(),
        info=_KEY_CONTEXT,
    ).derive(source_key)


def _manifest_bytes(manifest: BackupManifest) -> bytes:
    return json.dumps(
        manifest.model_dump(mode="json", exclude_defaults=True),
        ensure_ascii=True,
        separators=(",", ":"),
        sort_keys=True,
    ).encode()


def _base64url(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode()


def _decode_base64url(value: str, expected_length: int) -> bytes:
    try:
        decoded = base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))
    except (ValueError, UnicodeEncodeError) as exc:
        raise BackupError("backup manifest contains invalid binary metadata") from exc
    if len(decoded) != expected_length:
        raise BackupError("backup manifest contains invalid binary metadata")
    return decoded


def _sha256_file(path: Path) -> tuple[str, int]:
    digest = hashlib.sha256()
    size = 0
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(_CHUNK_BYTES), b""):
            digest.update(chunk)
            size += len(chunk)
    return digest.hexdigest(), size


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


def _require_utc(value: datetime) -> datetime:
    if value.tzinfo is None:
        raise ValueError("backup timestamp must be timezone-aware")
    return value.astimezone(timezone.utc)


def _utc_text(value: datetime) -> str:
    return _require_utc(value).isoformat(timespec="microseconds").replace("+00:00", "Z")


def _safe_error_code(error: Exception) -> str:
    if isinstance(error, RestoreOfflineError):
        return "runtime_online"
    if isinstance(error, BackupError):
        return "backup_validation_failed"
    if isinstance(error, OSError):
        return "filesystem_error"
    return "backup_failed"


def _fsync_directory(directory: Path) -> None:
    descriptor = os.open(directory, os.O_RDONLY)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


__all__ = [
    "ApplianceOperationLock",
    "BackupError",
    "BackupInventoryEntry",
    "BackupManifest",
    "RestoreOfflineError",
    "RestoreResult",
    "StandaloneBackupService",
]
