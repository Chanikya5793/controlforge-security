"""Fail-closed composition and upgrade lifecycle for one standalone appliance."""

from __future__ import annotations

import ipaddress
import json
import os
import sqlite3
import ssl
import stat
from dataclasses import asdict, dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Literal, Optional
from urllib.parse import urlsplit

from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.x509.oid import ExtendedKeyUsageOID

from controlforge import __version__

from .backup import BackupError, BackupInventoryEntry, RestoreResult, StandaloneBackupService
from .database import StandaloneDatabase
from .diagnostics import StandaloneDiagnosticsService
from .ingress import IngressMode, validate_ingress_listener
from .migrations import MIGRATIONS
from .networks import normalize_domain
from .runtime import StandaloneRuntime, StandaloneRuntimeConfig, build_standalone_runtime
from .secrets import StandaloneSecretBundle
from .settings import StandaloneSettings


class AppliancePreflightError(RuntimeError):
    """Raised before startup when appliance state cannot be trusted."""


TLS_RENEWAL_WARNING = timedelta(days=30)


@dataclass(frozen=True)
class AppliancePaths:
    root: Path
    data_directory: Path
    database: Path
    secrets_directory: Path
    backup_directory: Path

    @classmethod
    def from_root(cls, root: Path) -> AppliancePaths:
        normalized = root.expanduser().absolute()
        return cls(
            root=normalized,
            data_directory=normalized / "data",
            database=normalized / "data" / "controlforge.db",
            secrets_directory=normalized / "secrets",
            backup_directory=normalized / "backups",
        )


@dataclass(frozen=True)
class TlsPreflight:
    hostname: str
    certificate_subject: str
    not_before: str
    not_after: str
    key_algorithm: str
    identity_valid: bool
    days_until_expiry: int
    renewal_status: Literal["valid", "renewal_due"]
    browser_trust_verified: bool = False


@dataclass(frozen=True)
class SchemaPreflight:
    state: Literal["clean_install", "current", "upgrade_required"]
    applied_versions: tuple[int, ...]
    supported_versions: tuple[int, ...]
    tenant_count: int


@dataclass(frozen=True)
class ApplianceStartupReport:
    application_version: str
    schema_state: str
    schema_versions_before: tuple[int, ...]
    schema_versions_after: tuple[int, ...]
    rollback_backup_filename: Optional[str]
    tls: TlsPreflight

    def as_dict(self) -> dict[str, object]:
        return asdict(self)


@dataclass(frozen=True)
class ApplianceLaunchConfig:
    root: Path
    rules_directory: Path
    admin_origin: str
    rp_id: str
    host: str
    port: int
    tls_certificate: Path
    tls_private_key: Path
    worker_interval_seconds: float = 2.0
    backup_retention_count: int = 10
    bootstrap_ttl_seconds: int = 900
    network_base_domain: Optional[str] = None
    ingress_mode: IngressMode = "direct"

    def __post_init__(self) -> None:
        validate_ingress_listener(self.ingress_mode, self.host)
        if self.network_base_domain is not None:
            object.__setattr__(
                self, "network_base_domain", normalize_domain(self.network_base_domain)
            )


@dataclass(frozen=True)
class PreparedAppliance:
    runtime: StandaloneRuntime
    paths: AppliancePaths
    report: ApplianceStartupReport
    bootstrap_token: Optional[str]


class StandaloneApplianceLifecycle:
    """Provision, preflight, migrate, and roll back a single-node appliance."""

    def __init__(self, config: ApplianceLaunchConfig) -> None:
        self.config = config
        self.paths = AppliancePaths.from_root(config.root)

    def preflight(self, now: Optional[datetime] = None) -> tuple[SchemaPreflight, TlsPreflight]:
        checked_at = _utc_now() if now is None else _require_aware(now)
        self._prepare_layout()
        self._validate_rules_directory()
        schema = self._inspect_schema()
        if schema.state != "clean_install":
            StandaloneSecretBundle.load_existing(self.paths.secrets_directory)
        tls = _validate_tls(self.config, checked_at)
        return schema, tls

    def prepare_runtime(
        self,
        now: Optional[datetime] = None,
        *,
        issue_bootstrap_token: bool = True,
    ) -> PreparedAppliance:
        started_at = _utc_now() if now is None else _require_aware(now)
        schema, tls = self.preflight(started_at)
        rollback: Optional[BackupInventoryEntry] = None
        backups: Optional[StandaloneBackupService] = None
        if schema.state == "upgrade_required":
            if not 1 <= schema.tenant_count <= 200:
                raise AppliancePreflightError(
                    "upgrade requires between 1 and 200 configured networks"
                )
            secrets = StandaloneSecretBundle.load_existing(self.paths.secrets_directory)
            backups = StandaloneBackupService(
                _database(self.paths.database),
                secrets,
                self.paths.backup_directory,
                # A mandatory pre-upgrade rollback point must not be pruned by the
                # operator's routine retention window during the same startup.
                retention_count=1_000,
            )
            rollback = backups.create_backup(now=started_at)
        runtime: Optional[StandaloneRuntime] = None
        try:
            runtime = build_standalone_runtime(
                StandaloneRuntimeConfig(
                    settings=StandaloneSettings.from_environment().model_copy(
                        update={
                            "database_path": self.paths.database,
                            "network_base_domain": self.config.network_base_domain,
                            "ingress_mode": self.config.ingress_mode,
                        }
                    ),
                    rules_directory=self.config.rules_directory,
                    secret_directory=self.paths.secrets_directory,
                    admin_origin=self.config.admin_origin,
                    rp_id=self.config.rp_id,
                    worker_interval_seconds=self.config.worker_interval_seconds,
                )
            )
            versions_after = runtime.database.applied_versions()
            supported = tuple(migration.version for migration in MIGRATIONS)
            if versions_after != supported:
                raise AppliancePreflightError("runtime schema did not converge to this release")
            self._record_startup_state(
                runtime,
                schema,
                versions_after,
                rollback.filename if rollback is not None else None,
                started_at,
            )
            token = None
            if issue_bootstrap_token and not runtime.identity.bootstrap_status().configured:
                token = self._rotate_bootstrap_token(runtime, started_at)
            return PreparedAppliance(
                runtime=runtime,
                paths=self.paths,
                report=ApplianceStartupReport(
                    application_version=__version__,
                    schema_state=schema.state,
                    schema_versions_before=schema.applied_versions,
                    schema_versions_after=versions_after,
                    rollback_backup_filename=(rollback.filename if rollback is not None else None),
                    tls=tls,
                ),
                bootstrap_token=token,
            )
        except Exception as exc:
            if runtime is not None:
                runtime.close()
            if rollback is not None and backups is not None:
                try:
                    backups.restore_backup(
                        self.paths.backup_directory / rollback.filename,
                        started_at,
                    )
                except Exception as rollback_exc:
                    raise AppliancePreflightError(
                        "upgrade failed and the encrypted rollback could not be restored"
                    ) from rollback_exc
            if isinstance(exc, AppliancePreflightError):
                raise
            raise AppliancePreflightError("appliance runtime preparation failed") from exc

    def rollback_upgrade(
        self,
        backup_filename: str,
        now: Optional[datetime] = None,
    ) -> RestoreResult:
        restored_at = _utc_now() if now is None else _require_aware(now)
        self._prepare_layout()
        schema = self._inspect_schema()
        if schema.state == "clean_install":
            raise AppliancePreflightError("there is no appliance database to roll back")
        secrets = StandaloneSecretBundle.load_existing(self.paths.secrets_directory)
        backups = StandaloneBackupService(
            _database(self.paths.database),
            secrets,
            self.paths.backup_directory,
            retention_count=self.config.backup_retention_count,
        )
        return backups.restore_backup(Path(backup_filename), restored_at)

    def revoke_pending_bootstrap_tokens(self, now: Optional[datetime] = None) -> int:
        """Invalidate console bootstrap material whose plaintext cannot be delivered."""
        revoked_at = _utc_now() if now is None else _require_aware(now)
        self._prepare_layout()
        schema = self._inspect_schema()
        if schema.state == "clean_install":
            return 0
        try:
            with _database(self.paths.database).connect() as connection:
                cursor = connection.execute(
                    """
                    UPDATE bootstrap_tokens SET revoked_at = ?
                    WHERE used_at IS NULL AND revoked_at IS NULL
                    """,
                    (_utc_text(revoked_at),),
                )
        except (OSError, sqlite3.Error) as exc:
            raise AppliancePreflightError("pending bootstrap tokens could not be revoked") from exc
        return cursor.rowcount

    def health(self, now: Optional[datetime] = None) -> dict[str, object]:
        """Return bounded startup, durability, schema, and TLS health without secrets."""

        checked_at = _utc_now() if now is None else _require_aware(now)
        schema, tls = self.preflight(checked_at)
        if schema.state == "clean_install":
            return {
                "status": "installation_required",
                "application_version": __version__,
                "schema_state": schema.state,
                "tls": asdict(tls),
                "last_startup_status": None,
                "rollback_available": False,
                "diagnostics": None,
            }
        secrets = StandaloneSecretBundle.load_existing(self.paths.secrets_directory)
        database = _database(self.paths.database)
        backups = StandaloneBackupService(
            database,
            secrets,
            self.paths.backup_directory,
            retention_count=self.config.backup_retention_count,
        )
        diagnostics = StandaloneDiagnosticsService(database, backups).collect()
        last_status: Optional[str] = None
        rollback_available = False
        try:
            with database.connect() as connection:
                row = connection.execute(
                    "SELECT value_json FROM appliance_state "
                    "WHERE state_key = 'last_startup_preflight'"
                ).fetchone()
            if row is not None:
                state = json.loads(str(row[0]))
                if isinstance(state, dict) and state.get("status") == "ready":
                    last_status = "ready"
                    rollback_name = state.get("rollback_backup_filename")
                    rollback_available = isinstance(rollback_name, str) and any(
                        entry.filename == rollback_name for entry in backups.inventory(limit=1_000)
                    )
        except (BackupError, json.JSONDecodeError, sqlite3.Error):
            last_status = None
            rollback_available = False
        overall = (
            "healthy"
            if schema.state == "current"
            and diagnostics.status == "healthy"
            and last_status == "ready"
            and tls.renewal_status == "valid"
            else "degraded"
        )
        return {
            "status": overall,
            "application_version": __version__,
            "schema_state": schema.state,
            "schema_versions": schema.applied_versions,
            "tls": asdict(tls),
            "last_startup_status": last_status,
            "rollback_available": rollback_available,
            "diagnostics": diagnostics.as_dict(),
        }

    def _prepare_layout(self) -> None:
        if self.paths.root == Path("/"):
            raise AppliancePreflightError("appliance root cannot be the filesystem root")
        for path in (
            self.paths.root,
            self.paths.data_directory,
            self.paths.secrets_directory,
            self.paths.backup_directory,
        ):
            _prepare_private_directory(path)

    def _validate_rules_directory(self) -> None:
        path = self.config.rules_directory
        try:
            metadata = path.lstat()
        except OSError as exc:
            raise AppliancePreflightError("rule directory is unavailable") from exc
        if (
            path.is_symlink()
            or not stat.S_ISDIR(metadata.st_mode)
            or metadata.st_uid != os.geteuid()
            or stat.S_IMODE(metadata.st_mode) & 0o022
        ):
            raise AppliancePreflightError("rule directory is not a trusted directory")
        rule_paths = sorted(path.glob("*.yml"))
        if not rule_paths:
            raise AppliancePreflightError("rule directory contains no detection rules")
        for rule_path in rule_paths:
            try:
                rule_metadata = rule_path.lstat()
            except OSError as exc:
                raise AppliancePreflightError("detection rule is unavailable") from exc
            if (
                rule_path.is_symlink()
                or not stat.S_ISREG(rule_metadata.st_mode)
                or rule_metadata.st_uid != os.geteuid()
                or stat.S_IMODE(rule_metadata.st_mode) & 0o022
            ):
                raise AppliancePreflightError("detection rule is not a trusted file")

    def _inspect_schema(self) -> SchemaPreflight:
        supported = tuple(migration.version for migration in MIGRATIONS)
        path = self.paths.database
        if not path.exists():
            return SchemaPreflight("clean_install", (), supported, 0)
        _validate_private_file(path, "appliance database")
        try:
            connection = sqlite3.connect(f"{path.resolve().as_uri()}?mode=ro", uri=True)
            try:
                connection.execute("PRAGMA query_only = ON")
                integrity = connection.execute("PRAGMA integrity_check").fetchone()
                if integrity is None or str(integrity[0]).casefold() != "ok":
                    raise AppliancePreflightError("appliance database integrity check failed")
                if connection.execute("PRAGMA foreign_key_check").fetchone() is not None:
                    raise AppliancePreflightError("appliance database foreign keys are invalid")
                ledger = connection.execute(
                    "SELECT version, name FROM schema_migrations ORDER BY version"
                ).fetchall()
                tenant_count = int(connection.execute("SELECT COUNT(*) FROM tenants").fetchone()[0])
            finally:
                connection.close()
        except AppliancePreflightError:
            raise
        except sqlite3.Error as exc:
            raise AppliancePreflightError("appliance schema ledger is unavailable") from exc
        applied = tuple((int(row[0]), str(row[1])) for row in ledger)
        expected = tuple((migration.version, migration.name) for migration in MIGRATIONS)
        if not applied or applied != expected[: len(applied)]:
            raise AppliancePreflightError("appliance schema ledger is unsupported")
        if tenant_count > 200:
            raise AppliancePreflightError("standalone database exceeds the 200-network limit")
        state: Literal["current", "upgrade_required"] = (
            "current" if len(applied) == len(expected) else "upgrade_required"
        )
        return SchemaPreflight(state, tuple(item[0] for item in applied), supported, tenant_count)

    def _record_startup_state(
        self,
        runtime: StandaloneRuntime,
        schema: SchemaPreflight,
        versions_after: tuple[int, ...],
        rollback_filename: Optional[str],
        now: datetime,
    ) -> None:
        value = json.dumps(
            {
                "application_version": __version__,
                "schema_state": schema.state,
                "schema_versions_before": list(schema.applied_versions),
                "schema_versions_after": list(versions_after),
                "rollback_backup_filename": rollback_filename,
                "status": "ready",
            },
            separators=(",", ":"),
            sort_keys=True,
        )
        with runtime.database.connect() as connection:
            connection.execute(
                """
                INSERT INTO appliance_state(state_key, value_json, updated_at)
                VALUES ('last_startup_preflight', ?, ?)
                ON CONFLICT(state_key) DO UPDATE SET
                    value_json = excluded.value_json,
                    updated_at = excluded.updated_at
                """,
                (value, _utc_text(now)),
            )

    def _rotate_bootstrap_token(self, runtime: StandaloneRuntime, now: datetime) -> str:
        with runtime.database.connect() as connection:
            connection.execute(
                """
                UPDATE bootstrap_tokens SET revoked_at = ?
                WHERE used_at IS NULL AND revoked_at IS NULL
                """,
                (_utc_text(now),),
            )
        return runtime.identity.issue_bootstrap_token(
            now,
            ttl_seconds=self.config.bootstrap_ttl_seconds,
        )


def _database(path: Path) -> StandaloneDatabase:
    return StandaloneDatabase(StandaloneSettings(database_path=path))


def _validate_tls(config: ApplianceLaunchConfig, now: datetime) -> TlsPreflight:
    if config.port < 1 or config.port > 65_535:
        raise AppliancePreflightError("standalone TLS port is invalid")
    origin = urlsplit(config.admin_origin)
    if (
        origin.scheme != "https"
        or origin.hostname is None
        or origin.username is not None
        or origin.password is not None
        or origin.query
        or origin.fragment
        or origin.path not in {"", "/"}
    ):
        raise AppliancePreflightError("administrator origin must be one exact HTTPS origin")
    hostname = origin.hostname.casefold().rstrip(".")
    expected_port = origin.port or 443
    if config.ingress_mode == "cloudflare-tunnel":
        if expected_port != 443:
            raise AppliancePreflightError(
                "Cloudflare Tunnel administrator origin must use public HTTPS port 443"
            )
    elif expected_port != config.port:
        raise AppliancePreflightError("administrator origin port does not match the listener")
    if config.rp_id.casefold().rstrip(".") != hostname:
        raise AppliancePreflightError("WebAuthn RP ID must exactly match the administrator host")
    certificate_path = config.tls_certificate.expanduser().absolute()
    private_key_path = config.tls_private_key.expanduser().absolute()
    _validate_regular_file(certificate_path, "TLS certificate")
    _validate_private_file(private_key_path, "TLS private key")
    for path, label in (
        (certificate_path, "TLS certificate"),
        (private_key_path, "TLS private key"),
    ):
        if path.stat().st_size < 1 or path.stat().st_size > 1_048_576:
            raise AppliancePreflightError(f"{label} size is invalid")
    try:
        certificate = x509.load_pem_x509_certificate(certificate_path.read_bytes())
        private_key = serialization.load_pem_private_key(private_key_path.read_bytes(), None)
    except (OSError, ValueError, TypeError) as exc:
        raise AppliancePreflightError("TLS certificate or private key is invalid") from exc
    not_before = _certificate_time(certificate, "not_valid_before_utc", "not_valid_before")
    not_after = _certificate_time(certificate, "not_valid_after_utc", "not_valid_after")
    if now < not_before or now >= not_after:
        raise AppliancePreflightError("TLS certificate is not currently valid")
    if not _certificate_matches(certificate, hostname):
        raise AppliancePreflightError("TLS certificate does not match the administrator host")
    try:
        usage = certificate.extensions.get_extension_for_class(x509.ExtendedKeyUsage).value
        if ExtendedKeyUsageOID.SERVER_AUTH not in usage:
            raise AppliancePreflightError("TLS certificate is not valid for server authentication")
    except x509.ExtensionNotFound:
        pass
    certificate_key = certificate.public_key().public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    private_public_key = private_key.public_key().public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    if certificate_key != private_public_key:
        raise AppliancePreflightError("TLS private key does not match the certificate")
    key_algorithm = _key_algorithm(private_key)
    try:
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        context.load_cert_chain(str(certificate_path), str(private_key_path))
    except (OSError, ssl.SSLError) as exc:
        raise AppliancePreflightError("TLS material cannot be loaded by the server") from exc
    return TlsPreflight(
        hostname=hostname,
        certificate_subject=certificate.subject.rfc4514_string(),
        not_before=not_before.isoformat(),
        not_after=not_after.isoformat(),
        key_algorithm=key_algorithm,
        identity_valid=True,
        days_until_expiry=max(0, int((not_after - now).total_seconds() // 86_400)),
        renewal_status=("renewal_due" if not_after - now <= TLS_RENEWAL_WARNING else "valid"),
    )


def _certificate_matches(certificate: x509.Certificate, hostname: str) -> bool:
    try:
        alternatives = certificate.extensions.get_extension_for_class(
            x509.SubjectAlternativeName
        ).value
    except x509.ExtensionNotFound:
        return False
    try:
        expected_ip = ipaddress.ip_address(hostname)
    except ValueError:
        return hostname in {
            item.casefold().rstrip(".") for item in alternatives.get_values_for_type(x509.DNSName)
        }
    return expected_ip in alternatives.get_values_for_type(x509.IPAddress)


def _certificate_time(
    certificate: x509.Certificate,
    aware_name: str,
    legacy_name: str,
) -> datetime:
    aware = getattr(certificate, aware_name, None)
    if isinstance(aware, datetime):
        return aware.astimezone(timezone.utc)
    legacy = getattr(certificate, legacy_name)
    if not isinstance(legacy, datetime):
        raise AppliancePreflightError("TLS certificate validity is unavailable")
    return legacy.replace(tzinfo=timezone.utc)


def _key_algorithm(private_key: object) -> str:
    if isinstance(private_key, rsa.RSAPrivateKey):
        if private_key.key_size < 2_048:
            raise AppliancePreflightError("TLS RSA private key is too small")
        return f"RSA-{private_key.key_size}"
    if isinstance(private_key, ec.EllipticCurvePrivateKey):
        if private_key.key_size < 256:
            raise AppliancePreflightError("TLS elliptic-curve private key is too small")
        return f"EC-{private_key.curve.name}"
    raise AppliancePreflightError("TLS private key algorithm is unsupported")


def _prepare_private_directory(path: Path) -> None:
    try:
        created = not path.exists()
        path.mkdir(mode=0o700, parents=True, exist_ok=True)
        if created:
            path.chmod(0o700)
        metadata = path.lstat()
    except OSError as exc:
        raise AppliancePreflightError("appliance directory is unavailable") from exc
    if path.is_symlink() or not stat.S_ISDIR(metadata.st_mode):
        raise AppliancePreflightError("appliance path is not a trusted directory")
    if metadata.st_uid != os.geteuid() or stat.S_IMODE(metadata.st_mode) != 0o700:
        raise AppliancePreflightError(
            "appliance directories must be owned by the runtime user with mode 0700"
        )


def _validate_regular_file(path: Path, label: str) -> None:
    try:
        metadata = path.lstat()
    except OSError as exc:
        raise AppliancePreflightError(f"{label} is unavailable") from exc
    if path.is_symlink() or not stat.S_ISREG(metadata.st_mode):
        raise AppliancePreflightError(f"{label} is not a trusted regular file")
    if metadata.st_uid != os.geteuid():
        raise AppliancePreflightError(f"{label} is not owned by the runtime user")


def _validate_private_file(path: Path, label: str) -> None:
    _validate_regular_file(path, label)
    metadata = path.stat()
    if stat.S_IMODE(metadata.st_mode) != 0o600:
        raise AppliancePreflightError(f"{label} must use mode 0600")


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


def _require_aware(value: datetime) -> datetime:
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError("appliance lifecycle timestamps must be timezone-aware")
    return value.astimezone(timezone.utc)


def _utc_text(value: datetime) -> str:
    return _require_aware(value).isoformat(timespec="microseconds").replace("+00:00", "Z")


__all__ = [
    "TLS_RENEWAL_WARNING",
    "ApplianceLaunchConfig",
    "AppliancePaths",
    "AppliancePreflightError",
    "ApplianceStartupReport",
    "PreparedAppliance",
    "SchemaPreflight",
    "StandaloneApplianceLifecycle",
    "TlsPreflight",
]
