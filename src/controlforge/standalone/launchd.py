"""Root-only launchd supervision for the hardened standalone appliance."""

from __future__ import annotations

import fcntl
import os
import platform
import plistlib
import stat
import subprocess  # nosec B404 -- fixed launchctl boundary only
import sys
import tempfile
from collections.abc import Callable, Iterator, Sequence
from contextlib import contextmanager, suppress
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Optional, Protocol

from .appliance import (
    ApplianceLaunchConfig,
    AppliancePreflightError,
    StandaloneApplianceLifecycle,
)

LAUNCHD_LABEL = "com.controlforge.standalone"
LAUNCHD_DOMAIN_LABEL = f"system/{LAUNCHD_LABEL}"
LAUNCHD_PLIST = Path(f"/Library/LaunchDaemons/{LAUNCHD_LABEL}.plist")
LAUNCHCTL = "/bin/launchctl"


class StandaloneLaunchdError(RuntimeError):
    """A bounded launchd lifecycle error that never contains command output."""


class LaunchdCommandRunner(Protocol):
    def run(
        self,
        arguments: Sequence[str],
        *,
        timeout_seconds: float,
        allow_failure: bool = False,
    ) -> int:
        """Execute one allowlisted launchd operation and return its status."""


class FixedLaunchdRunner:
    """Execute only the exact launchctl commands required by this service."""

    def __init__(self, plist_path: Path = LAUNCHD_PLIST) -> None:
        self._allowed = {
            (LAUNCHCTL, "print", LAUNCHD_DOMAIN_LABEL),
            (LAUNCHCTL, "enable", LAUNCHD_DOMAIN_LABEL),
            (LAUNCHCTL, "bootstrap", "system", str(plist_path)),
            (LAUNCHCTL, "kickstart", "-k", LAUNCHD_DOMAIN_LABEL),
            (LAUNCHCTL, "bootout", LAUNCHD_DOMAIN_LABEL),
            (LAUNCHCTL, "disable", LAUNCHD_DOMAIN_LABEL),
        }

    def run(
        self,
        arguments: Sequence[str],
        *,
        timeout_seconds: float,
        allow_failure: bool = False,
    ) -> int:
        fixed_arguments = tuple(arguments)
        if fixed_arguments not in self._allowed:
            raise ValueError("launchd command is not allowlisted")
        try:
            result = subprocess.run(  # noqa: S603  # nosec B603
                fixed_arguments,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                check=False,
                timeout=timeout_seconds,
            )
        except (OSError, subprocess.TimeoutExpired) as exc:
            raise StandaloneLaunchdError("launchd command failed") from exc
        if result.returncode != 0 and not allow_failure:
            raise StandaloneLaunchdError("launchd command failed")
        return result.returncode


class _LaunchdOperationLock:
    """Serialize launchd mutations without sharing the runtime/restore lock."""

    def __init__(self, appliance_root: Path) -> None:
        self.path = appliance_root / ".launchd-service.lock"

    @contextmanager
    def exclusive(self) -> Iterator[None]:
        try:
            root_metadata = self.path.parent.lstat()
        except OSError as exc:
            raise StandaloneLaunchdError("appliance root is unavailable") from exc
        if (
            self.path.parent.is_symlink()
            or not stat.S_ISDIR(root_metadata.st_mode)
            or root_metadata.st_uid != os.geteuid()
            or stat.S_IMODE(root_metadata.st_mode) != 0o700
        ):
            raise StandaloneLaunchdError("appliance root is not trusted")
        try:
            descriptor = os.open(
                self.path,
                os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW,
                0o600,
            )
        except OSError as exc:
            raise StandaloneLaunchdError("launchd operation lock is unavailable") from exc
        try:
            metadata = os.fstat(descriptor)
            if (
                not stat.S_ISREG(metadata.st_mode)
                or metadata.st_uid != os.geteuid()
                or stat.S_IMODE(metadata.st_mode) != 0o600
            ):
                raise StandaloneLaunchdError("launchd operation lock is unsafe")
            try:
                fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError as exc:
                raise StandaloneLaunchdError(
                    "another launchd lifecycle operation is already running"
                ) from exc
            try:
                yield
            finally:
                fcntl.flock(descriptor, fcntl.LOCK_UN)
        finally:
            os.close(descriptor)


@dataclass(frozen=True)
class LaunchdServiceStatus:
    plist_installed: bool
    configuration_matches: bool
    loaded: bool
    plist_path: str
    appliance_root: str

    def as_dict(self) -> dict[str, object]:
        return asdict(self)


@dataclass(frozen=True)
class LaunchdInstallResult:
    installed_plist: bool
    already_active: bool
    loaded: bool
    plist_path: str
    appliance_root: str
    data_preserved: bool
    bootstrap_token: Optional[str]

    def as_dict(self) -> dict[str, object]:
        """Return status fields only; the console token is deliberately separate."""
        payload = asdict(self)
        payload.pop("bootstrap_token")
        return payload


@dataclass(frozen=True)
class LaunchdUninstallResult:
    removed_plist: bool
    was_loaded: bool
    plist_path: str
    appliance_root: str
    data_preserved: bool

    def as_dict(self) -> dict[str, object]:
        return asdict(self)


class StandaloneLaunchdService:
    """Install and supervise one fixed root-owned launch daemon."""

    def __init__(
        self,
        config: ApplianceLaunchConfig,
        *,
        plist_path: Path = LAUNCHD_PLIST,
        python_executable: Optional[Path] = None,
        runner: Optional[LaunchdCommandRunner] = None,
        system: Callable[[], str] = platform.system,
        euid: Callable[[], int] = os.geteuid,
    ) -> None:
        self.config = config
        self.plist_path = plist_path
        self.python_executable = (python_executable or Path(sys.executable)).expanduser().absolute()
        self._runner = runner or FixedLaunchdRunner(plist_path)
        self._system = system
        self._euid = euid
        self._lifecycle = StandaloneApplianceLifecycle(config)

    def install(self) -> LaunchdInstallResult:
        """Prepare durable state, atomically install the plist, and enable it."""
        self._require_root_macos()
        self._lifecycle.preflight()
        with _LaunchdOperationLock(self._lifecycle.paths.root).exclusive():
            return self._install_locked()

    def _install_locked(self) -> LaunchdInstallResult:
        schema, _ = self._lifecycle.preflight()
        expected = self._plist_bytes()
        before = self._status(expected)
        if before.plist_installed and not before.configuration_matches:
            raise StandaloneLaunchdError(
                "an unexpected standalone launch daemon configuration already exists"
            )
        if before.loaded and not before.plist_installed:
            raise StandaloneLaunchdError(
                "the standalone launch daemon is loaded without its trusted plist"
            )
        if before.loaded:
            if schema.state != "current":
                raise StandaloneLaunchdError(
                    "stop the standalone launch daemon before applying an appliance upgrade"
                )
            return LaunchdInstallResult(
                installed_plist=False,
                already_active=True,
                loaded=True,
                plist_path=str(self.plist_path),
                appliance_root=str(self._lifecycle.paths.root),
                data_preserved=True,
                bootstrap_token=None,
            )

        prepared = self._lifecycle.prepare_runtime(issue_bootstrap_token=True)
        try:
            token = prepared.bootstrap_token
        finally:
            prepared.runtime.close()
        current_schema, _ = self._lifecycle.preflight()
        if current_schema.state != "current":
            raise StandaloneLaunchdError("appliance schema did not reach the supported version")

        created = self._install_exact_plist(expected)
        try:
            self._run((LAUNCHCTL, "enable", LAUNCHD_DOMAIN_LABEL), timeout=5)
            self._run(
                (LAUNCHCTL, "bootstrap", "system", str(self.plist_path)),
                timeout=15,
            )
            self._run(
                (LAUNCHCTL, "kickstart", "-k", LAUNCHD_DOMAIN_LABEL),
                timeout=15,
            )
            if (
                self._run(
                    (LAUNCHCTL, "print", LAUNCHD_DOMAIN_LABEL),
                    timeout=5,
                    allow_failure=True,
                )
                != 0
            ):
                raise StandaloneLaunchdError("launch daemon did not remain loaded")
        except StandaloneLaunchdError as exc:
            rollback_complete = self._rollback_activation()
            bootstrap_revoked = True
            if token is not None:
                try:
                    self._lifecycle.revoke_pending_bootstrap_tokens()
                except AppliancePreflightError:
                    bootstrap_revoked = False
            if created and rollback_complete and bootstrap_revoked:
                self._remove_exact_plist(expected)
            if not rollback_complete or not bootstrap_revoked:
                raise StandaloneLaunchdError(
                    "launch daemon activation failed and rollback requires manual recovery"
                ) from exc
            raise StandaloneLaunchdError(
                "launch daemon activation failed; service changes were rolled back"
            ) from exc

        return LaunchdInstallResult(
            installed_plist=created,
            already_active=False,
            loaded=True,
            plist_path=str(self.plist_path),
            appliance_root=str(self._lifecycle.paths.root),
            data_preserved=True,
            bootstrap_token=token,
        )

    def status(self) -> LaunchdServiceStatus:
        self._require_root_macos()
        return self._status(self._plist_bytes())

    def uninstall(self) -> LaunchdUninstallResult:
        """Remove only service registration; appliance data always remains."""
        self._require_root_macos()
        if self._lifecycle.paths.root.exists():
            with _LaunchdOperationLock(self._lifecycle.paths.root).exclusive():
                return self._uninstall_locked()
        return self._uninstall_locked()

    def _uninstall_locked(self) -> LaunchdUninstallResult:
        expected = self._plist_bytes()
        before = self._status(expected)
        if before.plist_installed and not before.configuration_matches:
            raise StandaloneLaunchdError(
                "refusing to remove an unexpected launch daemon configuration"
            )
        if before.loaded:
            self._run((LAUNCHCTL, "bootout", LAUNCHD_DOMAIN_LABEL), timeout=15)
        self._run(
            (LAUNCHCTL, "disable", LAUNCHD_DOMAIN_LABEL),
            timeout=5,
            allow_failure=True,
        )
        removed = False
        if before.plist_installed:
            self._remove_exact_plist(expected)
            removed = True
        return LaunchdUninstallResult(
            removed_plist=removed,
            was_loaded=before.loaded,
            plist_path=str(self.plist_path),
            appliance_root=str(self._lifecycle.paths.root),
            data_preserved=True,
        )

    def _status(self, expected: bytes) -> LaunchdServiceStatus:
        current = self._read_installed_plist()
        loaded = (
            self._run(
                (LAUNCHCTL, "print", LAUNCHD_DOMAIN_LABEL),
                timeout=5,
                allow_failure=True,
            )
            == 0
        )
        return LaunchdServiceStatus(
            plist_installed=current is not None,
            configuration_matches=current == expected,
            loaded=loaded,
            plist_path=str(self.plist_path),
            appliance_root=str(self._lifecycle.paths.root),
        )

    def _plist_bytes(self) -> bytes:
        self._validate_executable()
        arguments = [
            *self._program_prefix(),
            "serve",
            "--root",
            str(self.config.root.expanduser().absolute()),
            "--rules",
            str(self.config.rules_directory.expanduser().absolute()),
            "--admin-origin",
            self.config.admin_origin,
            "--rp-id",
            self.config.rp_id,
            "--host",
            self.config.host,
            "--port",
            str(self.config.port),
            "--tls-certificate",
            str(self.config.tls_certificate.expanduser().absolute()),
            "--tls-private-key",
            str(self.config.tls_private_key.expanduser().absolute()),
            "--worker-interval-seconds",
            str(self.config.worker_interval_seconds),
            "--backup-retention-count",
            str(self.config.backup_retention_count),
            "--bootstrap-ttl-seconds",
            str(self.config.bootstrap_ttl_seconds),
            "--managed-service",
        ]
        payload = {
            "Disabled": True,
            "KeepAlive": {"SuccessfulExit": False},
            "Label": LAUNCHD_LABEL,
            "ProgramArguments": arguments,
            "RunAtLoad": True,
            "ThrottleInterval": 10,
            "Umask": 0o077,
            "WorkingDirectory": str(self.config.root.expanduser().absolute()),
        }
        return plistlib.dumps(payload, fmt=plistlib.FMT_XML, sort_keys=True)

    def _program_prefix(self) -> list[str]:
        if getattr(sys, "frozen", False):
            return [str(self.python_executable), "standalone-appliance"]
        return [
            str(self.python_executable),
            "-m",
            "controlforge.standalone",
        ]

    def _install_exact_plist(self, expected: bytes) -> bool:
        self._validate_plist_parent()
        current = self._read_installed_plist()
        if current is not None:
            if current != expected:
                raise StandaloneLaunchdError(
                    "an unexpected standalone launch daemon configuration already exists"
                )
            return False
        descriptor = -1
        temporary_path: Optional[Path] = None
        installed_target = False
        try:
            descriptor, temporary_name = tempfile.mkstemp(
                prefix=f".{self.plist_path.name}.",
                dir=self.plist_path.parent,
            )
            temporary_path = Path(temporary_name)
            os.fchmod(descriptor, 0o644)
            with os.fdopen(descriptor, "wb", closefd=True) as stream:
                descriptor = -1
                stream.write(expected)
                stream.flush()
                os.fsync(stream.fileno())
            if os.geteuid() == 0:
                os.chown(temporary_path, 0, 0)
            os.link(temporary_path, self.plist_path, follow_symlinks=False)
            installed_target = True
            temporary_path.unlink()
            temporary_path = None
            _fsync_directory(self.plist_path.parent)
            self._validate_installed_plist()
        except (OSError, StandaloneLaunchdError) as exc:
            if installed_target:
                with suppress(OSError):
                    if self.plist_path.read_bytes() == expected:
                        self.plist_path.unlink()
            raise StandaloneLaunchdError("launch daemon plist installation failed") from exc
        finally:
            if descriptor >= 0:
                os.close(descriptor)
            if temporary_path is not None:
                with suppress(OSError):
                    temporary_path.unlink()
        return True

    def _read_installed_plist(self) -> Optional[bytes]:
        self._validate_plist_parent()
        try:
            metadata = self.plist_path.lstat()
        except FileNotFoundError:
            return None
        except OSError as exc:
            raise StandaloneLaunchdError("launch daemon plist is unavailable") from exc
        if self.plist_path.is_symlink() or not stat.S_ISREG(metadata.st_mode):
            raise StandaloneLaunchdError("launch daemon plist is not a trusted regular file")
        self._validate_installed_plist()
        try:
            content = self.plist_path.read_bytes()
        except OSError as exc:
            raise StandaloneLaunchdError("launch daemon plist is unavailable") from exc
        if len(content) > 32_768:
            raise StandaloneLaunchdError("launch daemon plist is oversized")
        return content

    def _validate_installed_plist(self) -> None:
        metadata = self.plist_path.stat()
        if metadata.st_uid != os.geteuid() or stat.S_IMODE(metadata.st_mode) != 0o644:
            raise StandaloneLaunchdError("launch daemon plist ownership or mode is unsafe")

    def _remove_exact_plist(self, expected: bytes) -> None:
        current = self._read_installed_plist()
        if current != expected:
            raise StandaloneLaunchdError("launch daemon plist changed during the operation")
        try:
            self.plist_path.unlink()
            _fsync_directory(self.plist_path.parent)
        except OSError as exc:
            raise StandaloneLaunchdError("launch daemon plist removal failed") from exc

    def _validate_executable(self) -> None:
        if not self.python_executable.is_absolute():
            raise StandaloneLaunchdError("standalone Python executable must be absolute")
        self._validate_trusted_directory(
            self.python_executable.parent,
            "standalone Python directory",
        )
        try:
            metadata = self.python_executable.lstat()
        except OSError as exc:
            raise StandaloneLaunchdError("standalone Python executable is unavailable") from exc
        candidate = self.python_executable
        if stat.S_ISLNK(metadata.st_mode):
            if metadata.st_uid != os.geteuid():
                raise StandaloneLaunchdError("standalone Python executable is not trusted")
            try:
                candidate = self.python_executable.resolve(strict=True)
            except OSError as exc:
                raise StandaloneLaunchdError("standalone Python executable is unavailable") from exc
            self._validate_trusted_directory(
                candidate.parent,
                "standalone Python target directory",
            )
            metadata = candidate.lstat()
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_uid != os.geteuid()
            or stat.S_IMODE(metadata.st_mode) & 0o022
            or stat.S_IMODE(metadata.st_mode) & 0o111 == 0
        ):
            raise StandaloneLaunchdError("standalone Python executable is not trusted")

    def _validate_plist_parent(self) -> None:
        parent = self.plist_path.parent
        if not self.plist_path.is_absolute():
            raise StandaloneLaunchdError("launch daemon plist path must be absolute")
        self._validate_trusted_directory(parent, "launch daemon directory")

    def _validate_trusted_directory(self, path: Path, label: str) -> None:
        try:
            metadata = path.lstat()
        except OSError as exc:
            raise StandaloneLaunchdError(f"{label} is unavailable") from exc
        if (
            path.is_symlink()
            or not stat.S_ISDIR(metadata.st_mode)
            or metadata.st_uid != os.geteuid()
            or stat.S_IMODE(metadata.st_mode) & 0o022
        ):
            raise StandaloneLaunchdError(f"{label} is not trusted")

    def _rollback_activation(self) -> bool:
        try:
            self._run(
                (LAUNCHCTL, "bootout", LAUNCHD_DOMAIN_LABEL),
                timeout=10,
                allow_failure=True,
            )
            disabled = (
                self._run(
                    (LAUNCHCTL, "disable", LAUNCHD_DOMAIN_LABEL),
                    timeout=10,
                    allow_failure=True,
                )
                == 0
            )
        except StandaloneLaunchdError:
            return False
        try:
            unloaded = (
                self._run(
                    (LAUNCHCTL, "print", LAUNCHD_DOMAIN_LABEL),
                    timeout=5,
                    allow_failure=True,
                )
                != 0
            )
            return disabled and unloaded
        except StandaloneLaunchdError:
            return False

    def _require_root_macos(self) -> None:
        if self._system() != "Darwin":
            raise StandaloneLaunchdError("standalone launchd supervision requires macOS")
        if self._euid() != 0:
            raise StandaloneLaunchdError("standalone launchd supervision requires root")

    def _run(
        self,
        arguments: Sequence[str],
        *,
        timeout: float,
        allow_failure: bool = False,
    ) -> int:
        return self._runner.run(
            arguments,
            timeout_seconds=timeout,
            allow_failure=allow_failure,
        )


def _fsync_directory(path: Path) -> None:
    try:
        descriptor = os.open(path, os.O_RDONLY)
        try:
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
    except OSError as exc:
        raise StandaloneLaunchdError("launch daemon directory sync failed") from exc


__all__ = [
    "LAUNCHCTL",
    "LAUNCHD_DOMAIN_LABEL",
    "LAUNCHD_LABEL",
    "LAUNCHD_PLIST",
    "FixedLaunchdRunner",
    "LaunchdCommandRunner",
    "LaunchdInstallResult",
    "LaunchdServiceStatus",
    "LaunchdUninstallResult",
    "StandaloneLaunchdError",
    "StandaloneLaunchdService",
]
