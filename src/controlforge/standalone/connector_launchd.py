"""Root-owned launchd supervision for one hash-pinned Cloudflare Tunnel connector."""

from __future__ import annotations

import fcntl
import hashlib
import os
import platform
import plistlib
import stat
import subprocess  # nosec B404 -- fixed, hash-pinned connector and launchctl boundaries
import tempfile
from collections.abc import Callable, Iterator, Sequence
from contextlib import contextmanager, suppress
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Optional, Protocol

CONNECTOR_LABEL = "com.controlforge.cloudflared"
CONNECTOR_DOMAIN_LABEL = f"system/{CONNECTOR_LABEL}"
CONNECTOR_PLIST = Path(f"/Library/LaunchDaemons/{CONNECTOR_LABEL}.plist")
LAUNCHCTL = "/bin/launchctl"
DEFAULT_STDOUT_LOG = Path("/Library/Logs/ControlForge-cloudflared.out.log")
DEFAULT_STDERR_LOG = Path("/Library/Logs/ControlForge-cloudflared.err.log")


class ConnectorLaunchdError(RuntimeError):
    """A bounded connector lifecycle error that never contains command output."""


class ConnectorCommandRunner(Protocol):
    def run(
        self,
        arguments: Sequence[str],
        *,
        timeout_seconds: float,
        allow_failure: bool = False,
    ) -> int:
        """Execute one allowlisted launchd operation and return its status."""


class FixedConnectorRunner:
    """Execute only launchctl operations for the fixed connector label."""

    def __init__(self, plist_path: Path = CONNECTOR_PLIST) -> None:
        self._allowed = {
            (LAUNCHCTL, "print", CONNECTOR_DOMAIN_LABEL),
            (LAUNCHCTL, "enable", CONNECTOR_DOMAIN_LABEL),
            (LAUNCHCTL, "bootstrap", "system", str(plist_path)),
            (LAUNCHCTL, "kickstart", "-k", CONNECTOR_DOMAIN_LABEL),
            (LAUNCHCTL, "bootout", CONNECTOR_DOMAIN_LABEL),
            (LAUNCHCTL, "disable", CONNECTOR_DOMAIN_LABEL),
        }

    def run(
        self,
        arguments: Sequence[str],
        *,
        timeout_seconds: float,
        allow_failure: bool = False,
    ) -> int:
        fixed = tuple(arguments)
        if fixed not in self._allowed:
            raise ValueError("connector launchd command is not allowlisted")
        try:
            result = subprocess.run(  # noqa: S603  # nosec B603
                fixed,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                check=False,
                timeout=timeout_seconds,
            )
        except (OSError, subprocess.TimeoutExpired) as exc:
            raise ConnectorLaunchdError("connector launchd command failed") from exc
        if result.returncode != 0 and not allow_failure:
            raise ConnectorLaunchdError("connector launchd command failed")
        return result.returncode


@dataclass(frozen=True)
class ConnectorLaunchConfig:
    binary: Path
    binary_sha256: str
    config_file: Path
    stdout_log: Path = DEFAULT_STDOUT_LOG
    stderr_log: Path = DEFAULT_STDERR_LOG

    def __post_init__(self) -> None:
        digest = self.binary_sha256.casefold()
        if len(digest) != 64 or any(character not in "0123456789abcdef" for character in digest):
            raise ValueError("connector SHA-256 must contain 64 hexadecimal characters")
        object.__setattr__(self, "binary_sha256", digest)


@dataclass(frozen=True)
class ConnectorServiceStatus:
    plist_installed: bool
    configuration_matches: bool
    loaded: bool
    plist_path: str
    binary_path: str
    config_path: str

    def as_dict(self) -> dict[str, object]:
        return asdict(self)


@dataclass(frozen=True)
class ConnectorInstallResult:
    installed_plist: bool
    already_active: bool
    loaded: bool
    plist_path: str

    def as_dict(self) -> dict[str, object]:
        return asdict(self)


@dataclass(frozen=True)
class ConnectorUninstallResult:
    removed_plist: bool
    was_loaded: bool
    plist_path: str
    config_preserved: bool

    def as_dict(self) -> dict[str, object]:
        return asdict(self)


class _ConnectorOperationLock:
    def __init__(self, config_parent: Path) -> None:
        self.path = config_parent / ".connector-service.lock"

    @contextmanager
    def exclusive(self) -> Iterator[None]:
        _validate_trusted_directory(self.path.parent, "connector configuration directory")
        try:
            descriptor = os.open(self.path, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
        except OSError as exc:
            raise ConnectorLaunchdError("connector operation lock is unavailable") from exc
        try:
            metadata = os.fstat(descriptor)
            if (
                not stat.S_ISREG(metadata.st_mode)
                or metadata.st_uid != os.geteuid()
                or stat.S_IMODE(metadata.st_mode) != 0o600
            ):
                raise ConnectorLaunchdError("connector operation lock is unsafe")
            try:
                fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError as exc:
                raise ConnectorLaunchdError(
                    "another connector lifecycle operation is already running"
                ) from exc
            try:
                yield
            finally:
                fcntl.flock(descriptor, fcntl.LOCK_UN)
        finally:
            os.close(descriptor)


class TunnelConnectorLaunchdService:
    """Install one exact root-owned, hash-pinned Cloudflare Tunnel daemon."""

    def __init__(
        self,
        config: ConnectorLaunchConfig,
        *,
        plist_path: Path = CONNECTOR_PLIST,
        runner: Optional[ConnectorCommandRunner] = None,
        system: Callable[[], str] = platform.system,
        euid: Callable[[], int] = os.geteuid,
        connector_validator: Optional[Callable[[], None]] = None,
    ) -> None:
        self.config = config
        self.plist_path = plist_path
        self._runner = runner or FixedConnectorRunner(plist_path)
        self._system = system
        self._euid = euid
        self._connector_validator = connector_validator or self._validate_with_connector

    def install(self) -> ConnectorInstallResult:
        self._preflight()
        with _ConnectorOperationLock(self.config.config_file.parent).exclusive():
            expected = self._plist_bytes()
            before = self._status(expected)
            if before.plist_installed and not before.configuration_matches:
                raise ConnectorLaunchdError(
                    "an unexpected connector launch daemon configuration already exists"
                )
            if before.loaded and not before.plist_installed:
                raise ConnectorLaunchdError("connector is loaded without its trusted plist")
            if before.loaded:
                return ConnectorInstallResult(False, True, True, str(self.plist_path))
            created = self._install_exact_plist(expected)
            try:
                self._run((LAUNCHCTL, "enable", CONNECTOR_DOMAIN_LABEL), timeout=5)
                self._run((LAUNCHCTL, "bootstrap", "system", str(self.plist_path)), timeout=15)
                self._run((LAUNCHCTL, "kickstart", "-k", CONNECTOR_DOMAIN_LABEL), timeout=15)
                if (
                    self._run(
                        (LAUNCHCTL, "print", CONNECTOR_DOMAIN_LABEL),
                        timeout=5,
                        allow_failure=True,
                    )
                    != 0
                ):
                    raise ConnectorLaunchdError("connector did not remain loaded")
            except ConnectorLaunchdError as exc:
                rolled_back = self._rollback_activation()
                if created and rolled_back:
                    self._remove_exact_plist(expected)
                if not rolled_back:
                    raise ConnectorLaunchdError(
                        "connector activation failed and rollback requires manual recovery"
                    ) from exc
                raise ConnectorLaunchdError(
                    "connector activation failed; service changes were rolled back"
                ) from exc
            return ConnectorInstallResult(created, False, True, str(self.plist_path))

    def status(self) -> ConnectorServiceStatus:
        self._preflight()
        return self._status(self._plist_bytes())

    def uninstall(self) -> ConnectorUninstallResult:
        self._require_root_macos()
        _validate_trusted_directory(
            self.config.config_file.parent, "connector configuration directory"
        )
        with _ConnectorOperationLock(self.config.config_file.parent).exclusive():
            expected = self._plist_bytes()
            before = self._status(expected)
            if before.plist_installed and not before.configuration_matches:
                raise ConnectorLaunchdError(
                    "refusing to remove an unexpected connector launch daemon configuration"
                )
            if before.loaded:
                self._run((LAUNCHCTL, "bootout", CONNECTOR_DOMAIN_LABEL), timeout=15)
            self._run(
                (LAUNCHCTL, "disable", CONNECTOR_DOMAIN_LABEL),
                timeout=5,
                allow_failure=True,
            )
            removed = False
            if before.plist_installed:
                self._remove_exact_plist(expected)
                removed = True
            return ConnectorUninstallResult(
                removed, before.loaded, str(self.plist_path), self.config.config_file.exists()
            )

    def _preflight(self) -> None:
        self._require_root_macos()
        self._validate_binary()
        self._validate_config_file()
        for log in (self.config.stdout_log, self.config.stderr_log):
            if not log.is_absolute():
                raise ConnectorLaunchdError("connector log paths must be absolute")
            _validate_trusted_directory(log.parent, "connector log directory")
        self._connector_validator()

    def _validate_binary(self) -> None:
        path = self.config.binary
        if not path.is_absolute():
            raise ConnectorLaunchdError("connector binary path must be absolute")
        _validate_trusted_directory(path.parent, "connector binary directory")
        try:
            metadata = path.lstat()
        except OSError as exc:
            raise ConnectorLaunchdError("connector binary is unavailable") from exc
        if (
            path.is_symlink()
            or not stat.S_ISREG(metadata.st_mode)
            or metadata.st_uid != os.geteuid()
            or stat.S_IMODE(metadata.st_mode) & 0o022
            or stat.S_IMODE(metadata.st_mode) & 0o111 == 0
            or not 1_024 <= metadata.st_size <= 200_000_000
        ):
            raise ConnectorLaunchdError("connector binary is not trusted")
        digest = hashlib.sha256()
        try:
            with path.open("rb") as stream:
                for chunk in iter(lambda: stream.read(1024 * 1024), b""):
                    digest.update(chunk)
        except OSError as exc:
            raise ConnectorLaunchdError("connector binary could not be verified") from exc
        if digest.hexdigest() != self.config.binary_sha256:
            raise ConnectorLaunchdError("connector binary does not match the pinned SHA-256")

    def _validate_config_file(self) -> None:
        path = self.config.config_file
        if not path.is_absolute():
            raise ConnectorLaunchdError("connector configuration path must be absolute")
        _validate_trusted_directory(path.parent, "connector configuration directory")
        try:
            metadata = path.lstat()
        except OSError as exc:
            raise ConnectorLaunchdError("connector configuration is unavailable") from exc
        if (
            path.is_symlink()
            or not stat.S_ISREG(metadata.st_mode)
            or metadata.st_uid != os.geteuid()
            or stat.S_IMODE(metadata.st_mode) != 0o600
            or not 1 <= metadata.st_size <= 262_144
        ):
            raise ConnectorLaunchdError("connector configuration is not private")

    def _validate_with_connector(self) -> None:
        arguments = (
            str(self.config.binary),
            "tunnel",
            "--config",
            str(self.config.config_file),
            "ingress",
            "validate",
        )
        try:
            result = subprocess.run(  # noqa: S603  # nosec B603
                arguments,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                check=False,
                timeout=10,
            )
        except (OSError, subprocess.TimeoutExpired) as exc:
            raise ConnectorLaunchdError("connector configuration validation failed") from exc
        if result.returncode != 0:
            raise ConnectorLaunchdError("connector configuration validation failed")

    def _plist_bytes(self) -> bytes:
        payload = {
            "KeepAlive": {"SuccessfulExit": False},
            "Label": CONNECTOR_LABEL,
            "ProcessType": "Background",
            "ProgramArguments": [
                str(self.config.binary),
                "tunnel",
                "--config",
                str(self.config.config_file),
                "run",
            ],
            "RunAtLoad": True,
            "StandardErrorPath": str(self.config.stderr_log),
            "StandardOutPath": str(self.config.stdout_log),
            "ThrottleInterval": 10,
            "Umask": 0o077,
        }
        return plistlib.dumps(payload, fmt=plistlib.FMT_XML, sort_keys=True)

    def _status(self, expected: bytes) -> ConnectorServiceStatus:
        current = self._read_installed_plist()
        loaded = (
            self._run(
                (LAUNCHCTL, "print", CONNECTOR_DOMAIN_LABEL),
                timeout=5,
                allow_failure=True,
            )
            == 0
        )
        return ConnectorServiceStatus(
            current is not None,
            current == expected,
            loaded,
            str(self.plist_path),
            str(self.config.binary),
            str(self.config.config_file),
        )

    def _install_exact_plist(self, expected: bytes) -> bool:
        self._validate_plist_parent()
        current = self._read_installed_plist()
        if current is not None:
            if current != expected:
                raise ConnectorLaunchdError(
                    "an unexpected connector launch daemon configuration already exists"
                )
            return False
        descriptor = -1
        temporary_path: Optional[Path] = None
        installed = False
        try:
            descriptor, name = tempfile.mkstemp(
                prefix=f".{self.plist_path.name}.", dir=self.plist_path.parent
            )
            temporary_path = Path(name)
            os.fchmod(descriptor, 0o644)
            with os.fdopen(descriptor, "wb", closefd=True) as stream:
                descriptor = -1
                stream.write(expected)
                stream.flush()
                os.fsync(stream.fileno())
            os.link(temporary_path, self.plist_path, follow_symlinks=False)
            installed = True
            temporary_path.unlink()
            temporary_path = None
            _fsync_directory(self.plist_path.parent)
            self._validate_installed_plist()
        except (OSError, ConnectorLaunchdError) as exc:
            if installed:
                with suppress(OSError):
                    if self.plist_path.read_bytes() == expected:
                        self.plist_path.unlink()
            raise ConnectorLaunchdError("connector plist installation failed") from exc
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
            raise ConnectorLaunchdError("connector plist is unavailable") from exc
        if self.plist_path.is_symlink() or not stat.S_ISREG(metadata.st_mode):
            raise ConnectorLaunchdError("connector plist is not a trusted regular file")
        self._validate_installed_plist()
        content = self.plist_path.read_bytes()
        if len(content) > 32_768:
            raise ConnectorLaunchdError("connector plist is oversized")
        return content

    def _validate_installed_plist(self) -> None:
        metadata = self.plist_path.stat()
        if metadata.st_uid != os.geteuid() or stat.S_IMODE(metadata.st_mode) != 0o644:
            raise ConnectorLaunchdError("connector plist ownership or mode is unsafe")

    def _remove_exact_plist(self, expected: bytes) -> None:
        if self._read_installed_plist() != expected:
            raise ConnectorLaunchdError("connector plist changed during the operation")
        try:
            self.plist_path.unlink()
            _fsync_directory(self.plist_path.parent)
        except OSError as exc:
            raise ConnectorLaunchdError("connector plist removal failed") from exc

    def _validate_plist_parent(self) -> None:
        if not self.plist_path.is_absolute():
            raise ConnectorLaunchdError("connector plist path must be absolute")
        _validate_trusted_directory(self.plist_path.parent, "launch daemon directory")

    def _rollback_activation(self) -> bool:
        try:
            self._run(
                (LAUNCHCTL, "bootout", CONNECTOR_DOMAIN_LABEL),
                timeout=10,
                allow_failure=True,
            )
            disabled = (
                self._run(
                    (LAUNCHCTL, "disable", CONNECTOR_DOMAIN_LABEL),
                    timeout=10,
                    allow_failure=True,
                )
                == 0
            )
            unloaded = (
                self._run(
                    (LAUNCHCTL, "print", CONNECTOR_DOMAIN_LABEL),
                    timeout=5,
                    allow_failure=True,
                )
                != 0
            )
            return disabled and unloaded
        except ConnectorLaunchdError:
            return False

    def _require_root_macos(self) -> None:
        if self._system() != "Darwin":
            raise ConnectorLaunchdError("connector launchd supervision requires macOS")
        if self._euid() != 0:
            raise ConnectorLaunchdError("connector launchd supervision requires root")

    def _run(self, arguments: Sequence[str], *, timeout: float, allow_failure: bool = False) -> int:
        return self._runner.run(arguments, timeout_seconds=timeout, allow_failure=allow_failure)


def _validate_trusted_directory(path: Path, label: str) -> None:
    try:
        metadata = path.lstat()
    except OSError as exc:
        raise ConnectorLaunchdError(f"{label} is unavailable") from exc
    if (
        path.is_symlink()
        or not stat.S_ISDIR(metadata.st_mode)
        or metadata.st_uid != os.geteuid()
        or stat.S_IMODE(metadata.st_mode) & 0o022
    ):
        raise ConnectorLaunchdError(f"{label} is not trusted")


def _fsync_directory(path: Path) -> None:
    try:
        descriptor = os.open(path, os.O_RDONLY)
        try:
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
    except OSError as exc:
        raise ConnectorLaunchdError("connector directory sync failed") from exc


__all__ = [
    "CONNECTOR_DOMAIN_LABEL",
    "CONNECTOR_LABEL",
    "CONNECTOR_PLIST",
    "ConnectorCommandRunner",
    "ConnectorInstallResult",
    "ConnectorLaunchConfig",
    "ConnectorLaunchdError",
    "ConnectorServiceStatus",
    "ConnectorUninstallResult",
    "FixedConnectorRunner",
    "TunnelConnectorLaunchdService",
]
