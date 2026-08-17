"""Fail-closed activation of the installed macOS endpoint package."""

from __future__ import annotations

import os
import platform
import plistlib
import shutil
import stat
import subprocess  # nosec B404 -- fixed package and launchctl boundaries only
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Literal, Optional, Protocol

from .collector_agent import (
    CollectorDefinition,
    MacOSSystemKeychain,
    load_collector_definition,
)
from .macos_acceptance import PACKAGED_RULE_NAMES
from .macos_response import (
    MacOSContainmentStatus,
    MacOSPfResponseAdapter,
    MacOSResponseError,
    MacOSResponseResult,
)

COLLECTOR_BINARY = Path("/Library/ControlForge/bin/controlforge")
COLLECTOR_RUNTIME = Path("/Library/ControlForge/bin/controlforge-runtime")
COLLECTOR_CONFIG = Path("/Library/Application Support/ControlForge/collector.yml")
LAUNCHD_PLIST = Path("/Library/LaunchDaemons/com.controlforge.agent.plist")
COLLECTOR_DEFAULT_CONFIG = Path("/Library/Application Support/ControlForge/collector.default.yml")
CONTROLS_CONFIG = Path("/Library/Application Support/ControlForge/agents.yml")
COLLECTOR_SPOOL = Path("/Library/Application Support/ControlForge/controlforge-agent-spool.db")
STATUS_SNAPSHOT = Path("/Library/ControlForge/status/agent-status.json")
RESPONSE_STATE = Path("/Library/Application Support/ControlForge/response/pf-state.json")
RULES_DIRECTORY = Path("/Library/ControlForge/rules")
USER_APP = Path("/Applications/ControlForge.app")
COLLECTOR_LOG = Path("/var/log/controlforge-agent.log")
COLLECTOR_ERROR_LOG = Path("/var/log/controlforge-agent-error.log")
LAUNCHCTL = "/bin/launchctl"
CODESIGN = "/usr/bin/codesign"
PKGUTIL = "/usr/sbin/pkgutil"
LAUNCHD_LABEL = "system/com.controlforge.agent"
PACKAGE_IDENTIFIER = "com.controlforge.agent"
KEYCHAIN_SERVICE = "com.controlforge.collector.v2"
UNINSTALL_CONFIRMATION = "UNINSTALL-CONTROLFORGE"
RELEASE_CONTAINMENT_CONFIRMATION = "RELEASE-CONTROLFORGE-CONTAINMENT"


class MacOSEndpointLifecycleError(RuntimeError):
    """A bounded local activation failure with no provider or credential output."""


class LifecycleCommandRunner(Protocol):
    def run(
        self,
        arguments: Sequence[str],
        *,
        timeout_seconds: float,
        allow_failure: bool = False,
    ) -> int:
        """Run one allowlisted lifecycle command without a shell."""


class ContainmentRecoveryAdapter(Protocol):
    def containment_status(self) -> MacOSContainmentStatus:
        """Return a redacted local containment state."""

    def release_owned_state_for_recovery(self) -> MacOSResponseResult:
        """Release only ControlForge-owned PF state."""


class FixedMacOSLifecycleRunner:
    """Execute only the package verification, first-run, and launchctl command set."""

    def __init__(
        self,
        *,
        collector_binary: Path = COLLECTOR_BINARY,
        collector_runtime: Path = COLLECTOR_RUNTIME,
        collector_config: Path = COLLECTOR_CONFIG,
        launchd_plist: Path = LAUNCHD_PLIST,
        pkgutil: str = PKGUTIL,
    ) -> None:
        self._collector_binary = str(collector_binary)
        self._collector_runtime = str(collector_runtime)
        self._collector_config = str(collector_config)
        self._launchd_plist = str(launchd_plist)
        self._pkgutil = pkgutil

    def _allowed(self, arguments: tuple[str, ...]) -> bool:
        return arguments in {
            (CODESIGN, "--verify", "--strict", self._collector_binary),
            (CODESIGN, "--verify", "--strict", self._collector_runtime),
            (
                self._collector_binary,
                "agent",
                "--config",
                self._collector_config,
            ),
            (LAUNCHCTL, "print", LAUNCHD_LABEL),
            (LAUNCHCTL, "enable", LAUNCHD_LABEL),
            (LAUNCHCTL, "bootstrap", "system", self._launchd_plist),
            (LAUNCHCTL, "kickstart", "-k", LAUNCHD_LABEL),
            (LAUNCHCTL, "bootout", LAUNCHD_LABEL),
            (LAUNCHCTL, "disable", LAUNCHD_LABEL),
            (self._collector_binary, "keychain-delete-all"),
            (self._pkgutil, "--forget", PACKAGE_IDENTIFIER),
        }

    def run(
        self,
        arguments: Sequence[str],
        *,
        timeout_seconds: float,
        allow_failure: bool = False,
    ) -> int:
        fixed_arguments = tuple(arguments)
        if not self._allowed(fixed_arguments):
            raise ValueError("macOS lifecycle command is not allowlisted")
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
            raise MacOSEndpointLifecycleError("macOS lifecycle command failed") from exc
        if result.returncode != 0 and not allow_failure:
            raise MacOSEndpointLifecycleError("macOS lifecycle command failed")
        return result.returncode


@dataclass(frozen=True)
class MacOSEndpointActivationResult:
    device_id: str
    first_check_in_verified: bool
    launch_daemon_loaded: bool
    resumed_existing_daemon: bool


@dataclass(frozen=True)
class MacOSEndpointUninstallResult:
    launch_daemon_stopped: bool
    pf_state_released_or_absent: bool
    keychain_items_removed: bool
    package_receipt_forgotten: bool
    removed: tuple[str, ...]
    preserved: tuple[str, ...]


@dataclass(frozen=True)
class MacOSContainmentRecoveryResult:
    collector_disabled: bool
    state: Literal["released", "unchanged"]
    summary: str


class MacOSEndpointLifecycle:
    """Verify and activate the already-installed endpoint without exposing secrets."""

    def __init__(
        self,
        *,
        collector_binary: Path = COLLECTOR_BINARY,
        collector_runtime: Path = COLLECTOR_RUNTIME,
        collector_config: Path = COLLECTOR_CONFIG,
        launchd_plist: Path = LAUNCHD_PLIST,
        runner: Optional[LifecycleCommandRunner] = None,
        system: Callable[[], str] = platform.system,
        euid: Callable[[], int] = os.geteuid,
        expected_uid: int = 0,
        credential_check: Optional[Callable[[CollectorDefinition], None]] = None,
        collector_default_config: Path = COLLECTOR_DEFAULT_CONFIG,
        controls_config: Path = CONTROLS_CONFIG,
        collector_spool: Path = COLLECTOR_SPOOL,
        status_snapshot: Path = STATUS_SNAPSHOT,
        response_state: Path = RESPONSE_STATE,
        user_app: Path = USER_APP,
        collector_log: Path = COLLECTOR_LOG,
        collector_error_log: Path = COLLECTOR_ERROR_LOG,
        pkgutil: str = PKGUTIL,
        pf_cleanup: Optional[Callable[[CollectorDefinition], None]] = None,
        containment_adapter: Optional[ContainmentRecoveryAdapter] = None,
        rules_directory: Path = RULES_DIRECTORY,
    ) -> None:
        self._collector_binary = collector_binary
        self._collector_runtime = collector_runtime
        self._collector_config = collector_config
        self._launchd_plist = launchd_plist
        self._runner = runner or FixedMacOSLifecycleRunner(
            collector_binary=collector_binary,
            collector_runtime=collector_runtime,
            collector_config=collector_config,
            launchd_plist=launchd_plist,
            pkgutil=pkgutil,
        )
        self._system = system
        self._euid = euid
        self._expected_uid = expected_uid
        self._credential_check = credential_check or self._load_credentials
        self._collector_default_config = collector_default_config
        self._controls_config = controls_config
        self._collector_spool = collector_spool
        self._status_snapshot = status_snapshot
        self._response_state = response_state
        self._user_app = user_app
        self._collector_log = collector_log
        self._collector_error_log = collector_error_log
        self._pkgutil = pkgutil
        self._pf_cleanup = pf_cleanup or self._release_pf_state
        self._containment_adapter = containment_adapter
        self._rules_directory = rules_directory

    def containment_status(self) -> MacOSContainmentStatus:
        """Report only the enum-level local PF posture from a root console."""

        self._require_environment(operation="containment status")
        return self._local_containment_adapter().containment_status()

    def release_containment(
        self,
        *,
        confirmation: str,
    ) -> MacOSContainmentRecoveryResult:
        """Disable collector polling and release only ControlForge-owned PF state.

        Disabling launchd first prevents a still-approved action from immediately
        reapplying containment while the operator is recovering without network access.
        The operator must resolve or expire the control-plane action before explicitly
        running ``agent-activate`` again.
        """

        self._require_environment(operation="containment release")
        if confirmation != RELEASE_CONTAINMENT_CONFIRMATION:
            raise MacOSEndpointLifecycleError(
                f"containment release requires --confirm {RELEASE_CONTAINMENT_CONFIRMATION}"
            )
        self._run(
            (LAUNCHCTL, "bootout", LAUNCHD_LABEL),
            timeout=15,
            allow_failure=True,
        )
        self._run((LAUNCHCTL, "disable", LAUNCHD_LABEL), timeout=10)
        if (
            self._run(
                (LAUNCHCTL, "print", LAUNCHD_LABEL),
                timeout=5,
                allow_failure=True,
            )
            == 0
        ):
            raise MacOSEndpointLifecycleError(
                "launch daemon remains loaded; containment release stopped"
            )
        try:
            result = self._local_containment_adapter().release_owned_state_for_recovery()
        except (MacOSResponseError, OSError, ValueError) as exc:
            raise MacOSEndpointLifecycleError(
                "ControlForge PF state could not be safely released"
            ) from exc
        if self._response_state.exists() or self._response_state.is_symlink():
            raise MacOSEndpointLifecycleError(
                "ControlForge PF recovery state remains; containment release stopped"
            )
        if result.state == "isolated":
            raise MacOSEndpointLifecycleError("containment release returned an invalid state")
        return MacOSContainmentRecoveryResult(
            collector_disabled=True,
            state=result.state,
            summary=(
                "ControlForge containment released; collector remains disabled until "
                "agent-activate is run explicitly."
            ),
        )

    def activate(self) -> MacOSEndpointActivationResult:
        self._require_environment()
        definition = self._verify_package()
        self._credential_check(definition)

        already_loaded = (
            self._run(
                (LAUNCHCTL, "print", LAUNCHD_LABEL),
                timeout=5,
                allow_failure=True,
            )
            == 0
        )
        self._run(
            (
                str(self._collector_binary),
                "agent",
                "--config",
                str(self._collector_config),
            ),
            timeout=120,
        )

        if already_loaded:
            self._run(
                (LAUNCHCTL, "kickstart", "-k", LAUNCHD_LABEL),
                timeout=15,
            )
        else:
            self._activate_new_daemon()

        if (
            self._run(
                (LAUNCHCTL, "print", LAUNCHD_LABEL),
                timeout=5,
                allow_failure=True,
            )
            != 0
        ):
            if not already_loaded:
                self._rollback_new_daemon()
            raise MacOSEndpointLifecycleError(
                "launch daemon did not remain loaded after first check-in"
            )
        return MacOSEndpointActivationResult(
            device_id=definition.device_id,
            first_check_in_verified=True,
            launch_daemon_loaded=True,
            resumed_existing_daemon=already_loaded,
        )

    def uninstall(
        self,
        *,
        confirmation: str,
        delete_spool: bool = False,
        delete_logs: bool = False,
    ) -> MacOSEndpointUninstallResult:
        """Remove only the validated endpoint package and locally owned state.

        This is intentionally a phased, idempotent workflow rather than a claim of
        cross-volume atomic deletion. Every destructive target is validated before
        launchd, PF, Keychain, or filesystem state is changed.
        """

        self._require_environment(operation="uninstall")
        if confirmation != UNINSTALL_CONFIRMATION:
            raise MacOSEndpointLifecycleError(
                f"endpoint uninstall requires --confirm {UNINSTALL_CONFIRMATION}"
            )
        definition = self._verify_uninstall_preflight(
            delete_spool=delete_spool,
            delete_logs=delete_logs,
        )

        self._run(
            (LAUNCHCTL, "bootout", LAUNCHD_LABEL),
            timeout=15,
            allow_failure=True,
        )
        self._run((LAUNCHCTL, "disable", LAUNCHD_LABEL), timeout=10)
        if (
            self._run(
                (LAUNCHCTL, "print", LAUNCHD_LABEL),
                timeout=5,
                allow_failure=True,
            )
            == 0
        ):
            raise MacOSEndpointLifecycleError(
                "launch daemon remains loaded; endpoint uninstall stopped"
            )

        try:
            self._pf_cleanup(definition)
        except (MacOSResponseError, OSError, ValueError) as exc:
            raise MacOSEndpointLifecycleError(
                "ControlForge PF state could not be safely released"
            ) from exc
        if self._response_state.exists() or self._response_state.is_symlink():
            raise MacOSEndpointLifecycleError(
                "ControlForge PF recovery state remains; endpoint uninstall stopped"
            )

        self._run((str(self._collector_binary), "keychain-delete-all"), timeout=30)

        removed: list[str] = []
        if self._remove_tree_if_present(self._user_app):
            removed.append("user_dashboard_app")
        for category, path in self._package_file_removals():
            if self._unlink_if_present(path):
                removed.append(category)

        if delete_spool:
            for category, path in self._spool_removals():
                if self._unlink_if_present(path):
                    removed.append(category)
        if delete_logs:
            for category, path in self._log_removals():
                if self._unlink_if_present(path):
                    removed.append(category)

        self._remove_empty_package_directories()
        receipt_forgotten = (
            self._run(
                (self._pkgutil, "--forget", PACKAGE_IDENTIFIER),
                timeout=15,
                allow_failure=True,
            )
            == 0
        )
        preserved = []
        if not delete_spool:
            preserved.append("telemetry_spool")
        if not delete_logs:
            preserved.append("collector_logs")
        return MacOSEndpointUninstallResult(
            launch_daemon_stopped=True,
            pf_state_released_or_absent=True,
            keychain_items_removed=True,
            package_receipt_forgotten=receipt_forgotten,
            removed=tuple(removed),
            preserved=tuple(preserved),
        )

    def _verify_uninstall_preflight(
        self,
        *,
        delete_spool: bool,
        delete_logs: bool,
    ) -> CollectorDefinition:
        self._trusted_file(self._collector_binary, executable=True)
        self._trusted_file(self._collector_config, exact_mode=0o600)
        self._run(
            (CODESIGN, "--verify", "--strict", str(self._collector_binary)),
            timeout=15,
        )
        try:
            definition = load_collector_definition(self._collector_config)
        except (OSError, ValueError) as exc:
            raise MacOSEndpointLifecycleError(
                "installed collector configuration is invalid"
            ) from exc
        if (
            definition.credential_source != "macos_system_keychain"
            or definition.keychain_service != KEYCHAIN_SERVICE
        ):
            raise MacOSEndpointLifecycleError(
                "installed collector Keychain ownership is not recognized"
            )
        if definition.response_state_path != self._response_state:
            raise MacOSEndpointLifecycleError(
                "configured PF recovery state is outside the uninstall allowlist"
            )
        if delete_spool and definition.spool_path != self._collector_spool:
            raise MacOSEndpointLifecycleError(
                "configured telemetry spool is outside the uninstall allowlist"
            )

        for _, path, executable, exact_mode in self._preflight_files(
            delete_spool=delete_spool,
            delete_logs=delete_logs,
        ):
            self._trusted_optional_file(
                path,
                executable=executable,
                exact_mode=exact_mode,
            )
        self._trusted_optional_tree(self._user_app)
        return definition

    def _preflight_files(
        self,
        *,
        delete_spool: bool,
        delete_logs: bool,
    ) -> tuple[tuple[str, Path, bool, Optional[int]], ...]:
        files: list[tuple[str, Path, bool, Optional[int]]] = [
            ("collector_runtime", self._collector_runtime, True, None),
            ("launch_daemon", self._launchd_plist, False, 0o644),
            ("default_config", self._collector_default_config, False, 0o644),
            ("controls_config", self._controls_config, False, 0o644),
            ("status_snapshot", self._status_snapshot, False, 0o644),
            ("account_server", self._status_snapshot.parent / "account-server.json", False, 0o644),
            (
                "account_installer_defaults",
                self._status_snapshot.parent.parent / "installer/account-server.default.json",
                False,
                0o644,
            ),
            (
                "network_membership",
                self._status_snapshot.parent / "network-membership.json",
                False,
                0o644,
            ),
            (
                "account_enrollment_lock",
                self._collector_config.parent / "account-enrollment.lock",
                False,
                0o600,
            ),
            ("pf_recovery_state", self._response_state, False, 0o600),
        ]
        files.extend(
            (f"canonical_rule:{name}", self._rules_directory / name, False, 0o644)
            for name in PACKAGED_RULE_NAMES
        )
        if delete_spool:
            files.extend((category, path, False, None) for category, path in self._spool_removals())
        if delete_logs:
            files.extend((category, path, False, None) for category, path in self._log_removals())
        return tuple(files)

    def _package_file_removals(self) -> tuple[tuple[str, Path], ...]:
        # Keep the signed Keychain helper and live config until every other
        # package-owned file has been removed. This leaves the safest recovery
        # boundary if an unexpected filesystem error interrupts deletion.
        return (
            ("launch_daemon", self._launchd_plist),
            ("status_snapshot", self._status_snapshot),
            ("account_server", self._status_snapshot.parent / "account-server.json"),
            (
                "account_installer_defaults",
                self._status_snapshot.parent.parent / "installer/account-server.default.json",
            ),
            ("network_membership", self._status_snapshot.parent / "network-membership.json"),
            ("account_enrollment_lock", self._collector_config.parent / "account-enrollment.lock"),
            ("controls_config", self._controls_config),
            ("default_config", self._collector_default_config),
            *(
                (f"canonical_rule:{name}", self._rules_directory / name)
                for name in sorted(PACKAGED_RULE_NAMES)
            ),
            ("collector_runtime", self._collector_runtime),
            ("collector_config", self._collector_config),
            ("collector_wrapper", self._collector_binary),
        )

    def _spool_removals(self) -> tuple[tuple[str, Path], ...]:
        return (
            ("telemetry_spool", self._collector_spool),
            ("telemetry_spool_wal", Path(f"{self._collector_spool}-wal")),
            ("telemetry_spool_shm", Path(f"{self._collector_spool}-shm")),
        )

    def _log_removals(self) -> tuple[tuple[str, Path], ...]:
        return (
            ("collector_log", self._collector_log),
            ("collector_error_log", self._collector_error_log),
        )

    def _trusted_optional_file(
        self,
        path: Path,
        *,
        executable: bool = False,
        exact_mode: Optional[int] = None,
    ) -> None:
        if path.is_symlink():
            raise MacOSEndpointLifecycleError("uninstall target is a symbolic link")
        if not path.exists():
            return
        self._trusted_file(path, executable=executable, exact_mode=exact_mode)

    def _trusted_optional_tree(self, path: Path) -> None:
        if path.is_symlink():
            raise MacOSEndpointLifecycleError("uninstall target is a symbolic link")
        if not path.exists():
            return
        self._trusted_parent(path.parent)
        for root, directories, files in os.walk(path, followlinks=False):
            root_path = Path(root)
            self._trusted_directory(root_path)
            for name in (*directories, *files):
                child = root_path / name
                try:
                    metadata = child.lstat()
                except OSError as exc:
                    raise MacOSEndpointLifecycleError(
                        "uninstall target changed during validation"
                    ) from exc
                if (
                    child.is_symlink()
                    or metadata.st_uid != self._expected_uid
                    or stat.S_IMODE(metadata.st_mode) & 0o022
                    or not (stat.S_ISREG(metadata.st_mode) or stat.S_ISDIR(metadata.st_mode))
                ):
                    raise MacOSEndpointLifecycleError("uninstall application bundle is not trusted")

    def _trusted_directory(self, path: Path) -> None:
        try:
            metadata = path.lstat()
        except OSError as exc:
            raise MacOSEndpointLifecycleError("uninstall directory is unavailable") from exc
        if (
            path.is_symlink()
            or not stat.S_ISDIR(metadata.st_mode)
            or metadata.st_uid != self._expected_uid
            or stat.S_IMODE(metadata.st_mode) & 0o022
        ):
            raise MacOSEndpointLifecycleError("uninstall directory is not trusted")

    def _unlink_if_present(self, path: Path) -> bool:
        self._trusted_optional_file(path)
        if not path.exists():
            return False
        try:
            path.unlink()
        except OSError as exc:
            raise MacOSEndpointLifecycleError(
                "validated endpoint file could not be removed"
            ) from exc
        return True

    def _remove_tree_if_present(self, path: Path) -> bool:
        self._trusted_optional_tree(path)
        if not path.exists():
            return False
        try:
            shutil.rmtree(path)
        except OSError as exc:
            raise MacOSEndpointLifecycleError(
                "validated endpoint application could not be removed"
            ) from exc
        return True

    def _remove_empty_package_directories(self) -> None:
        directories = (
            self._response_state.parent,
            self._status_snapshot.parent,
            self._rules_directory,
            self._collector_binary.parent,
            self._collector_config.parent,
            self._collector_binary.parent.parent,
        )
        for directory in directories:
            if directory.is_symlink() or not directory.exists():
                continue
            self._trusted_directory(directory)
            try:
                directory.rmdir()
            except OSError:
                # Retained spool files or unknown operator-owned content keep the
                # exact package directory in place; no broad recursive deletion.
                continue

    def _release_pf_state(self, definition: CollectorDefinition) -> None:
        MacOSPfResponseAdapter(
            enabled=False,
            device_id=definition.device_id,
            api_host=definition.api_host,
            api_port=definition.api_port,
            state_path=self._response_state,
            system=self._system,
            euid=self._euid,
            state_expected_uid=self._expected_uid,
        ).release_owned_state_for_uninstall()

    def _local_containment_adapter(self) -> ContainmentRecoveryAdapter:
        if self._containment_adapter is not None:
            return self._containment_adapter
        return MacOSPfResponseAdapter(
            enabled=False,
            device_id="local-recovery",
            api_host="localhost",
            api_port=443,
            state_path=self._response_state,
            system=self._system,
            euid=self._euid,
            state_expected_uid=self._expected_uid,
        )

    def _activate_new_daemon(self) -> None:
        try:
            self._run((LAUNCHCTL, "enable", LAUNCHD_LABEL), timeout=5)
            self._run(
                (LAUNCHCTL, "bootstrap", "system", str(self._launchd_plist)),
                timeout=15,
            )
        except MacOSEndpointLifecycleError:
            self._rollback_new_daemon()
            raise MacOSEndpointLifecycleError(
                "launch daemon activation failed after verified first check-in"
            ) from None

    def _rollback_new_daemon(self) -> None:
        for arguments in (
            (LAUNCHCTL, "bootout", LAUNCHD_LABEL),
            (LAUNCHCTL, "disable", LAUNCHD_LABEL),
        ):
            try:
                self._run(arguments, timeout=10, allow_failure=True)
            except MacOSEndpointLifecycleError:
                continue

    def _verify_package(self) -> CollectorDefinition:
        self._trusted_file(self._collector_binary, executable=True)
        self._trusted_file(self._collector_runtime, executable=True)
        self._trusted_file(self._collector_config, exact_mode=0o600)
        self._trusted_file(self._launchd_plist, exact_mode=0o644)
        self._validate_launchd_plist()
        self._run(
            (CODESIGN, "--verify", "--strict", str(self._collector_binary)),
            timeout=15,
        )
        self._run(
            (CODESIGN, "--verify", "--strict", str(self._collector_runtime)),
            timeout=15,
        )
        try:
            definition = load_collector_definition(self._collector_config)
        except (OSError, ValueError) as exc:
            raise MacOSEndpointLifecycleError(
                "installed collector configuration is invalid"
            ) from exc
        if definition.credential_source != "macos_system_keychain":
            raise MacOSEndpointLifecycleError(
                "installed collector must use the macOS System Keychain"
            )
        return definition

    def _trusted_file(
        self,
        path: Path,
        *,
        executable: bool = False,
        exact_mode: Optional[int] = None,
    ) -> None:
        self._trusted_parent(path.parent)
        try:
            metadata = path.lstat()
        except OSError as exc:
            raise MacOSEndpointLifecycleError("installed package file is unavailable") from exc
        mode = stat.S_IMODE(metadata.st_mode)
        if (
            path.is_symlink()
            or not stat.S_ISREG(metadata.st_mode)
            or metadata.st_uid != self._expected_uid
            or mode & 0o022
            or (exact_mode is not None and mode != exact_mode)
            or (executable and mode & 0o111 == 0)
        ):
            raise MacOSEndpointLifecycleError("installed package file is not trusted")

    def _trusted_parent(self, path: Path) -> None:
        try:
            metadata = path.lstat()
        except OSError as exc:
            raise MacOSEndpointLifecycleError("installed package directory is unavailable") from exc
        if (
            path.is_symlink()
            or not stat.S_ISDIR(metadata.st_mode)
            or metadata.st_uid != self._expected_uid
            or stat.S_IMODE(metadata.st_mode) & 0o022
        ):
            raise MacOSEndpointLifecycleError("installed package directory is not trusted")

    def _validate_launchd_plist(self) -> None:
        try:
            raw = self._launchd_plist.read_bytes()
            if len(raw) > 16_384:
                raise ValueError("oversized plist")
            payload = plistlib.loads(raw)
        except (OSError, ValueError, plistlib.InvalidFileException) as exc:
            raise MacOSEndpointLifecycleError("installed launch daemon plist is invalid") from exc
        expected_arguments = [
            str(self._collector_binary),
            "agent",
            "--config",
            str(self._collector_config),
        ]
        if (
            not isinstance(payload, dict)
            or payload.get("Label") != "com.controlforge.agent"
            or payload.get("ProgramArguments") != expected_arguments
            or payload.get("RunAtLoad") is not True
            or payload.get("Disabled") is not True
            or payload.get("StartInterval") != 60
        ):
            raise MacOSEndpointLifecycleError("installed launch daemon plist is invalid")

    def _load_credentials(self, definition: CollectorDefinition) -> None:
        try:
            MacOSSystemKeychain(definition.keychain_service).load(
                require_access=definition.access_proxy_required
            )
        except ValueError as exc:
            raise MacOSEndpointLifecycleError(
                "collector credentials are unavailable in the System Keychain"
            ) from exc

    def _require_environment(self, *, operation: str = "activation") -> None:
        if self._system() != "Darwin":
            raise MacOSEndpointLifecycleError(f"endpoint {operation} requires macOS")
        if self._euid() != 0:
            raise MacOSEndpointLifecycleError(f"endpoint {operation} requires root")

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


__all__ = [
    "RELEASE_CONTAINMENT_CONFIRMATION",
    "RULES_DIRECTORY",
    "UNINSTALL_CONFIRMATION",
    "ContainmentRecoveryAdapter",
    "FixedMacOSLifecycleRunner",
    "MacOSContainmentRecoveryResult",
    "MacOSEndpointActivationResult",
    "MacOSEndpointLifecycle",
    "MacOSEndpointLifecycleError",
    "MacOSEndpointUninstallResult",
]
