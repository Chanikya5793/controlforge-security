"""Read-only, claim-safe acceptance checks for a physical macOS endpoint."""

from __future__ import annotations

import hashlib
import platform
import sqlite3
import stat
import subprocess  # nosec B404 -- fixed read-only macOS verification commands
from collections.abc import Callable, Sequence
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Literal, Optional, Protocol

from .collector_agent import AgentStatusSnapshot, load_collector_definition

AcceptancePhase = Literal["preinstall", "installed", "enrolled", "running", "uninstalled"]

PKGUTIL = "/usr/sbin/pkgutil"
CODESIGN = "/usr/bin/codesign"
SPCTL = "/usr/sbin/spctl"
STAPLER = "/usr/bin/xcrun"
LAUNCHCTL = "/bin/launchctl"
SECURITY = "/usr/bin/security"
SYSTEM_KEYCHAIN = "/Library/Keychains/System.keychain"
PACKAGE_IDENTIFIER = "com.controlforge.agent"
LAUNCHD_LABEL = "system/com.controlforge.agent"
KEYCHAIN_SERVICE = "com.controlforge.collector.v2"
PACKAGED_RULE_NAMES = frozenset(
    {
        "credential_dumping.yml",
        "edge_sensitive_path_scan.yml",
        "encoded_powershell.yml",
        "phishing_email.yml",
        "privilege_grant.yml",
        "run_key_persistence.yml",
        "santa_denied_execution.yml",
        "santa_gatekeeper_override.yml",
        "santa_xprotect.yml",
        "suspicious_process_tree.yml",
    }
)


@dataclass(frozen=True)
class MacOSAcceptancePaths:
    collector_binary: Path
    collector_runtime: Path
    collector_config: Path
    collector_default_config: Path
    controls_config: Path
    launchd_plist: Path
    status_snapshot: Path
    collector_spool: Path
    user_app: Path
    collector_log: Path
    collector_error_log: Path
    rules_directory: Path

    @classmethod
    def from_root(cls, root: Path = Path("/")) -> MacOSAcceptancePaths:
        def fixed(value: str) -> Path:
            return root / value.lstrip("/")

        return cls(
            collector_binary=fixed("/Library/ControlForge/bin/controlforge"),
            collector_runtime=fixed("/Library/ControlForge/bin/controlforge-runtime"),
            collector_config=fixed("/Library/Application Support/ControlForge/collector.yml"),
            collector_default_config=fixed(
                "/Library/Application Support/ControlForge/collector.default.yml"
            ),
            controls_config=fixed("/Library/Application Support/ControlForge/agents.yml"),
            launchd_plist=fixed("/Library/LaunchDaemons/com.controlforge.agent.plist"),
            status_snapshot=fixed("/Library/ControlForge/status/agent-status.json"),
            collector_spool=fixed(
                "/Library/Application Support/ControlForge/controlforge-agent-spool.db"
            ),
            user_app=fixed("/Applications/ControlForge.app"),
            collector_log=fixed("/var/log/controlforge-agent.log"),
            collector_error_log=fixed("/var/log/controlforge-agent-error.log"),
            rules_directory=fixed("/Library/ControlForge/rules"),
        )


@dataclass(frozen=True)
class ReadOnlyCommandResult:
    returncode: int
    output: str = ""


class MacOSAcceptanceRunner(Protocol):
    def run(self, arguments: Sequence[str], timeout_seconds: float) -> ReadOnlyCommandResult:
        """Run one allowlisted read-only command."""


class FixedMacOSAcceptanceRunner:
    """Allow only local signature, receipt, launchd, and Keychain metadata reads."""

    def __init__(
        self,
        paths: MacOSAcceptancePaths,
        package: Optional[Path] = None,
    ) -> None:
        commands = {
            (PKGUTIL, "--pkg-info", PACKAGE_IDENTIFIER),
            (LAUNCHCTL, "print", LAUNCHD_LABEL),
            (CODESIGN, "--verify", "--strict", str(paths.collector_binary)),
            (CODESIGN, "--verify", "--strict", str(paths.collector_runtime)),
            (CODESIGN, "--verify", "--deep", "--strict", str(paths.user_app)),
        }
        for account in ("credential-id", "credential-secret", "credential-pair-v1"):
            commands.add(
                (
                    SECURITY,
                    "find-generic-password",
                    "-s",
                    KEYCHAIN_SERVICE,
                    "-a",
                    account,
                    SYSTEM_KEYCHAIN,
                )
            )
        if package is not None:
            commands.update(
                {
                    (PKGUTIL, "--check-signature", str(package)),
                    (STAPLER, "stapler", "validate", str(package)),
                    (SPCTL, "--assess", "--type", "install", "-vv", str(package)),
                }
            )
        self._commands = commands

    def run(self, arguments: Sequence[str], timeout_seconds: float) -> ReadOnlyCommandResult:
        fixed = tuple(arguments)
        if fixed not in self._commands:
            raise ValueError("physical acceptance command is not allowlisted")
        try:
            completed = subprocess.run(  # noqa: S603  # nosec B603
                fixed,
                stdin=subprocess.DEVNULL,
                capture_output=True,
                text=True,
                check=False,
                timeout=timeout_seconds,
            )
        except (OSError, subprocess.TimeoutExpired):
            return ReadOnlyCommandResult(127)
        output = f"{completed.stdout}\n{completed.stderr}"[:4_096]
        return ReadOnlyCommandResult(completed.returncode, output)


@dataclass(frozen=True)
class MacOSAcceptanceCheck:
    name: str
    status: Literal["pass", "fail"]
    evidence: str


@dataclass(frozen=True)
class MacOSAcceptanceReport:
    schema_version: Literal["controlforge-macos-physical-acceptance.v1"]
    generated_at: str
    phase: AcceptancePhase
    machine_fingerprint: str
    passed: bool
    checks: tuple[MacOSAcceptanceCheck, ...]

    def as_dict(self) -> dict[str, object]:
        return {
            "schema_version": self.schema_version,
            "generated_at": self.generated_at,
            "phase": self.phase,
            "machine_fingerprint": self.machine_fingerprint,
            "passed": self.passed,
            "checks": [asdict(check) for check in self.checks],
        }


class MacOSPhysicalAcceptanceVerifier:
    """Collect bounded physical evidence without reading credentials or telemetry rows."""

    def __init__(
        self,
        *,
        phase: AcceptancePhase,
        paths: Optional[MacOSAcceptancePaths] = None,
        package: Optional[Path] = None,
        package_sha256: Optional[str] = None,
        runner: Optional[MacOSAcceptanceRunner] = None,
        system: Callable[[], str] = platform.system,
        machine: Callable[[], str] = platform.machine,
        mac_version: Callable[[], str] = lambda: platform.mac_ver()[0],
        hostname: Callable[[], str] = platform.node,
        expected_uid: int = 0,
    ) -> None:
        if (package is None) != (package_sha256 is None):
            raise ValueError("package and package_sha256 must be supplied together")
        self._phase = phase
        self._paths = paths or MacOSAcceptancePaths.from_root()
        self._package = package
        self._package_sha256 = package_sha256
        self._runner = runner or FixedMacOSAcceptanceRunner(self._paths, package)
        self._system = system
        self._machine = machine
        self._mac_version = mac_version
        self._hostname = hostname
        self._expected_uid = expected_uid

    def verify(self, now: Optional[datetime] = None) -> MacOSAcceptanceReport:
        checked_at = (now or datetime.now(timezone.utc)).astimezone(timezone.utc)
        checks: list[MacOSAcceptanceCheck] = []
        checks.append(self._environment_check())
        if self._package is not None and self._package_sha256 is not None:
            checks.extend(self._package_checks())
        if self._phase == "preinstall":
            checks.extend(self._absence_checks(require_receipt_absent=True))
        elif self._phase == "installed":
            checks.extend(self._installed_checks(expect_running=False))
        elif self._phase == "enrolled":
            checks.extend(self._installed_checks(expect_running=False))
            checks.extend(self._enrollment_checks())
        elif self._phase == "running":
            checks.extend(self._installed_checks(expect_running=True))
            checks.extend(self._enrollment_checks())
            checks.extend(self._running_checks(checked_at))
        else:
            checks.extend(self._absence_checks(require_receipt_absent=True))
        machine_fingerprint = hashlib.sha256(
            self._hostname().encode("utf-8", errors="ignore")
        ).hexdigest()[:16]
        return MacOSAcceptanceReport(
            schema_version="controlforge-macos-physical-acceptance.v1",
            generated_at=checked_at.isoformat().replace("+00:00", "Z"),
            phase=self._phase,
            machine_fingerprint=machine_fingerprint,
            passed=all(check.status == "pass" for check in checks),
            checks=tuple(checks),
        )

    def _environment_check(self) -> MacOSAcceptanceCheck:
        version = self._mac_version()
        try:
            major = int(version.split(".", 1)[0])
        except (TypeError, ValueError):
            major = 0
        passed = self._system() == "Darwin" and self._machine() == "arm64" and major >= 13
        return self._check(
            "supported_clean_mac",
            passed,
            "Apple Silicon macOS 13 or newer" if passed else "unsupported host boundary",
        )

    def _package_checks(self) -> list[MacOSAcceptanceCheck]:
        assert self._package is not None
        assert self._package_sha256 is not None
        try:
            package_bytes = self._package.read_bytes()
        except OSError:
            package_bytes = b""
        digest_matches = bool(package_bytes) and hashlib.sha256(package_bytes).hexdigest() == (
            self._package_sha256.casefold()
        )
        signature = self._runner.run(
            (PKGUTIL, "--check-signature", str(self._package)),
            30,
        )
        stapled = self._runner.run((STAPLER, "stapler", "validate", str(self._package)), 30)
        gatekeeper = self._runner.run(
            (SPCTL, "--assess", "--type", "install", "-vv", str(self._package)),
            30,
        )
        return [
            self._check("package_sha256", digest_matches, "pinned artifact digest"),
            self._check(
                "package_developer_id",
                signature.returncode == 0 and "signed by a developer" in signature.output,
                "Developer ID installer signature",
            ),
            self._check(
                "package_stapled_ticket",
                stapled.returncode == 0 and "validate action worked" in stapled.output,
                "Apple stapled-ticket validation",
            ),
            self._check(
                "package_gatekeeper",
                gatekeeper.returncode == 0 and "source=Notarized Developer ID" in gatekeeper.output,
                "Gatekeeper notarized Developer ID assessment",
            ),
        ]

    def _installed_checks(self, *, expect_running: bool) -> list[MacOSAcceptanceCheck]:
        paths = self._paths
        checks = [
            self._check(
                "package_receipt_present",
                self._runner.run((PKGUTIL, "--pkg-info", PACKAGE_IDENTIFIER), 15).returncode == 0,
                "fixed package receipt",
            ),
            self._trusted_file("collector_wrapper", paths.collector_binary, executable=True),
            self._trusted_file("collector_runtime", paths.collector_runtime, executable=True),
            self._trusted_file(
                "launchd_plist",
                paths.launchd_plist,
                exact_mode=0o644,
            ),
            self._trusted_file(
                "default_configuration",
                paths.collector_default_config,
                exact_mode=0o644,
            ),
            self._trusted_file(
                "controls_configuration",
                paths.controls_config,
                exact_mode=0o644,
            ),
            self._trusted_tree("native_user_application", paths.user_app),
            self._trusted_rule_set(),
        ]
        signature_commands = (
            (
                "collector_wrapper_signature",
                (CODESIGN, "--verify", "--strict", str(paths.collector_binary)),
            ),
            (
                "collector_runtime_signature",
                (CODESIGN, "--verify", "--strict", str(paths.collector_runtime)),
            ),
            (
                "native_application_signature",
                (CODESIGN, "--verify", "--deep", "--strict", str(paths.user_app)),
            ),
        )
        checks.extend(
            self._check(
                name, self._runner.run(command, 20).returncode == 0, "strict code signature"
            )
            for name, command in signature_commands
        )
        daemon_loaded = self._runner.run((LAUNCHCTL, "print", LAUNCHD_LABEL), 10).returncode == 0
        checks.append(
            self._check(
                "launchd_state",
                daemon_loaded == expect_running,
                "loaded" if daemon_loaded else "not loaded",
            )
        )
        return checks

    def _enrollment_checks(self) -> list[MacOSAcceptanceCheck]:
        config_check = self._trusted_file(
            "live_configuration",
            self._paths.collector_config,
            exact_mode=0o600,
        )
        definition_valid = False
        try:
            definition = load_collector_definition(self._paths.collector_config)
            definition_valid = (
                definition.credential_source == "macos_system_keychain"
                and definition.keychain_service == KEYCHAIN_SERVICE
                and definition.status_snapshot_path == self._paths.status_snapshot
                and definition.spool_path == self._paths.collector_spool
            )
        except (OSError, ValueError):
            definition_valid = False
        item_results = {
            account: self._runner.run(
                (
                    SECURITY,
                    "find-generic-password",
                    "-s",
                    KEYCHAIN_SERVICE,
                    "-a",
                    account,
                    SYSTEM_KEYCHAIN,
                ),
                15,
            ).returncode
            == 0
            for account in ("credential-id", "credential-secret", "credential-pair-v1")
        }
        keychain_present = item_results["credential-pair-v1"] or (
            item_results["credential-id"] and item_results["credential-secret"]
        )
        return [
            config_check,
            self._check(
                "standalone_configuration_contract",
                definition_valid,
                "fixed host, System Keychain, status, and spool paths",
            ),
            self._check(
                "system_keychain_credential_presence",
                keychain_present,
                "metadata-only lookup; credential values were not read",
            ),
        ]

    def _running_checks(self, now: datetime) -> list[MacOSAcceptanceCheck]:
        status_file = self._trusted_file(
            "status_snapshot_file",
            self._paths.status_snapshot,
            exact_mode=0o644,
        )
        status_valid = False
        status_fresh = False
        run_completed = False
        containment_bounded = False
        try:
            raw = self._paths.status_snapshot.read_bytes()
            if len(raw) <= 65_536:
                status = AgentStatusSnapshot.model_validate_json(raw)
                age = (now - status.generated_at).total_seconds()
                status_valid = status.schema_version == "controlforge-agent-status-v3"
                status_fresh = -60 <= age <= 300
                run_completed = status.run_status == "completed"
                containment_bounded = status.containment.state in {
                    "not_configured",
                    "released",
                    "isolated",
                    "needs_attention",
                }
        except (OSError, ValueError):
            pass
        spool_file = self._trusted_file("telemetry_spool_file", self._paths.collector_spool)
        spool_integrity = False
        try:
            with sqlite3.connect(
                f"file:{self._paths.collector_spool}?mode=ro",
                uri=True,
            ) as connection:
                spool_integrity = connection.execute("PRAGMA quick_check").fetchone()[0] == "ok"
        except (OSError, sqlite3.Error):
            spool_integrity = False
        return [
            status_file,
            self._check("status_contract_v2", status_valid, "strict redacted schema"),
            self._check("status_freshness", status_fresh, "within five minutes"),
            self._check("latest_agent_run", run_completed, "completed"),
            self._check(
                "containment_posture_bounded",
                containment_bounded,
                "enum-only state with optional bounded expiry",
            ),
            spool_file,
            self._check("telemetry_spool_integrity", spool_integrity, "SQLite quick_check ok"),
        ]

    def _absence_checks(self, *, require_receipt_absent: bool) -> list[MacOSAcceptanceCheck]:
        receipt_absent = (
            self._runner.run((PKGUTIL, "--pkg-info", PACKAGE_IDENTIFIER), 15).returncode != 0
        )
        core_paths = (
            self._paths.collector_binary,
            self._paths.collector_runtime,
            self._paths.launchd_plist,
            self._paths.user_app,
            *(self._paths.rules_directory / name for name in PACKAGED_RULE_NAMES),
        )
        paths_absent = all(not path.exists() and not path.is_symlink() for path in core_paths)
        return [
            self._check(
                "package_receipt_absent",
                receipt_absent if require_receipt_absent else True,
                "fixed package receipt absent",
            ),
            self._check("package_payload_absent", paths_absent, "fixed package paths absent"),
        ]

    def _trusted_file(
        self,
        name: str,
        path: Path,
        *,
        executable: bool = False,
        exact_mode: Optional[int] = None,
    ) -> MacOSAcceptanceCheck:
        trusted = False
        try:
            metadata = path.lstat()
            mode = stat.S_IMODE(metadata.st_mode)
            trusted = (
                not path.is_symlink()
                and stat.S_ISREG(metadata.st_mode)
                and metadata.st_uid == self._expected_uid
                and mode & 0o022 == 0
                and (not executable or mode & 0o111 != 0)
                and (exact_mode is None or mode == exact_mode)
            )
        except OSError:
            pass
        return self._check(name, trusted, "root-owned regular file with safe mode")

    def _trusted_tree(self, name: str, path: Path) -> MacOSAcceptanceCheck:
        trusted = False
        try:
            metadata = path.lstat()
            trusted = (
                not path.is_symlink()
                and stat.S_ISDIR(metadata.st_mode)
                and metadata.st_uid == self._expected_uid
                and stat.S_IMODE(metadata.st_mode) & 0o022 == 0
            )
        except OSError:
            pass
        return self._check(name, trusted, "root-owned application directory with safe mode")

    def _trusted_rule_set(self) -> MacOSAcceptanceCheck:
        directory = self._paths.rules_directory
        trusted = False
        try:
            metadata = directory.lstat()
            children = tuple(directory.iterdir())
            trusted = (
                not directory.is_symlink()
                and stat.S_ISDIR(metadata.st_mode)
                and metadata.st_uid == self._expected_uid
                and stat.S_IMODE(metadata.st_mode) & 0o022 == 0
                and {child.name for child in children} == PACKAGED_RULE_NAMES
                and all(
                    not child.is_symlink()
                    and stat.S_ISREG(child.lstat().st_mode)
                    and child.lstat().st_uid == self._expected_uid
                    and stat.S_IMODE(child.lstat().st_mode) == 0o644
                    for child in children
                )
            )
        except OSError:
            pass
        return self._check(
            "canonical_rule_payload",
            trusted,
            "exact root-owned canonical YAML set with mode 0644",
        )

    @staticmethod
    def _check(name: str, passed: bool, evidence: str) -> MacOSAcceptanceCheck:
        return MacOSAcceptanceCheck(name, "pass" if passed else "fail", evidence)


__all__ = [
    "PACKAGED_RULE_NAMES",
    "AcceptancePhase",
    "FixedMacOSAcceptanceRunner",
    "MacOSAcceptanceCheck",
    "MacOSAcceptancePaths",
    "MacOSAcceptanceReport",
    "MacOSAcceptanceRunner",
    "MacOSPhysicalAcceptanceVerifier",
    "ReadOnlyCommandResult",
]
