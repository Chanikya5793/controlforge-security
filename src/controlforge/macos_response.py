"""Disabled-by-default, reversible macOS PF endpoint containment."""

from __future__ import annotations

import ipaddress
import os
import platform
import re
import socket
import stat
import subprocess  # nosec B404 -- fixed /sbin/pfctl boundary only
import tempfile
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Literal, Optional, Protocol

from pydantic import BaseModel, ConfigDict, Field, field_validator

PFCTL = "/sbin/pfctl"
CONTROLFORGE_ANCHOR = "com.apple/controlforge"
MAX_CONTAINMENT = timedelta(minutes=15)
_TOKEN = re.compile(r"^[0-9]{1,20}$")
_TOKEN_OUTPUT = re.compile(r"(?im)^Token\s*:\s*([0-9]{1,20})\s*$")
_FIXED_HOST = re.compile(r"^(?:localhost|(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63})$")


class MacOSResponseError(RuntimeError):
    """A bounded endpoint response failure that never includes command output."""

    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


class PfctlCommandError(RuntimeError):
    """A fixed PF command failed without exposing its provider output."""


class MacOSResponseAction(BaseModel):
    """Strict active action accepted by the endpoint containment adapter."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    action_id: str = Field(
        min_length=36,
        max_length=36,
        pattern=r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-"
        r"[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$",
    )
    action_type: Literal["isolate_endpoint", "release_endpoint"]
    target_type: Literal["device"]
    target_id: str = Field(min_length=1, max_length=128, pattern=r"^[A-Za-z0-9._:-]+$")
    rationale: str = Field(min_length=1, max_length=2_000)
    risk_level: Literal["active"]
    expires_at: datetime

    @field_validator("expires_at")
    @classmethod
    def require_timezone(cls, value: datetime) -> datetime:
        if value.tzinfo is None:
            raise ValueError("active response expiry must be timezone-aware")
        return value.astimezone(timezone.utc)


class MacOSPfState(BaseModel):
    """Only the minimum PF ownership material persisted across collector runs."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    pf_token: str = Field(pattern=r"^[0-9]{1,20}$")
    expires_at: datetime
    management_ips: list[str] = Field(min_length=1, max_length=16)

    @field_validator("expires_at")
    @classmethod
    def require_timezone(cls, value: datetime) -> datetime:
        if value.tzinfo is None:
            raise ValueError("PF state expiry must be timezone-aware")
        return value.astimezone(timezone.utc)

    @field_validator("management_ips")
    @classmethod
    def validate_management_ips(cls, values: list[str]) -> list[str]:
        normalized = sorted({str(ipaddress.ip_address(value)) for value in values})
        if len(normalized) != len(values):
            raise ValueError("PF state management IPs must be unique and sorted")
        return normalized


@dataclass(frozen=True)
class MacOSResponseResult:
    succeeded: bool
    state: Literal["isolated", "released", "unchanged"]
    summary: str
    evidence: tuple[str, ...]


@dataclass(frozen=True)
class MacOSReconciliationEvent:
    occurred_at: datetime
    state: Literal["released", "release_failed", "state_invalid"]
    reason: Literal["containment_expired", "automatic_release_failed", "state_invalid"]


@dataclass(frozen=True)
class MacOSContainmentStatus:
    """Redacted local posture without action, PF token, address, or rationale data."""

    state: Literal["not_configured", "released", "isolated", "needs_attention"]
    expires_at: Optional[datetime] = None


class PfctlRunner(Protocol):
    def run(self, arguments: Sequence[str], rules: Optional[str] = None) -> str:
        """Run one allowlisted PF command and return bounded stdout for token parsing."""


class ManagementResolver(Protocol):
    def resolve(self, host: str, port: int) -> tuple[str, ...]:
        """Resolve only the already validated fixed management host."""


class PfStateStore(Protocol):
    def read(self) -> Optional[MacOSPfState]:
        """Read and strictly validate the current PF ownership state."""

    def write(self, state: MacOSPfState) -> None:
        """Atomically persist PF ownership state."""

    def delete(self) -> None:
        """Delete PF ownership state after a complete release."""


class MacOSResponseAdapter(Protocol):
    def execute(self, action: MacOSResponseAction) -> MacOSResponseResult:
        """Execute one strictly validated active action."""

    def reconcile(self) -> Optional[MacOSReconciliationEvent]:
        """Release expired containment and return a bounded state transition."""

    def containment_status(self) -> MacOSContainmentStatus:
        """Return the privacy-safe current containment posture."""


class FixedPfctlRunner:
    """Execute only the four PF argv shapes owned by ControlForge."""

    @staticmethod
    def _validate(arguments: tuple[str, ...], rules: Optional[str]) -> None:
        if arguments == (PFCTL, "-E") and rules is None:
            return
        if arguments == (PFCTL, "-a", CONTROLFORGE_ANCHOR, "-f", "-") and rules:
            return
        if arguments == (PFCTL, "-a", CONTROLFORGE_ANCHOR, "-F", "all") and rules is None:
            return
        if (
            len(arguments) == 3
            and arguments[:2] == (PFCTL, "-X")
            and _TOKEN.fullmatch(arguments[2]) is not None
            and rules is None
        ):
            return
        raise ValueError("PF command is not allowlisted")

    def run(self, arguments: Sequence[str], rules: Optional[str] = None) -> str:
        fixed_arguments = tuple(arguments)
        self._validate(fixed_arguments, rules)
        try:
            completed = subprocess.run(  # noqa: S603  # nosec B603
                fixed_arguments,
                input=rules,
                text=True,
                check=True,
                capture_output=True,
                timeout=10,
            )
        except (OSError, subprocess.CalledProcessError, subprocess.TimeoutExpired) as exc:
            raise PfctlCommandError("fixed PF command failed") from exc
        return completed.stdout[:1_024]


class FixedHostResolver:
    """Resolve a configured hostname to a bounded, normalized address set."""

    def resolve(self, host: str, port: int) -> tuple[str, ...]:
        try:
            records = socket.getaddrinfo(
                host,
                port,
                family=socket.AF_UNSPEC,
                type=socket.SOCK_STREAM,
                proto=socket.IPPROTO_TCP,
            )
        except socket.gaierror as exc:
            raise MacOSResponseError("management_resolution_failed") from exc
        addresses = sorted({str(ipaddress.ip_address(record[4][0])) for record in records})
        if not addresses or len(addresses) > 16:
            raise MacOSResponseError("management_resolution_failed")
        return tuple(addresses)


class RootOwnedPfStateStore:
    """Atomically persist a strict 0600 PF state file in a private directory."""

    def __init__(self, path: Path, *, expected_uid: int = 0) -> None:
        self.path = path
        self._expected_uid = expected_uid

    def _prepare_parent(self) -> None:
        try:
            self.path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
            metadata = self.path.parent.lstat()
        except OSError as exc:
            raise MacOSResponseError("state_storage_unavailable") from exc
        if (
            not stat.S_ISDIR(metadata.st_mode)
            or self.path.parent.is_symlink()
            or metadata.st_uid != self._expected_uid
            or stat.S_IMODE(metadata.st_mode) != 0o700
        ):
            raise MacOSResponseError("state_storage_unsafe")

    def _metadata(self) -> Optional[os.stat_result]:
        try:
            return self.path.lstat()
        except FileNotFoundError:
            return None
        except OSError as exc:
            raise MacOSResponseError("state_unavailable") from exc

    def _trusted_file(self, metadata: Optional[os.stat_result] = None) -> os.stat_result:
        selected = self._metadata() if metadata is None else metadata
        if selected is None:
            raise MacOSResponseError("state_unavailable")
        if (
            not stat.S_ISREG(selected.st_mode)
            or self.path.is_symlink()
            or selected.st_uid != self._expected_uid
            or stat.S_IMODE(selected.st_mode) != 0o600
        ):
            raise MacOSResponseError("state_unsafe")
        return selected

    def read(self) -> Optional[MacOSPfState]:
        metadata = self._metadata()
        if metadata is None:
            return None
        metadata = self._trusted_file(metadata)
        if metadata.st_size < 2 or metadata.st_size > 4_096:
            raise MacOSResponseError("state_malformed")
        try:
            return MacOSPfState.model_validate_json(self.path.read_bytes())
        except (OSError, ValueError) as exc:
            raise MacOSResponseError("state_malformed") from exc

    def write(self, state: MacOSPfState) -> None:
        self._prepare_parent()
        metadata = self._metadata()
        if metadata is not None:
            self._trusted_file(metadata)
        payload = state.model_dump_json().encode()
        descriptor, temporary_name = tempfile.mkstemp(
            prefix=f".{self.path.name}.",
            dir=self.path.parent,
        )
        temporary_path = Path(temporary_name)
        replaced = False
        try:
            os.fchmod(descriptor, 0o600)
            with os.fdopen(descriptor, "wb") as stream:
                stream.write(payload)
                stream.flush()
                os.fsync(stream.fileno())
            os.replace(temporary_path, self.path)
            replaced = True
            self._fsync_parent()
        except OSError as exc:
            if replaced:
                try:
                    self.path.unlink()
                    self._fsync_parent()
                except OSError:
                    pass
            raise MacOSResponseError("state_persistence_failed") from exc
        finally:
            temporary_path.unlink(missing_ok=True)

    def delete(self) -> None:
        metadata = self._metadata()
        if metadata is None:
            return
        self._trusted_file(metadata)
        try:
            self.path.unlink()
        except OSError as exc:
            raise MacOSResponseError("state_release_failed") from exc
        try:
            self._fsync_parent()
        except OSError:
            # The state is already absent and PF has already been released. Reporting
            # failure here would incorrectly claim that recovery material still exists.
            return

    def _fsync_parent(self) -> None:
        descriptor = os.open(self.path.parent, os.O_RDONLY)
        try:
            os.fsync(descriptor)
        finally:
            os.close(descriptor)


class MacOSPfResponseAdapter:
    """Apply and release one runtime-only ControlForge PF anchor."""

    def __init__(
        self,
        *,
        enabled: bool,
        device_id: str,
        api_host: str,
        api_port: int,
        state_path: Path,
        runner: Optional[PfctlRunner] = None,
        resolver: Optional[ManagementResolver] = None,
        clock: Optional[Callable[[], datetime]] = None,
        system: Optional[Callable[[], str]] = None,
        euid: Optional[Callable[[], int]] = None,
        state_expected_uid: int = 0,
        state_store: Optional[PfStateStore] = None,
    ) -> None:
        if _FIXED_HOST.fullmatch(api_host) is None:
            raise ValueError("response adapter API host is invalid")
        if type(api_port) is not int or api_port < 1 or api_port > 65_535:
            raise ValueError("response adapter API port is invalid")
        self._enabled = enabled
        self._device_id = device_id
        self._api_host = api_host
        self._api_port = api_port
        self._runner = runner or FixedPfctlRunner()
        self._resolver = resolver or FixedHostResolver()
        self._clock = clock or (lambda: datetime.now(timezone.utc))
        self._system = system or platform.system
        self._euid = euid or os.geteuid
        self._state = state_store or RootOwnedPfStateStore(
            state_path,
            expected_uid=state_expected_uid,
        )

    def execute(self, action: MacOSResponseAction) -> MacOSResponseResult:
        now = self._utc_now()
        if action.target_id != self._device_id:
            raise MacOSResponseError("target_mismatch")
        if action.expires_at <= now:
            raise MacOSResponseError("action_expired")
        if action.action_type == "isolate_endpoint":
            self._require_environment()
            return self._isolate(action, now)
        self._require_environment(allow_disabled=True)
        return self._release()

    def reconcile(self) -> Optional[MacOSReconciliationEvent]:
        now = self._utc_now()
        try:
            current = self._state.read()
        except MacOSResponseError:
            return MacOSReconciliationEvent(now, "state_invalid", "state_invalid")
        if current is None or current.expires_at > now:
            return None
        try:
            self._require_environment(allow_disabled=True)
            self._release_state(current)
        except MacOSResponseError:
            return MacOSReconciliationEvent(
                now,
                "release_failed",
                "automatic_release_failed",
            )
        return MacOSReconciliationEvent(now, "released", "containment_expired")

    def containment_status(self) -> MacOSContainmentStatus:
        """Describe owned PF posture without exposing recovery material."""

        now = self._utc_now()
        try:
            current = self._state.read()
        except MacOSResponseError:
            return MacOSContainmentStatus("needs_attention")
        if current is None:
            return MacOSContainmentStatus("released" if self._enabled else "not_configured")
        if current.expires_at <= now:
            return MacOSContainmentStatus("needs_attention")
        return MacOSContainmentStatus("isolated", current.expires_at)

    def release_owned_state_for_uninstall(self) -> MacOSResponseResult:
        """Release only ControlForge's persisted PF token before package removal."""

        return self.release_owned_state_for_recovery()

    def release_owned_state_for_recovery(self) -> MacOSResponseResult:
        """Release only ControlForge-owned PF state from a local recovery console."""

        self._require_environment(allow_disabled=True)
        return self._release()

    def _isolate(
        self,
        action: MacOSResponseAction,
        now: datetime,
    ) -> MacOSResponseResult:
        current = self._state.read()
        if current is not None:
            if current.expires_at <= now:
                self._release_state(current)
            else:
                return MacOSResponseResult(
                    True,
                    "unchanged",
                    "Endpoint containment is already active.",
                    ("macos-pf-anchor:already-isolated",),
                )
        management_ips = self._validated_management_ips(
            self._resolver.resolve(self._api_host, self._api_port)
        )
        expiry = min(action.expires_at, now + MAX_CONTAINMENT)
        token: Optional[str] = None
        try:
            token = self._enable_pf()
            self._runner.run(
                (PFCTL, "-a", CONTROLFORGE_ANCHOR, "-f", "-"),
                self._rules(management_ips),
            )
            self._state.write(
                MacOSPfState(
                    pf_token=token,
                    expires_at=expiry,
                    management_ips=list(management_ips),
                )
            )
        except (MacOSResponseError, PfctlCommandError) as exc:
            if token is not None:
                rollback_succeeded = self._rollback(token)
                if rollback_succeeded:
                    self._discard_failed_state(token)
                else:
                    self._preserve_failed_rollback(token, expiry, management_ips)
            if isinstance(exc, MacOSResponseError):
                raise
            raise MacOSResponseError("pf_command_failed") from exc
        return MacOSResponseResult(
            True,
            "isolated",
            "Endpoint network containment applied.",
            (
                "macos-pf-anchor:isolated",
                f"management-addresses:{len(management_ips)}",
                f"expires-at:{expiry.isoformat()}",
            ),
        )

    def _release(self) -> MacOSResponseResult:
        current = self._state.read()
        if current is None:
            return MacOSResponseResult(
                True,
                "unchanged",
                "Endpoint containment is already released.",
                ("macos-pf-anchor:already-released",),
            )
        self._release_state(current)
        return MacOSResponseResult(
            True,
            "released",
            "Endpoint network containment released.",
            ("macos-pf-anchor:released",),
        )

    def _release_state(self, state: MacOSPfState) -> None:
        try:
            self._runner.run((PFCTL, "-a", CONTROLFORGE_ANCHOR, "-F", "all"))
            self._runner.run((PFCTL, "-X", state.pf_token))
            self._state.delete()
        except (MacOSResponseError, PfctlCommandError) as exc:
            raise MacOSResponseError("release_failed") from exc

    def _enable_pf(self) -> str:
        try:
            output = self._runner.run((PFCTL, "-E"))
        except PfctlCommandError as exc:
            raise MacOSResponseError("pf_enable_failed") from exc
        match = _TOKEN_OUTPUT.search(output)
        if match is None:
            raise MacOSResponseError("pf_token_missing")
        return match.group(1)

    def _rollback(self, token: str) -> bool:
        succeeded = True
        for arguments in (
            (PFCTL, "-a", CONTROLFORGE_ANCHOR, "-F", "all"),
            (PFCTL, "-X", token),
        ):
            try:
                self._runner.run(arguments)
            except PfctlCommandError:
                succeeded = False
        return succeeded

    def _discard_failed_state(self, token: str) -> None:
        """Remove only state written by the isolate attempt that was rolled back."""

        try:
            state = self._state.read()
            if state is not None and state.pf_token == token:
                self._state.delete()
        except MacOSResponseError:
            return

    def _preserve_failed_rollback(
        self,
        token: str,
        expiry: datetime,
        management_ips: tuple[str, ...],
    ) -> None:
        """Best-effort persistence of the token when partial rollback also fails."""

        try:
            current = self._state.read()
            if current is None:
                self._state.write(
                    MacOSPfState(
                        pf_token=token,
                        expires_at=expiry,
                        management_ips=list(management_ips),
                    )
                )
        except MacOSResponseError:
            return

    def _require_environment(self, *, allow_disabled: bool = False) -> None:
        if not self._enabled and not allow_disabled:
            raise MacOSResponseError("adapter_disabled")
        if self._system() != "Darwin":
            raise MacOSResponseError("unsupported_platform")
        if self._euid() != 0:
            raise MacOSResponseError("root_required")

    def _utc_now(self) -> datetime:
        value = self._clock()
        if value.tzinfo is None:
            raise MacOSResponseError("clock_invalid")
        return value.astimezone(timezone.utc)

    @staticmethod
    def _validated_management_ips(addresses: tuple[str, ...]) -> tuple[str, ...]:
        try:
            normalized = tuple(
                sorted({str(ipaddress.ip_address(address)) for address in addresses})
            )
        except ValueError as exc:
            raise MacOSResponseError("management_resolution_failed") from exc
        if not normalized or len(normalized) > 16:
            raise MacOSResponseError("management_resolution_failed")
        return normalized

    def _rules(self, management_ips: tuple[str, ...]) -> str:
        rules = [
            "block drop all",
            "pass quick on lo0 all",
            "pass out quick inet proto udp to any port 53 keep state",
            "pass out quick inet proto tcp to any port 53 keep state",
            "pass out quick inet6 proto udp to any port 53 keep state",
            "pass out quick inet6 proto tcp to any port 53 keep state",
        ]
        for address in management_ips:
            family = "inet" if ipaddress.ip_address(address).version == 4 else "inet6"
            rules.append(
                f"pass out quick {family} proto tcp to {address} port {self._api_port} keep state"
            )
        return "\n".join(rules) + "\n"


__all__ = [
    "CONTROLFORGE_ANCHOR",
    "PFCTL",
    "FixedHostResolver",
    "FixedPfctlRunner",
    "MacOSContainmentStatus",
    "MacOSPfResponseAdapter",
    "MacOSPfState",
    "MacOSReconciliationEvent",
    "MacOSResponseAction",
    "MacOSResponseAdapter",
    "MacOSResponseError",
    "MacOSResponseResult",
    "ManagementResolver",
    "PfStateStore",
    "PfctlCommandError",
    "PfctlRunner",
    "RootOwnedPfStateStore",
]
