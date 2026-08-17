"""Non-secret package defaults and preservation-first macOS account provisioning."""

from __future__ import annotations

import argparse
import os
from collections.abc import Callable
from pathlib import Path
from typing import Literal, Optional

from pydantic import BaseModel, ConfigDict, Field, model_validator

from .collector_agent import CollectorDefinition, MacOSSystemKeychain, load_collector_definition
from .macos_account_enrollment import (
    MacAccountEnrollment,
    MacAccountError,
    _read_owned_file,
    _trusted_directory,
    read_account_profile,
)

INSTALLER_DEFAULTS = Path("/Library/ControlForge/installer/account-server.default.json")


class AccountInstallerDefaults(BaseModel):
    """Package input never includes device IDs, usernames, grants or credentials."""

    model_config = ConfigDict(extra="forbid", frozen=True)
    schema_version: Literal["controlforge-account-installer-v1"] = (
        "controlforge-account-installer-v1"
    )
    mode: Literal["manual", "account"]
    api_host: Optional[str] = Field(default=None, min_length=1, max_length=253)
    api_port: int = Field(default=443, ge=1, le=65535, strict=True)

    @model_validator(mode="after")
    def valid_destination(self) -> AccountInstallerDefaults:
        if self.mode == "account":
            if self.api_host is None:
                raise ValueError("an account installer requires a fixed server host")
            CollectorDefinition(api_host=self.api_host, api_port=self.api_port, device_id="check")
        elif self.api_host is not None or self.api_port != 443:
            raise ValueError("manual installers must not carry an account destination")
        return self


def write_installer_defaults(path: Path, host: Optional[str], port: int = 443) -> None:
    """Build-time artifact generation; never replace an existing output file."""
    defaults = AccountInstallerDefaults(
        mode="account" if host is not None else "manual", api_host=host, api_port=port
    )
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o644)
    with os.fdopen(descriptor, "wb") as stream:
        os.fchmod(stream.fileno(), 0o644)
        stream.write(defaults.model_dump_json().encode())
        stream.flush()
        os.fsync(stream.fileno())


class MacInstallerProvisioning:
    """Apply only a signed package's fixed defaults, never a user's supplied URL."""

    def __init__(
        self,
        enrollment: Optional[MacAccountEnrollment] = None,
        *,
        defaults_path: Path = INSTALLER_DEFAULTS,
        credential_state: Optional[Callable[[], Literal["empty", "present"]]] = None,
    ) -> None:
        self.enrollment = enrollment or MacAccountEnrollment()
        self.defaults_path = defaults_path
        self._credential_state = (
            credential_state
            or MacOSSystemKeychain("com.controlforge.collector.v2").enrollment_state
        )

    def provision(self) -> dict[str, object]:
        enroller = self.enrollment
        with enroller._exclusive():
            _trusted_directory(self.defaults_path.parent, enroller.expected_uid)
            raw, _ = _read_owned_file(self.defaults_path, enroller.expected_uid, 0o644, 4096)
            defaults = AccountInstallerDefaults.model_validate_json(raw)
            if enroller.profile_path.exists() or enroller.profile_path.is_symlink():
                previous = read_account_profile(
                    enroller.profile_path, expected_uid=enroller.expected_uid
                )
                return {
                    "status": "preserved_existing_profile",
                    "matches_installer": defaults.mode == "account"
                    and previous.api_host == defaults.api_host
                    and previous.api_port == defaults.api_port,
                }
            if enroller.receipt_path.exists() or enroller.receipt_path.is_symlink():
                raise MacAccountError("an existing membership needs operator repair")
            if defaults.mode == "manual":
                return {"status": "manual_setup_required"}
            _read_owned_file(enroller.config_path, enroller.expected_uid, 0o600, 65536)
            current = load_collector_definition(enroller.config_path)
            if current.keychain_service != "com.controlforge.collector.v2":
                raise MacAccountError("the installed collector needs explicit operator migration")
            state = self._credential_state()
            if state == "present":
                return {"status": "preserved_existing_collector"}
            if state != "empty":
                raise MacAccountError("collector credential state is unavailable")
            # Rechecks emptiness under the shared account-enrollment lock. The
            # profile contains a fresh local UUID, not an ID copied from the PKG.
            if defaults.api_host is None:
                raise MacAccountError("the installer account destination is unavailable")
            enroller._configure_server(defaults.api_host, defaults.api_port)
            return {"status": "account_sign_in_ready"}


def main() -> None:
    parser = argparse.ArgumentParser(description="Build non-secret account installer defaults")
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--api-host")
    parser.add_argument("--api-port", type=int, default=443)
    args = parser.parse_args()
    try:
        write_installer_defaults(args.output, args.api_host, args.api_port)
    except (OSError, ValueError):
        parser.exit(1, "Installer defaults are invalid or the output already exists.\n")


if __name__ == "__main__":
    main()
