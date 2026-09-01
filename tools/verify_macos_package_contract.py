#!/usr/bin/env python3
"""Validate the static safety contract for the macOS package sources.

This verifier is deliberately read-only. It checks the release policy and package
metadata that can be established without signing identities, notarization credentials,
installing a package, or mutating a host.
"""

from __future__ import annotations

import ast
import plistlib
import stat
import sys
from pathlib import Path
from typing import Any

PROJECT_ROOT = Path(__file__).resolve().parents[1]
MACOS_ROOT = PROJECT_ROOT / "deployment" / "macos"


class ContractError(ValueError):
    """Raised when a release-safety invariant is missing."""


def require(condition: bool, message: str) -> None:
    """Fail with one concise contract message."""
    if not condition:
        raise ContractError(message)


def read_text(path: Path) -> str:
    """Read a required UTF-8 source file."""
    require(path.is_file(), f"required file is missing: {path.relative_to(PROJECT_ROOT)}")
    return path.read_text(encoding="utf-8")


def read_plist(path: Path) -> dict[str, Any]:
    """Parse one required property list."""
    require(path.is_file(), f"required plist is missing: {path.relative_to(PROJECT_ROOT)}")
    payload = plistlib.loads(path.read_bytes())
    require(isinstance(payload, dict), f"plist root must be a dictionary: {path.name}")
    return payload


def package_version() -> str:
    """Read __version__ without importing application code."""
    init_path = PROJECT_ROOT / "src" / "controlforge" / "__init__.py"
    tree = ast.parse(read_text(init_path), filename=str(init_path))
    for node in tree.body:
        if not isinstance(node, ast.Assign):
            continue
        if not any(
            isinstance(target, ast.Name) and target.id == "__version__" for target in node.targets
        ):
            continue
        require(
            isinstance(node.value, ast.Constant) and isinstance(node.value.value, str),
            "controlforge.__version__ must be a string literal",
        )
        return node.value.value
    raise ContractError("controlforge.__version__ is missing")


def project_version() -> str:
    """Read the wheel version from the fixed ``[project]`` metadata field."""
    section = ""
    for line in read_text(PROJECT_ROOT / "pyproject.toml").splitlines():
        stripped = line.strip()
        if stripped.startswith("[") and stripped.endswith("]"):
            section = stripped
            continue
        if section != "[project]" or not stripped.startswith("version"):
            continue
        key, separator, value = stripped.partition("=")
        require(separator == "=" and key.strip() == "version", "invalid project version field")
        require(
            len(value.strip()) >= 2 and value.strip()[0] == '"' and value.strip()[-1] == '"',
            "project.version must be a double-quoted string literal",
        )
        return value.strip()[1:-1]
    raise ContractError("project.version is missing")


def require_snippets(source: str, snippets: tuple[str, ...], source_name: str) -> None:
    """Require fixed fail-closed policy markers in one source file."""
    for snippet in snippets:
        require(snippet in source, f"{source_name} is missing policy marker: {snippet}")


def verify_executable_scripts() -> None:
    """Require package scripts to stay executable and use a fixed POSIX shell."""
    paths = (
        MACOS_ROOT / "build-pkg.sh",
        MACOS_ROOT / "provision-system-keychain.sh",
        MACOS_ROOT / "scripts" / "preinstall",
        MACOS_ROOT / "scripts" / "postinstall",
    )
    for path in paths:
        source = read_text(path)
        require(source.startswith("#!/bin/sh\nset -eu\n"), f"unsafe shell preamble: {path.name}")
        require(
            bool(path.stat().st_mode & stat.S_IXUSR),
            f"package script is not executable: {path.relative_to(PROJECT_ROOT)}",
        )


def verify_package_metadata(version: str) -> None:
    """Validate the app and launchd metadata used by the package builder."""
    info = read_plist(MACOS_ROOT / "ControlForge-Info.plist")
    require(info.get("CFBundleIdentifier") == "com.controlforge.user", "unexpected app bundle ID")
    require(info.get("CFBundleExecutable") == "ControlForge", "unexpected app executable")
    require(info.get("CFBundlePackageType") == "APPL", "unexpected app package type")
    require(info.get("CFBundleShortVersionString") == version, "app and package versions differ")
    require(info.get("LSMinimumSystemVersion") == "13.0", "minimum macOS must remain 13.0")

    launchd = read_plist(MACOS_ROOT / "com.controlforge.agent.plist")
    require(launchd.get("Label") == "com.controlforge.agent", "unexpected launchd label")
    require(
        launchd.get("ProgramArguments")
        == [
            "/Library/ControlForge/bin/controlforge",
            "agent",
            "--config",
            "/Library/Application Support/ControlForge/collector.yml",
        ],
        "launchd must use the fixed collector command and configuration",
    )
    require(launchd.get("Disabled") is True, "the packaged collector must default to disabled")
    require(launchd.get("RunAtLoad") is True, "the activated collector must run at load")
    require(launchd.get("StartInterval") == 60, "the collector interval must remain bounded")

    expected_profiles = {
        "com.controlforge.santa.mobileconfig": "com.controlforge.santa",
        "com.controlforge.santa-system-extension.mobileconfig": (
            "com.controlforge.santa.system-extension"
        ),
    }
    for filename, identifier in expected_profiles.items():
        profile = read_plist(MACOS_ROOT / filename)
        require(profile.get("PayloadType") == "Configuration", f"invalid profile type: {filename}")
        require(profile.get("PayloadIdentifier") == identifier, f"invalid profile ID: {filename}")
        require(profile.get("PayloadVersion") == 1, f"invalid profile version: {filename}")


def verify_release_policy() -> None:
    """Verify the builder still fails closed for production releases."""
    build = read_text(MACOS_ROOT / "build-pkg.sh")
    require_snippets(
        build,
        (
            'case "$release_channel" in',
            "development|staging|production",
            'if [ "$release_channel" = production ]; then',
            "Production releases require CONTROLFORGE_ACCOUNT_SERVER_HOST.",
            "Production releases require an explicitly matched production account host.",
            "Production releases require a clean source tree.",
            'if [ "$source_tag" != "v$version" ]; then',
            "Production releases require Developer ID signing and notarization.",
            "--identifier com.controlforge.agent",
            "arm64-apple-macos13.0",
            "notarytool submit",
            "stapler validate",
            "spctl --assess --type install",
            "-m controlforge.release_manifest verify",
        ),
        "build-pkg.sh",
    )

    preinstall = read_text(MACOS_ROOT / "scripts" / "preinstall")
    require_snippets(
        preinstall,
        (
            '"$(/usr/bin/id -u)" != "0"',
            '"${3:-}" != "/"',
            'if [ -L "$owned_path" ]; then',
            "ControlForge installation refused an unsafe file",
        ),
        "preinstall",
    )

    postinstall = read_text(MACOS_ROOT / "scripts" / "postinstall")
    require_snippets(
        postinstall,
        (
            'if [ "${3:-}" != "/" ]; then',
            'if [ ! -e "$collector_config" ]; then',
            'if [ -L "$collector_config" ] || [ ! -f "$collector_config" ]; then',
            "agent-provision-account-server",
        ),
        "postinstall",
    )


def main() -> int:
    """Run all static package contract checks."""
    try:
        version = package_version()
        require(project_version() == version, "Python source and distribution versions differ")
        verify_executable_scripts()
        verify_package_metadata(version)
        verify_release_policy()
    except (ContractError, OSError, plistlib.InvalidFileException, SyntaxError) as exc:
        print(f"macOS package contract failed: {exc}", file=sys.stderr)
        return 1
    print(f"macOS package source contract passed for ControlForge {version}.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
