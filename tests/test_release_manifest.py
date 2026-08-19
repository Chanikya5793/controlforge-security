from __future__ import annotations

import json
import subprocess
import sys

import pytest
from pydantic import ValidationError

from controlforge.release_manifest import (
    MacBuildIdentity,
    build_release_manifest,
    verify_release_manifest,
    write_build_identity,
)

COMMIT = "a" * 40


def identity(**overrides: object) -> MacBuildIdentity:
    values: dict[str, object] = {
        "version": "0.4.0",
        "channel": "staging",
        "source_commit": COMMIT,
        "source_dirty": True,
        "account_mode": "account",
        "account_host": "admin-staging.example.com",
    }
    values.update(overrides)
    return MacBuildIdentity(**values)


def test_build_identity_is_deterministic_nonsecret_and_write_once(tmp_path) -> None:
    path = tmp_path / "release-build.json"
    build = identity()
    write_build_identity(path, build)
    raw = path.read_bytes()
    assert raw.endswith(b"\n")
    assert json.loads(raw) == build.model_dump(mode="json")
    assert path.stat().st_mode & 0o777 == 0o644
    assert b"password" not in raw and b"credential" not in raw
    with pytest.raises(FileExistsError):
        write_build_identity(path, build)


@pytest.mark.parametrize(
    "overrides",
    [
        {"version": "0.4"},
        {"source_commit": "ABC" * 14},
        {"account_host": "https://accounts.example.com/path"},
        {"channel": "staging", "account_mode": "manual", "account_host": None},
        {"account_mode": "manual", "account_host": "accounts.example.com"},
        {"account_mode": "manual", "account_host": None, "account_port": 8443},
    ],
)
def test_build_identity_rejects_ambiguous_release_inputs(overrides) -> None:
    with pytest.raises(ValidationError):
        identity(**overrides)


def test_production_identity_requires_clean_exact_tag_and_account_host() -> None:
    with pytest.raises(ValidationError, match="clean"):
        identity(channel="production", source_tag="v0.4.0")
    with pytest.raises(ValidationError, match="exact"):
        identity(channel="production", source_dirty=False, source_tag="v0.3.0")
    production = identity(channel="production", source_dirty=False, source_tag="v0.4.0")
    assert production.account_host == "admin-staging.example.com"


def test_release_manifest_binds_package_bytes_and_production_attestation(tmp_path) -> None:
    package = tmp_path / "ControlForge-0.4.0.pkg"
    package.write_bytes(b"signed-package-fixture")
    production = identity(channel="production", source_dirty=False, source_tag="v0.4.0")
    with pytest.raises(ValidationError, match="signed and notarized"):
        build_release_manifest(
            package,
            production,
            developer_id_signed=True,
            apple_notarized=False,
        )
    manifest = build_release_manifest(
        package,
        production,
        developer_id_signed=True,
        apple_notarized=True,
    )
    path = tmp_path / "ControlForge-0.4.0.release.json"
    path.write_text(manifest.model_dump_json())
    assert verify_release_manifest(path, package) == manifest
    package.write_bytes(b"tampered")
    with pytest.raises(ValueError, match="does not match"):
        verify_release_manifest(path, package)


def test_release_manifest_cli_writes_and_verifies_staging_metadata(tmp_path) -> None:
    package = tmp_path / "ControlForge-0.4.0-unsigned.pkg"
    package.write_bytes(b"local-stage")
    manifest = tmp_path / "ControlForge-0.4.0.release.json"
    common = [
        "--version",
        "0.4.0",
        "--channel",
        "staging",
        "--source-commit",
        COMMIT,
        "--source-dirty",
        "true",
        "--api-host",
        "admin-staging.example.com",
    ]
    created = subprocess.run(  # noqa: S603 - fixed interpreter and local module
        [
            sys.executable,
            "-m",
            "controlforge.release_manifest",
            "release-manifest",
            "--output",
            str(manifest),
            "--package",
            str(package),
            "--developer-id-signed",
            "false",
            "--apple-notarized",
            "false",
            *common,
        ],
        check=False,
        capture_output=True,
        timeout=15,
    )
    assert created.returncode == 0 and manifest.exists()
    verified = subprocess.run(  # noqa: S603 - fixed interpreter and local module
        [
            sys.executable,
            "-m",
            "controlforge.release_manifest",
            "verify",
            "--manifest",
            str(manifest),
            "--package",
            str(package),
        ],
        check=False,
        capture_output=True,
        timeout=15,
    )
    assert verified.returncode == 0


def test_release_manifest_rejects_symlinked_package(tmp_path) -> None:
    package = tmp_path / "ControlForge-0.4.0.pkg"
    target = tmp_path / "real.pkg"
    target.write_bytes(b"fixture")
    package.symlink_to(target)
    with pytest.raises(ValueError, match="regular file"):
        build_release_manifest(
            package,
            identity(),
            developer_id_signed=False,
            apple_notarized=False,
        )
