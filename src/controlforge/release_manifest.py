"""Deterministic macOS build identity and release-manifest contracts."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
from pathlib import Path
from typing import Literal, Optional

from pydantic import BaseModel, ConfigDict, Field, model_validator

from .macos_installer import AccountInstallerDefaults

_VERSION = re.compile(r"^[0-9]+\.[0-9]+\.[0-9]+$")
_COMMIT = re.compile(r"^[0-9a-f]{40}$")
_DIGEST = re.compile(r"^[0-9a-f]{64}$")
_PACKAGE = re.compile(r"^ControlForge-[0-9]+\.[0-9]+\.[0-9]+(?:-unsigned)?\.pkg$")


class MacBuildIdentity(BaseModel):
    """Non-secret identity embedded in an installed macOS package."""

    model_config = ConfigDict(extra="forbid", frozen=True)
    schema_version: Literal["controlforge-macos-build-v1"] = "controlforge-macos-build-v1"
    product: Literal["ControlForge"] = "ControlForge"
    version: str = Field(min_length=5, max_length=32)
    channel: Literal["development", "staging", "production"]
    source_commit: str = Field(min_length=40, max_length=40)
    source_tag: Optional[str] = Field(default=None, max_length=64)
    source_dirty: bool
    account_mode: Literal["manual", "account"]
    account_host: Optional[str] = Field(default=None, min_length=1, max_length=253)
    account_port: int = Field(default=443, ge=1, le=65535, strict=True)
    architectures: tuple[Literal["arm64"], ...] = ("arm64",)
    minimum_macos: Literal["13.0"] = "13.0"
    package_identifier: Literal["com.controlforge.agent"] = "com.controlforge.agent"
    app_bundle_identifier: Literal["com.controlforge.user"] = "com.controlforge.user"

    @model_validator(mode="after")
    def validate_release_identity(self) -> MacBuildIdentity:
        if _VERSION.fullmatch(self.version) is None:
            raise ValueError("release version must use three numeric components")
        if _COMMIT.fullmatch(self.source_commit) is None:
            raise ValueError("source commit must be a full lowercase Git object ID")
        if self.account_mode == "account":
            if self.account_host is None:
                raise ValueError("account builds require a fixed account host")
            AccountInstallerDefaults(
                mode="account", api_host=self.account_host, api_port=self.account_port
            )
        elif self.account_host is not None or self.account_port != 443:
            raise ValueError("manual builds cannot carry an account destination")
        if self.channel in {"staging", "production"} and self.account_mode != "account":
            raise ValueError("staging and production releases require an account host")
        if self.channel == "production":
            if self.source_dirty:
                raise ValueError("production releases require a clean source tree")
            if self.source_tag != f"v{self.version}":
                raise ValueError("production releases require the exact version tag")
        return self


class MacReleaseManifest(BaseModel):
    """Public checksum and provenance metadata for one immutable PKG."""

    model_config = ConfigDict(extra="forbid", frozen=True)
    schema_version: Literal["controlforge-macos-release-v1"] = "controlforge-macos-release-v1"
    build: MacBuildIdentity
    package_filename: str = Field(min_length=1, max_length=128)
    package_sha256: str = Field(min_length=64, max_length=64)
    package_size_bytes: int = Field(gt=0, strict=True)
    developer_id_signed: bool
    apple_notarized: bool

    @model_validator(mode="after")
    def validate_release(self) -> MacReleaseManifest:
        if _PACKAGE.fullmatch(self.package_filename) is None:
            raise ValueError("release package filename is invalid")
        if _DIGEST.fullmatch(self.package_sha256) is None:
            raise ValueError("release package digest is invalid")
        if self.build.channel == "production" and not (
            self.developer_id_signed and self.apple_notarized
        ):
            raise ValueError("production releases must be signed and notarized")
        return self


def _serialize(model: MacBuildIdentity | MacReleaseManifest) -> bytes:
    return (
        json.dumps(
            model.model_dump(mode="json"),
            ensure_ascii=True,
            separators=(",", ":"),
            sort_keys=True,
        )
        + "\n"
    ).encode()


def _write_once(path: Path, payload: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o644)
    with os.fdopen(descriptor, "wb") as stream:
        os.fchmod(stream.fileno(), 0o644)
        stream.write(payload)
        stream.flush()
        os.fsync(stream.fileno())


def write_build_identity(path: Path, identity: MacBuildIdentity) -> None:
    """Write immutable build identity without credentials or machine identity."""
    _write_once(path, _serialize(identity))


def build_release_manifest(
    package: Path,
    identity: MacBuildIdentity,
    *,
    developer_id_signed: bool,
    apple_notarized: bool,
) -> MacReleaseManifest:
    """Hash one completed package and bind it to its source/build identity."""
    if package.is_symlink() or not package.is_file():
        raise ValueError("release package must be a regular file")
    digest = hashlib.sha256()
    size = 0
    with package.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
            size += len(chunk)
    return MacReleaseManifest(
        build=identity,
        package_filename=package.name,
        package_sha256=digest.hexdigest(),
        package_size_bytes=size,
        developer_id_signed=developer_id_signed,
        apple_notarized=apple_notarized,
    )


def verify_release_manifest(manifest_path: Path, package: Path) -> MacReleaseManifest:
    """Validate metadata and prove the local package matches its public digest."""
    manifest = MacReleaseManifest.model_validate_json(manifest_path.read_bytes())
    rebuilt = build_release_manifest(
        package,
        manifest.build,
        developer_id_signed=manifest.developer_id_signed,
        apple_notarized=manifest.apple_notarized,
    )
    if rebuilt != manifest:
        raise ValueError("release package does not match its manifest")
    return manifest


def _boolean(value: str) -> bool:
    if value == "true":
        return True
    if value == "false":
        return False
    raise argparse.ArgumentTypeError("expected true or false")


def _identity_from_args(args: argparse.Namespace) -> MacBuildIdentity:
    host = args.api_host
    return MacBuildIdentity(
        version=args.version,
        channel=args.channel,
        source_commit=args.source_commit,
        source_tag=args.source_tag,
        source_dirty=args.source_dirty,
        account_mode="account" if host is not None else "manual",
        account_host=host,
        account_port=args.api_port,
    )


def _add_identity_arguments(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--version", required=True)
    parser.add_argument(
        "--channel", choices=("development", "staging", "production"), required=True
    )
    parser.add_argument("--source-commit", required=True)
    parser.add_argument("--source-tag")
    parser.add_argument("--source-dirty", type=_boolean, required=True)
    parser.add_argument("--api-host")
    parser.add_argument("--api-port", type=int, default=443)


def main() -> None:
    parser = argparse.ArgumentParser(description="Build and verify ControlForge release metadata")
    commands = parser.add_subparsers(dest="command", required=True)
    build = commands.add_parser("build-identity")
    build.add_argument("--output", type=Path, required=True)
    _add_identity_arguments(build)
    release = commands.add_parser("release-manifest")
    release.add_argument("--output", type=Path, required=True)
    release.add_argument("--package", type=Path, required=True)
    release.add_argument("--developer-id-signed", type=_boolean, required=True)
    release.add_argument("--apple-notarized", type=_boolean, required=True)
    _add_identity_arguments(release)
    verify = commands.add_parser("verify")
    verify.add_argument("--manifest", type=Path, required=True)
    verify.add_argument("--package", type=Path, required=True)
    args = parser.parse_args()
    try:
        if args.command == "build-identity":
            write_build_identity(args.output, _identity_from_args(args))
        elif args.command == "release-manifest":
            manifest = build_release_manifest(
                args.package,
                _identity_from_args(args),
                developer_id_signed=args.developer_id_signed,
                apple_notarized=args.apple_notarized,
            )
            _write_once(args.output, _serialize(manifest))
        else:
            verify_release_manifest(args.manifest, args.package)
    except (OSError, ValueError) as error:
        parser.exit(1, f"Release metadata failed validation: {error}\n")


if __name__ == "__main__":
    main()


__all__ = [
    "MacBuildIdentity",
    "MacReleaseManifest",
    "build_release_manifest",
    "verify_release_manifest",
    "write_build_identity",
]
