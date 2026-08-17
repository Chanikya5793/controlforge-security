#!/usr/bin/env python3
"""Capture redacted, read-only evidence from a physical ControlForge Mac."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import cast

PROJECT_ROOT = Path(__file__).resolve().parents[1]
SOURCE_ROOT = PROJECT_ROOT / "src"
if str(SOURCE_ROOT) not in sys.path:
    sys.path.insert(0, str(SOURCE_ROOT))

from controlforge.macos_acceptance import (  # noqa: E402
    AcceptancePhase,
    MacOSPhysicalAcceptanceVerifier,
)
from controlforge.release_manifest import verify_release_manifest  # noqa: E402


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--phase",
        choices=("preinstall", "installed", "enrolled", "running", "uninstalled"),
        required=True,
    )
    parser.add_argument("--package", type=Path)
    parser.add_argument("--package-sha256")
    parser.add_argument("--release-manifest", type=Path)
    parser.add_argument("--output", type=Path)
    return parser


def main(arguments: list[str] | None = None) -> int:
    args = build_parser().parse_args(arguments)
    try:
        package = args.package.resolve() if args.package is not None else None
        package_sha256 = args.package_sha256
        release_evidence = None
        if args.release_manifest is not None:
            if package is None:
                raise ValueError("a release manifest requires --package")
            manifest = verify_release_manifest(args.release_manifest.resolve(), package)
            if not manifest.developer_id_signed or not manifest.apple_notarized:
                raise ValueError("physical acceptance requires a signed and notarized release")
            if package_sha256 is not None and package_sha256 != manifest.package_sha256:
                raise ValueError("the supplied package digest conflicts with the release manifest")
            package_sha256 = manifest.package_sha256
            release_evidence = {
                "schema_version": manifest.schema_version,
                "version": manifest.build.version,
                "channel": manifest.build.channel,
                "source_commit": manifest.build.source_commit,
                "source_dirty": manifest.build.source_dirty,
                "package_sha256": manifest.package_sha256,
                "account_mode": manifest.build.account_mode,
                "account_host": manifest.build.account_host,
            }
        report = MacOSPhysicalAcceptanceVerifier(
            phase=cast(AcceptancePhase, args.phase),
            package=package,
            package_sha256=package_sha256,
        ).verify()
        evidence = report.as_dict()
        if release_evidence is not None:
            evidence["release"] = release_evidence
        rendered = json.dumps(evidence, indent=2, sort_keys=True)
    except (OSError, ValueError) as exc:
        rendered = json.dumps(
            {
                "schema_version": "controlforge-macos-physical-acceptance.v1",
                "passed": False,
                "error": str(exc),
            },
            indent=2,
            sort_keys=True,
        )
        print(rendered)
        return 2
    if args.output is not None:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(f"{rendered}\n", encoding="utf-8")
    print(rendered)
    return 0 if report.passed else 1


if __name__ == "__main__":
    raise SystemExit(main())
