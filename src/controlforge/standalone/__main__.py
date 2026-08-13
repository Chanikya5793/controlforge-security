"""Executable single-root launcher for ControlForge Standalone."""

from __future__ import annotations

import argparse
import json
import sys
from collections.abc import Callable, Sequence
from pathlib import Path
from typing import Optional

import uvicorn

from .appliance import (
    ApplianceLaunchConfig,
    AppliancePreflightError,
    StandaloneApplianceLifecycle,
)
from .backup import BackupError
from .launchd import StandaloneLaunchdError, StandaloneLaunchdService
from .secrets import SecretProvisioningError

ServerRunner = Callable[..., object]
LaunchdServiceFactory = Callable[[ApplianceLaunchConfig], StandaloneLaunchdService]
INSTALLED_RULES_DIRECTORY = Path("/Library/ControlForge/rules")


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="python -m controlforge.standalone",
        description="Provision and operate one cloud-independent ControlForge appliance.",
    )
    commands = parser.add_subparsers(dest="command", required=True)

    def add_launch_options(command: argparse.ArgumentParser) -> None:
        command.add_argument("--root", type=Path, required=True)
        command.add_argument("--rules", type=Path, default=Path("rules"))
        command.add_argument("--admin-origin", default="https://localhost:8443")
        command.add_argument("--rp-id", default="localhost")
        command.add_argument("--host", default="127.0.0.1")
        command.add_argument("--port", type=int, default=8443)
        command.add_argument("--tls-certificate", type=Path, required=True)
        command.add_argument("--tls-private-key", type=Path, required=True)

    def add_runtime_options(command: argparse.ArgumentParser) -> None:
        command.add_argument("--worker-interval-seconds", type=float, default=2.0)
        command.add_argument("--backup-retention-count", type=int, default=10)
        command.add_argument("--bootstrap-ttl-seconds", type=int, default=900)

    serve = commands.add_parser(
        "serve",
        help="provision, preflight, migrate, and serve the standalone appliance",
    )
    add_launch_options(serve)
    add_runtime_options(serve)
    serve.add_argument("--managed-service", action="store_true", help=argparse.SUPPRESS)

    service_install = commands.add_parser(
        "service-install",
        help="preflight and atomically install the root launch daemon",
    )
    add_launch_options(service_install)
    add_runtime_options(service_install)

    service_status = commands.add_parser(
        "service-status",
        help="report bounded root launch daemon status",
    )
    add_launch_options(service_status)
    add_runtime_options(service_status)

    service_uninstall = commands.add_parser(
        "service-uninstall",
        help="remove launchd registration while preserving appliance data",
    )
    add_launch_options(service_uninstall)
    add_runtime_options(service_uninstall)

    preflight = commands.add_parser(
        "preflight",
        help="validate filesystem, schema, TLS, and WebAuthn composition without migration",
    )
    add_launch_options(preflight)

    diagnostics = commands.add_parser(
        "diagnostics",
        help="report bounded startup, durability, schema, and TLS health",
    )
    add_launch_options(diagnostics)
    diagnostics.add_argument("--backup-retention-count", type=int, default=10)

    rollback = commands.add_parser(
        "rollback",
        help="restore an encrypted pre-upgrade backup while the runtime is stopped",
    )
    rollback.add_argument("--root", type=Path, required=True)
    rollback.add_argument("--file", required=True)
    return parser


def _launch_config(args: argparse.Namespace) -> ApplianceLaunchConfig:
    rules = args.rules
    packaged_rules = Path(__file__).resolve().parent.parent / "data" / "rules"
    if rules == Path("rules") and not rules.exists():
        if INSTALLED_RULES_DIRECTORY.exists():
            rules = INSTALLED_RULES_DIRECTORY
        elif packaged_rules.exists():
            rules = packaged_rules
    return ApplianceLaunchConfig(
        root=args.root,
        rules_directory=rules,
        admin_origin=args.admin_origin,
        rp_id=args.rp_id,
        host=args.host,
        port=args.port,
        tls_certificate=args.tls_certificate,
        tls_private_key=args.tls_private_key,
        worker_interval_seconds=getattr(args, "worker_interval_seconds", 2.0),
        backup_retention_count=getattr(args, "backup_retention_count", 10),
        bootstrap_ttl_seconds=getattr(args, "bootstrap_ttl_seconds", 900),
    )


def run(
    arguments: Optional[Sequence[str]] = None,
    *,
    server_runner: ServerRunner = uvicorn.run,
    launchd_service_factory: LaunchdServiceFactory = StandaloneLaunchdService,
) -> int:
    args = _parser().parse_args(arguments)
    if args.command == "rollback":
        placeholder = ApplianceLaunchConfig(
            root=args.root,
            rules_directory=Path("rules"),
            admin_origin="https://localhost:8443",
            rp_id="localhost",
            host="127.0.0.1",
            port=8443,
            tls_certificate=Path("unused-certificate"),
            tls_private_key=Path("unused-private-key"),
        )
        restored = StandaloneApplianceLifecycle(placeholder).rollback_upgrade(args.file)
        print(
            json.dumps(
                {
                    "backup_id": restored.backup_id,
                    "restored_at": restored.restored_at.isoformat(),
                    "schema_versions": restored.schema_versions,
                },
                sort_keys=True,
            )
        )
        return 0

    config = _launch_config(args)
    if args.command.startswith("service-"):
        service = launchd_service_factory(config)
        if args.command == "service-install":
            installed = service.install()
            print(json.dumps(installed.as_dict(), sort_keys=True))
            if installed.bootstrap_token is not None:
                print(
                    "ControlForge first-administrator bootstrap token "
                    f"(expires in {config.bootstrap_ttl_seconds} seconds):\n"
                    f"{installed.bootstrap_token}",
                    file=sys.stderr,
                )
            return 0
        if args.command == "service-status":
            print(json.dumps(service.status().as_dict(), sort_keys=True))
            return 0
        print(json.dumps(service.uninstall().as_dict(), sort_keys=True))
        return 0

    lifecycle = StandaloneApplianceLifecycle(config)
    if args.command == "diagnostics":
        print(json.dumps(lifecycle.health(), sort_keys=True, default=str))
        return 0
    if args.command == "preflight":
        schema, tls = lifecycle.preflight()
        print(
            json.dumps(
                {
                    "schema": {
                        "state": schema.state,
                        "applied_versions": schema.applied_versions,
                        "supported_versions": schema.supported_versions,
                        "tenant_count": schema.tenant_count,
                    },
                    "tls": {
                        "hostname": tls.hostname,
                        "certificate_subject": tls.certificate_subject,
                        "not_before": tls.not_before,
                        "not_after": tls.not_after,
                        "key_algorithm": tls.key_algorithm,
                        "identity_valid": tls.identity_valid,
                        "browser_trust_verified": tls.browser_trust_verified,
                    },
                },
                sort_keys=True,
            )
        )
        return 0

    prepared = lifecycle.prepare_runtime(issue_bootstrap_token=not args.managed_service)
    try:
        print(json.dumps(prepared.report.as_dict(), sort_keys=True, default=str))
        if prepared.bootstrap_token is not None:
            print(
                "ControlForge first-administrator bootstrap token "
                f"(expires in {config.bootstrap_ttl_seconds} seconds):\n"
                f"{prepared.bootstrap_token}",
                file=sys.stderr,
            )
        server_runner(
            prepared.runtime.app,
            host=config.host,
            port=config.port,
            ssl_certfile=str(config.tls_certificate),
            ssl_keyfile=str(config.tls_private_key),
        )
    finally:
        prepared.runtime.close()
    return 0


def main() -> None:
    try:
        exit_code = run()
    except (
        AppliancePreflightError,
        BackupError,
        OSError,
        SecretProvisioningError,
        StandaloneLaunchdError,
        ValueError,
    ) as exc:
        print(json.dumps({"error": str(exc)}), file=sys.stderr)
        exit_code = 3
    raise SystemExit(exit_code)


if __name__ == "__main__":
    main()
