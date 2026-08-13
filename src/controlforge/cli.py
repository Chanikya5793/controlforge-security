"""Command-line interface for local control checks and event scans."""

from __future__ import annotations

import argparse
import getpass
import json
import os
import sys
from collections.abc import Sequence
from dataclasses import asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import BinaryIO, Optional

import uvicorn
from pydantic import ValidationError

from .collector_agent import (
    AgentSpool,
    CollectorDefinition,
    CollectorSecrets,
    EndpointCollectorAgent,
    MacOSSystemKeychain,
    SignedControlForgeClient,
    load_collector_definition,
)
from .config import load_control_config
from .controls import EndpointAssuranceEngine
from .detections import DetectionPipeline, load_rules
from .endpoint_enrollment import (
    EndpointEnrollmentError,
    StandaloneEndpointEnrollmentClient,
    install_collector_definition,
    standalone_collector_definition,
)
from .exposure import ExposureService, HibpClient, HibpError
from .macos_lifecycle import (
    RELEASE_CONTAINMENT_CONFIRMATION,
    UNINSTALL_CONFIRMATION,
    MacOSEndpointLifecycle,
    MacOSEndpointLifecycleError,
)
from .models import SecurityEvent
from .probes import LocalSystemProbe
from .service import DetectionService
from .standalone.backup import BackupError, StandaloneBackupService
from .standalone.database import StandaloneDatabase, StandaloneDatabaseSecurityError
from .standalone.diagnostics import StandaloneDiagnosticsService
from .standalone.identity import BootstrapError
from .standalone.runtime import (
    StandaloneRuntime,
    StandaloneRuntimeConfig,
    build_standalone_runtime,
)
from .standalone.secrets import SecretProvisioningError, StandaloneSecretBundle
from .standalone.settings import StandaloneSettings
from .store import AuditStore


def _load_events(path: Path) -> list[SecurityEvent]:
    events: list[SecurityEvent] = []
    for line_number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1):
        if not line.strip():
            continue
        try:
            events.append(SecurityEvent.model_validate_json(line))
        except ValidationError as exc:
            raise ValueError(f"{path}:{line_number}: invalid event") from exc
    return events


def _print_json(payload: object) -> None:
    if hasattr(payload, "model_dump_json"):
        print(payload.model_dump_json(indent=2))
        return
    print(json.dumps(payload, indent=2, default=str))


def _load_stdin_collector_secrets(stream: BinaryIO) -> CollectorSecrets:
    raw_secrets = stream.read(4097)
    if len(raw_secrets) > 4096:
        raise ValueError("collector credential payload exceeds 4 KB")
    try:
        parsed_secrets = json.loads(raw_secrets)
    except (json.JSONDecodeError, UnicodeDecodeError) as exc:
        raise ValueError("collector credential payload is invalid") from exc
    required_keys = {
        "credential-id",
        "credential-secret",
    }
    access_keys = {
        "access-client-id",
        "access-client-secret",
    }
    if not isinstance(parsed_secrets, dict) or set(parsed_secrets) not in (
        required_keys,
        required_keys | access_keys,
    ):
        raise ValueError("collector credential payload has invalid fields")
    credential_id = parsed_secrets["credential-id"]
    credential_secret = parsed_secrets["credential-secret"]
    access_client_id = parsed_secrets.get("access-client-id")
    access_client_secret = parsed_secrets.get("access-client-secret")
    if not isinstance(credential_id, str) or not isinstance(credential_secret, str):
        raise ValueError("collector credential payload has invalid values")
    if access_client_id is not None and not isinstance(access_client_id, str):
        raise ValueError("collector credential payload has invalid values")
    if access_client_secret is not None and not isinstance(access_client_secret, str):
        raise ValueError("collector credential payload has invalid values")
    return CollectorSecrets(
        credential_id=credential_id,
        credential_secret=credential_secret,
        access_client_id=access_client_id,
        access_client_secret=access_client_secret,
    )


def _apply_collector_access_policy(
    definition: CollectorDefinition,
    secrets: CollectorSecrets,
) -> CollectorSecrets:
    requires_access = definition.access_proxy_required
    if requires_access and (
        secrets.access_client_id is None or secrets.access_client_secret is None
    ):
        raise ValueError("collector configuration requires Cloudflare Access credentials")
    if requires_access:
        return secrets
    # A machine that previously used the hosted service may still have Access
    # entries in its Keychain. Never forward those unrelated provider secrets to
    # a standalone appliance.
    return CollectorSecrets(
        credential_id=secrets.credential_id,
        credential_secret=secrets.credential_secret,
        access_client_id=None,
        access_client_secret=None,
    )


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="controlforge",
        description="Endpoint security-control assurance and detection automation",
    )
    subcommands = parser.add_subparsers(dest="command", required=True)

    controls = subcommands.add_parser("controls", help="check configured endpoint controls")
    controls.add_argument("--config", type=Path, default=Path("config/agents.yml"))

    scan = subcommands.add_parser("scan", help="evaluate JSONL events against rules")
    scan.add_argument("--events", type=Path, required=True)
    scan.add_argument("--rules", type=Path, default=Path("rules"))
    scan.add_argument("--database", type=Path, default=Path("controlforge.db"))

    exposures = subcommands.add_parser(
        "exposures",
        help="scan a verified domain for breach and optional infostealer exposure",
    )
    exposures.add_argument("--domain", required=True)
    exposures.add_argument("--database", type=Path, default=Path("controlforge.db"))
    exposures.add_argument("--api-key-env", default="HIBP_API_KEY")
    exposures.add_argument("--include-stealer-logs", action="store_true")

    serve = subcommands.add_parser("serve", help="start the HTTP API")
    serve.add_argument("--host", default="127.0.0.1")
    serve.add_argument("--port", type=int, default=8080)

    agent = subcommands.add_parser(
        "agent", help="collect endpoint control evidence and flush signed telemetry once"
    )
    agent.add_argument("--config", type=Path, default=Path("config/collector.yml"))
    agent.add_argument("--credential-id-env", default="CONTROLFORGE_CREDENTIAL_ID")
    agent.add_argument("--credential-secret-env", default="CONTROLFORGE_CREDENTIAL_SECRET")
    agent.add_argument("--access-client-id-env", default="CONTROLFORGE_ACCESS_CLIENT_ID")
    agent.add_argument("--access-client-secret-env", default="CONTROLFORGE_ACCESS_CLIENT_SECRET")
    agent.add_argument("--credential-json-stdin", action="store_true", help=argparse.SUPPRESS)

    agent_enroll = subcommands.add_parser(
        "agent-enroll",
        help="claim a standalone enrollment code and provision this Mac",
    )
    agent_enroll.add_argument(
        "--config",
        type=Path,
        default=Path("/Library/Application Support/ControlForge/collector.yml"),
    )
    agent_enroll.add_argument("--api-host", default="localhost")
    agent_enroll.add_argument("--api-port", type=int, default=8443)
    agent_enroll.add_argument("--device-id", required=True)
    agent_enroll.add_argument("--display-name", required=True)
    agent_enroll.add_argument("--token-stdin", action="store_true", help=argparse.SUPPRESS)

    agent_activate = subcommands.add_parser(
        "agent-activate",
        help="verify first check-in and activate the installed macOS launch daemon",
    )
    agent_activate.add_argument(
        "--config",
        type=Path,
        default=Path("/Library/Application Support/ControlForge/collector.yml"),
    )

    agent_uninstall = subcommands.add_parser(
        "agent-uninstall",
        help="safely remove the installed macOS endpoint package",
    )
    agent_uninstall.add_argument(
        "--config",
        type=Path,
        default=Path("/Library/Application Support/ControlForge/collector.yml"),
    )
    agent_uninstall.add_argument(
        "--confirm",
        required=True,
        metavar=UNINSTALL_CONFIRMATION,
        help=f"required exact confirmation: {UNINSTALL_CONFIRMATION}",
    )
    agent_uninstall.add_argument(
        "--delete-spool",
        action="store_true",
        help="also delete the local telemetry spool (preserved by default)",
    )
    agent_uninstall.add_argument(
        "--delete-logs",
        action="store_true",
        help="also delete collector logs (preserved by default)",
    )

    subcommands.add_parser(
        "agent-containment-status",
        help="report the redacted local ControlForge containment posture",
    )
    agent_containment_release = subcommands.add_parser(
        "agent-containment-release",
        help="disable collector polling and release ControlForge-owned PF state",
    )
    agent_containment_release.add_argument(
        "--confirm",
        required=True,
        metavar=RELEASE_CONTAINMENT_CONFIRMATION,
        help=f"required exact confirmation: {RELEASE_CONTAINMENT_CONFIRMATION}",
    )

    standalone = subcommands.add_parser(
        "standalone",
        help="operate the cloud-independent single-node appliance",
    )
    standalone_commands = standalone.add_subparsers(
        dest="standalone_command",
        required=True,
    )

    def add_standalone_paths(command: argparse.ArgumentParser) -> None:
        command.add_argument(
            "--database",
            type=Path,
            default=Path("controlforge-standalone.db"),
        )
        command.add_argument(
            "--secrets-directory",
            type=Path,
            default=Path("controlforge-standalone-secrets"),
        )
        command.add_argument("--rules", type=Path, default=Path("rules"))
        command.add_argument("--admin-origin", default="https://localhost:8443")
        command.add_argument("--rp-id", default="localhost")

    standalone_serve = standalone_commands.add_parser(
        "serve",
        help="start the authenticated standalone admin and ingestion service",
    )
    add_standalone_paths(standalone_serve)
    standalone_serve.add_argument("--host", default="127.0.0.1")
    standalone_serve.add_argument("--port", type=int, default=8443)
    standalone_serve.add_argument("--tls-certificate", type=Path, required=True)
    standalone_serve.add_argument("--tls-private-key", type=Path, required=True)

    standalone_bootstrap = standalone_commands.add_parser(
        "bootstrap-token",
        help="print one expiring first-administrator token to this console",
    )
    add_standalone_paths(standalone_bootstrap)

    def add_backup_paths(command: argparse.ArgumentParser) -> None:
        command.add_argument(
            "--database",
            type=Path,
            default=Path("controlforge-standalone.db"),
        )
        command.add_argument(
            "--secrets-directory",
            type=Path,
            default=Path("controlforge-standalone-secrets"),
        )
        command.add_argument(
            "--backup-directory",
            type=Path,
            default=Path("controlforge-standalone-backups"),
        )
        command.add_argument("--retention-count", type=int, default=10)

    standalone_backup = standalone_commands.add_parser(
        "backup",
        help="create, verify, restore, and retain encrypted database backups",
    )
    backup_commands = standalone_backup.add_subparsers(
        dest="backup_command",
        required=True,
    )
    backup_create = backup_commands.add_parser("create", help="create one encrypted snapshot")
    add_backup_paths(backup_create)
    backup_create.add_argument("--tenant-id")

    backup_list = backup_commands.add_parser("list", help="list verified backup artifacts")
    add_backup_paths(backup_list)
    backup_list.add_argument("--limit", type=int, default=100)

    backup_verify = backup_commands.add_parser("verify", help="authenticate one backup artifact")
    add_backup_paths(backup_verify)
    backup_verify.add_argument("--file", type=Path, required=True)

    backup_restore = backup_commands.add_parser(
        "restore",
        help="verify and atomically restore while the appliance is stopped",
    )
    add_backup_paths(backup_restore)
    backup_restore.add_argument("--file", type=Path, required=True)

    backup_prune = backup_commands.add_parser(
        "prune",
        help="remove old verified backup artifacts according to retention",
    )
    add_backup_paths(backup_prune)

    standalone_diagnostics = standalone_commands.add_parser(
        "diagnostics",
        help="report bounded local database, workload, and backup health",
    )
    add_backup_paths(standalone_diagnostics)

    return parser


def _standalone_runtime(args: argparse.Namespace) -> StandaloneRuntime:
    rules_path = args.rules
    if not rules_path.exists() and rules_path == Path("rules"):
        rules_path = Path(__file__).resolve().parent / "data" / "rules"
    return build_standalone_runtime(
        StandaloneRuntimeConfig(
            settings=StandaloneSettings(database_path=args.database),
            rules_directory=rules_path,
            secret_directory=args.secrets_directory,
            admin_origin=args.admin_origin,
            rp_id=args.rp_id,
        )
    )


def _standalone_backup_service(args: argparse.Namespace) -> StandaloneBackupService:
    return StandaloneBackupService(
        StandaloneDatabase(StandaloneSettings(database_path=args.database)),
        StandaloneSecretBundle.load_existing(args.secrets_directory),
        args.backup_directory,
        retention_count=args.retention_count,
    )


def run(arguments: Optional[Sequence[str]] = None) -> int:
    args = _build_parser().parse_args(arguments)
    if args.command == "controls":
        config = load_control_config(args.config)
        report = EndpointAssuranceEngine(config.agents, LocalSystemProbe()).run()
        _print_json(report)
        return 2 if report.failed_count else 0

    if args.command == "scan":
        pipeline = DetectionPipeline(load_rules(args.rules))
        scan_result = DetectionService(pipeline, AuditStore(args.database)).process(
            _load_events(args.events)
        )
        _print_json(scan_result)
        return 1 if scan_result.alerts else 0

    if args.command == "exposures":
        api_key = os.environ.get(args.api_key_env)
        if not api_key:
            raise ValueError(f"missing HIBP API key in environment variable {args.api_key_env}")
        records = HibpClient(api_key).scan_verified_domain(
            args.domain,
            include_stealer_logs=args.include_stealer_logs,
        )
        exposure_result = ExposureService(AuditStore(args.database)).process(records)
        _print_json(exposure_result)
        return 1 if exposure_result.alerts else 0

    if args.command == "serve":
        uvicorn.run("controlforge.api:app", host=args.host, port=args.port)
        return 0

    if args.command == "agent":
        definition = load_collector_definition(args.config)
        if args.credential_json_stdin:
            secrets = _load_stdin_collector_secrets(sys.stdin.buffer)
        elif definition.credential_source == "macos_system_keychain":
            secrets = MacOSSystemKeychain(definition.keychain_service).load(
                require_access=definition.access_proxy_required
            )
        else:
            credential_id = os.environ.get(args.credential_id_env)
            credential_secret = os.environ.get(args.credential_secret_env)
            if not credential_id or not credential_secret:
                raise ValueError("collector credential environment variables are required")
            secrets = CollectorSecrets(
                credential_id=credential_id,
                credential_secret=credential_secret,
                access_client_id=os.environ.get(args.access_client_id_env),
                access_client_secret=os.environ.get(args.access_client_secret_env),
            )
        secrets = _apply_collector_access_policy(definition, secrets)
        client = SignedControlForgeClient(
            definition,
            secrets.credential_id,
            secrets.credential_secret,
            access_client_id=secrets.access_client_id,
            access_client_secret=secrets.access_client_secret,
        )
        result = EndpointCollectorAgent(
            definition,
            client,
            AgentSpool(definition.spool_path),
            credential_pair_store=(
                MacOSSystemKeychain(definition.keychain_service)
                if definition.credential_source == "macos_system_keychain"
                else None
            ),
        ).run_once()
        _print_json(result)
        return 0

    if args.command == "agent-enroll":
        current = load_collector_definition(args.config)
        definition = standalone_collector_definition(
            current,
            args.api_host,
            args.api_port,
            args.device_id,
        )
        keychain = MacOSSystemKeychain(definition.keychain_service)
        # Perform every local validation and the destructive-overwrite preflight
        # before exchanging the one-use server grant.
        keychain.require_initial_empty()
        token = (
            sys.stdin.readline(129).strip()
            if args.token_stdin
            else getpass.getpass("Standalone enrollment code: ")
        )
        # Install the non-secret config before consuming the grant so a local
        # filesystem failure cannot orphan a server-side device credential.
        install_collector_definition(args.config, definition)
        enrollment_result = StandaloneEndpointEnrollmentClient(
            definition.api_host,
            api_port=definition.api_port,
        ).claim(token, definition.device_id, args.display_name)
        # If the atomic Keychain helper unexpectedly fails, an administrator can
        # revoke the reported device and retry without any secret appearing on stdout.
        try:
            keychain.store_initial(
                enrollment_result.credential_id,
                enrollment_result.credential_secret,
            )
        except ValueError as exc:
            raise EndpointEnrollmentError(
                "local credential provisioning failed; revoke device "
                f"{enrollment_result.device_id} before retry"
            ) from exc
        try:
            activation = MacOSEndpointLifecycle(collector_config=args.config).activate()
        except MacOSEndpointLifecycleError as exc:
            raise EndpointEnrollmentError(
                "credentials were stored but endpoint activation failed; "
                "fix the local issue and run agent-activate without claiming a new code"
            ) from exc
        _print_json(
            {
                "device_id": enrollment_result.device_id,
                "expires_at": enrollment_result.expires_at,
                "configured_host": definition.api_host,
                "configured_port": definition.api_port,
                "credentials_stored": True,
                "first_check_in_verified": activation.first_check_in_verified,
                "launch_daemon_loaded": activation.launch_daemon_loaded,
            }
        )
        return 0

    if args.command == "agent-activate":
        activation = MacOSEndpointLifecycle(collector_config=args.config).activate()
        _print_json(asdict(activation))
        return 0

    if args.command == "agent-uninstall":
        uninstall_result = MacOSEndpointLifecycle(collector_config=args.config).uninstall(
            confirmation=args.confirm,
            delete_spool=args.delete_spool,
            delete_logs=args.delete_logs,
        )
        _print_json(asdict(uninstall_result))
        return 0

    if args.command == "agent-containment-status":
        _print_json(asdict(MacOSEndpointLifecycle().containment_status()))
        return 0

    if args.command == "agent-containment-release":
        recovery = MacOSEndpointLifecycle().release_containment(
            confirmation=args.confirm,
        )
        _print_json(asdict(recovery))
        return 0

    if args.command == "standalone":
        if args.standalone_command == "backup":
            backups = _standalone_backup_service(args)
            if args.backup_command == "create":
                _print_json(asdict(backups.create_backup(args.tenant_id)))
                return 0
            if args.backup_command == "list":
                _print_json([asdict(entry) for entry in backups.inventory(args.limit)])
                return 0
            if args.backup_command == "verify":
                _print_json(asdict(backups.verify_backup(args.file)))
                return 0
            if args.backup_command == "restore":
                _print_json(asdict(backups.restore_backup(args.file)))
                return 0
            if args.backup_command == "prune":
                _print_json({"removed": backups.prune(args.retention_count)})
                return 0
            raise AssertionError(f"unhandled backup command: {args.backup_command}")
        if args.standalone_command == "diagnostics":
            backups = _standalone_backup_service(args)
            database = StandaloneDatabase(StandaloneSettings(database_path=args.database))
            _print_json(StandaloneDiagnosticsService(database, backups).collect().as_dict())
            return 0
        runtime = _standalone_runtime(args)
        try:
            if args.standalone_command == "bootstrap-token":
                print(runtime.identity.issue_bootstrap_token(datetime.now(timezone.utc)))
                return 0
            if args.standalone_command == "serve":
                uvicorn.run(
                    runtime.app,
                    host=args.host,
                    port=args.port,
                    ssl_certfile=str(args.tls_certificate),
                    ssl_keyfile=str(args.tls_private_key),
                )
                return 0
        finally:
            runtime.close()
        raise AssertionError(f"unhandled standalone command: {args.standalone_command}")

    raise AssertionError(f"unhandled command: {args.command}")


def main() -> None:
    try:
        exit_code = run()
    except (
        BackupError,
        BootstrapError,
        EndpointEnrollmentError,
        HibpError,
        MacOSEndpointLifecycleError,
        OSError,
        StandaloneDatabaseSecurityError,
        SecretProvisioningError,
        ValueError,
    ) as exc:
        print(json.dumps({"error": str(exc)}), file=sys.stderr)
        exit_code = 3
    raise SystemExit(exit_code)
