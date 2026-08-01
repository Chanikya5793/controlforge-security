"""Command-line interface for local control checks and event scans."""

from __future__ import annotations

import argparse
import json
import os
import sys
from collections.abc import Sequence
from pathlib import Path
from typing import Optional

import uvicorn
from pydantic import ValidationError

from .config import load_control_config
from .controls import EndpointAssuranceEngine
from .detections import DetectionPipeline, load_rules
from .exposure import ExposureService, HibpClient, HibpError
from .models import SecurityEvent
from .probes import LocalSystemProbe
from .service import DetectionService
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

    return parser


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

    raise AssertionError(f"unhandled command: {args.command}")


def main() -> None:
    try:
        exit_code = run()
    except (HibpError, OSError, ValueError) as exc:
        print(json.dumps({"error": str(exc)}), file=sys.stderr)
        exit_code = 3
    raise SystemExit(exit_code)
