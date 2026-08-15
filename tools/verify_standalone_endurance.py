#!/usr/bin/env python3
"""Run bounded Standalone ingestion, restart, aggregation, and backup endurance."""

from __future__ import annotations

import argparse
import json
import sys
import tempfile
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
SOURCE_ROOT = PROJECT_ROOT / "src"
if str(SOURCE_ROOT) not in sys.path:
    sys.path.insert(0, str(SOURCE_ROOT))

from controlforge.standalone.endurance import run_standalone_endurance  # noqa: E402


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--events", type=int, default=2_000)
    parser.add_argument("--batch-size", type=int, default=100)
    parser.add_argument("--alert-every", type=int, default=50)
    parser.add_argument("--rules", type=Path, default=PROJECT_ROOT / "rules")
    parser.add_argument("--work-directory", type=Path)
    parser.add_argument("--output", type=Path)
    return parser


def main(arguments: list[str] | None = None) -> int:
    args = build_parser().parse_args(arguments)
    try:
        if args.work_directory is not None:
            report = run_standalone_endurance(
                args.work_directory.resolve(),
                args.rules.resolve(),
                event_count=args.events,
                batch_size=args.batch_size,
                alert_every=args.alert_every,
            )
        else:
            with tempfile.TemporaryDirectory(prefix="controlforge-endurance-") as temporary:
                report = run_standalone_endurance(
                    Path(temporary),
                    args.rules.resolve(),
                    event_count=args.events,
                    batch_size=args.batch_size,
                    alert_every=args.alert_every,
                )
        rendered = json.dumps(report.as_dict(), indent=2, sort_keys=True)
    except (OSError, RuntimeError, ValueError) as exc:
        rendered = json.dumps(
            {
                "schema_version": "controlforge-standalone-endurance.v1",
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
