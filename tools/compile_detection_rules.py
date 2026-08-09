#!/usr/bin/env python3
"""Compile canonical ControlForge YAML rules into a deterministic Cloud artifact."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Optional

PROJECT_ROOT = Path(__file__).resolve().parents[1]
SOURCE_ROOT = PROJECT_ROOT / "src"
if str(SOURCE_ROOT) not in sys.path:
    sys.path.insert(0, str(SOURCE_ROOT))

from controlforge.detections import (  # noqa: E402
    SigmaRule,
    canonical_builtin_detections,
    canonical_contract_digest,
    canonical_sigma_rule,
    canonical_stateful_correlations,
    load_rules,
    sigma_rule_digest,
)

CONTRACT_VERSION = "1.0"
DEFAULT_RULES = PROJECT_ROOT / "rules"
DEFAULT_OUTPUT = PROJECT_ROOT / "cloud" / "src" / "generated" / "rules.v1.json"


def canonical_rule_payload(rule: SigmaRule) -> dict[str, object]:
    """Return the normalized rule object whose digest is stable across YAML formatting."""

    return canonical_sigma_rule(rule)


def rule_digest(payload: dict[str, object]) -> str:
    return sigma_rule_digest(SigmaRule.model_validate(payload))


def compile_rules(directory: Path) -> str:
    compiled_rules: list[dict[str, object]] = []
    for rule in sorted(load_rules(directory), key=lambda item: (item.id.casefold(), item.id)):
        payload = canonical_rule_payload(rule)
        compiled_rules.append({**payload, "rule_digest": rule_digest(payload)})
    artifact = {
        "contract_version": CONTRACT_VERSION,
        "rules": compiled_rules,
        "builtins": [
            {**payload, "rule_digest": canonical_contract_digest(payload)}
            for payload in canonical_builtin_detections()
        ],
        "correlations": [
            {**payload, "rule_digest": canonical_contract_digest(payload)}
            for payload in canonical_stateful_correlations()
        ],
    }
    return f"{json.dumps(artifact, ensure_ascii=False, indent=2)}\n"


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--rules", type=Path, default=DEFAULT_RULES)
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    parser.add_argument(
        "--check",
        action="store_true",
        help="fail if the committed artifact is missing or stale",
    )
    return parser


def run(arguments: Optional[list[str]] = None) -> int:
    args = build_parser().parse_args(arguments)
    rendered = compile_rules(args.rules)
    if args.check:
        try:
            current = args.output.read_text(encoding="utf-8")
        except FileNotFoundError:
            print(f"generated detection artifact is missing: {args.output}", file=sys.stderr)
            return 1
        if current != rendered:
            print(
                "generated detection artifact is stale; run "
                f"{Path(__file__).name} --rules {args.rules} --output {args.output}",
                file=sys.stderr,
            )
            return 1
        return 0

    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(rendered, encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(run())
