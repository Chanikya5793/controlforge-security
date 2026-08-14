"""PyInstaller entry point for the ControlForge macOS collector."""

from __future__ import annotations

import sys

from controlforge.cli import main as cli_main
from controlforge.standalone.__main__ import run as standalone_run


def main() -> None:
    """Dispatch one fixed bundled appliance namespace or the existing CLI."""
    if len(sys.argv) > 1 and sys.argv[1] == "standalone-appliance":
        raise SystemExit(standalone_run(sys.argv[2:]))
    cli_main()


if __name__ == "__main__":
    main()
