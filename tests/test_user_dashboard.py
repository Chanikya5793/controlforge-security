import platform
import subprocess
from pathlib import Path

import pytest


@pytest.mark.skipif(platform.system() != "Darwin", reason="macOS SwiftUI contract")
def test_native_user_dashboard_strict_redacted_contract(
    project_root: Path,
    tmp_path: Path,
) -> None:
    binary = tmp_path / "user-dashboard-contract"
    compile_result = subprocess.run(  # noqa: S603
        [
            "/usr/bin/xcrun",
            "swiftc",
            "-D",
            "CONTROLFORGE_CONTRACT_TEST",
            "-parse-as-library",
            "-target",
            "arm64-apple-macos13.0",
            "-framework",
            "SwiftUI",
            "-framework",
            "AppKit",
            str(project_root / "deployment/macos/user-dashboard.swift"),
            str(project_root / "tests/fixtures/user_dashboard_contract.swift"),
            "-o",
            str(binary),
        ],
        check=False,
        capture_output=True,
        text=True,
        timeout=60,
    )
    assert compile_result.returncode == 0, compile_result.stderr

    contract_result = subprocess.run(  # noqa: S603
        [str(binary)],
        check=False,
        capture_output=True,
        text=True,
        timeout=10,
    )
    assert contract_result.returncode == 0, contract_result.stderr
