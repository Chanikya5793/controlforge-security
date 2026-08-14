from __future__ import annotations

import platform
import plistlib
import shutil
import subprocess
from pathlib import Path

import pytest


def test_pyinstaller_entrypoint_bundles_hardened_appliance_dispatch(
    project_root: Path,
) -> None:
    build_script = (project_root / "deployment/macos/build-pkg.sh").read_text(encoding="utf-8")
    entrypoint = (project_root / "deployment/macos/entrypoint.py").read_text(encoding="utf-8")

    assert "--collect-data controlforge" in build_script
    assert '"$package_root/Library/ControlForge/rules"' in build_script
    assert '"$project_root"/rules/*.yml' in build_script
    assert "deployment/macos/entrypoint.py" in build_script
    assert "from controlforge.standalone.__main__ import run as standalone_run" in entrypoint
    assert 'sys.argv[1] == "standalone-appliance"' in entrypoint
    assert "standalone_run(sys.argv[2:])" in entrypoint
    cli_source = (project_root / "src/controlforge/cli.py").read_text(encoding="utf-8")
    assert '"agent-containment-status"' in cli_source
    assert '"agent-containment-release"' in cli_source


def test_packaged_appliance_uses_stable_installed_rules_directory(
    project_root: Path,
) -> None:
    launcher = (project_root / "src/controlforge/standalone/__main__.py").read_text(
        encoding="utf-8"
    )
    postinstall = (project_root / "deployment/macos/scripts/postinstall").read_text(
        encoding="utf-8"
    )

    assert 'Path("/Library/ControlForge/rules")' in launcher
    assert "if INSTALLED_RULES_DIRECTORY.exists()" in launcher
    assert "/Library/ControlForge/rules/*.yml" in postinstall
    assert "/bin/chmod 644 /Library/ControlForge/rules/*.yml" in postinstall


def test_package_sources_preserve_live_config_and_ship_disabled_launchd(
    project_root: Path,
) -> None:
    build_script = (project_root / "deployment/macos/build-pkg.sh").read_text(encoding="utf-8")
    postinstall = (project_root / "deployment/macos/scripts/postinstall").read_text(
        encoding="utf-8"
    )
    launchd = plistlib.loads(
        (project_root / "deployment/macos/com.controlforge.agent.plist").read_bytes()
    )

    assert 'collector.default.yml"' in build_script
    assert '"$project_root/config/collector.yml"' in build_script
    assert '"$package_root/Library/Application Support/ControlForge/collector.yml"' not in (
        build_script
    )
    guard = 'if [ ! -e "$collector_config" ]; then'
    install = '/usr/bin/install -o root -g wheel -m 600 "$collector_default" "$collector_config"'
    assert postinstall.index(guard) < postinstall.index(install)
    assert "/bin/rm" not in postinstall
    assert launchd["Disabled"] is True
    assert launchd["RunAtLoad"] is True
    assert launchd["ProgramArguments"] == [
        "/Library/ControlForge/bin/controlforge",
        "agent",
        "--config",
        "/Library/Application Support/ControlForge/collector.yml",
    ]


def test_signed_wrapper_owns_bounded_idempotent_keychain_cleanup(project_root: Path) -> None:
    wrapper = (project_root / "deployment/macos/collector-wrapper.swift").read_text(
        encoding="utf-8"
    )

    assert 'let keychainService = "com.controlforge.collector.v2"' in wrapper
    assert 'if arguments.first == "keychain-delete-all"' in wrapper
    assert "for account in allowedAccounts.sorted()" in wrapper
    assert "if status == errSecItemNotFound" in wrapper
    assert "SecKeychainItemDelete(item)" in wrapper
    assert "geteuid() == 0" in wrapper


def test_signed_wrapper_uses_one_atomic_effective_pair_for_rotation(project_root: Path) -> None:
    wrapper = (project_root / "deployment/macos/collector-wrapper.swift").read_text(
        encoding="utf-8"
    )

    assert 'let credentialPairAccount = "credential-pair-v1"' in wrapper
    assert 'if arguments.first == "keychain-replace-pair"' in wrapper
    assert "String(data: currentIDData, encoding: .utf8) == expectedID" in wrapper
    assert "SecKeychainItemModifyAttributesAndData" in wrapper
    assert "let effectiveCredentials = effectiveCredentialPair()" in wrapper
    assert "requiredAccounts + [credentialPairAccount]" in wrapper


@pytest.mark.skipif(platform.system() != "Darwin", reason="macOS package tooling")
def test_package_archive_contains_default_not_live_config(
    project_root: Path,
    tmp_path: Path,
) -> None:
    package_root = tmp_path / "root"
    scripts = tmp_path / "scripts"
    output = tmp_path / "ControlForge-lifecycle-test.pkg"
    expanded = tmp_path / "expanded"
    default_config = package_root / "Library/Application Support/ControlForge/collector.default.yml"
    default_config.parent.mkdir(parents=True)
    default_config.write_text("api_host: standalone.example.com\n", encoding="utf-8")
    binary = package_root / "Library/ControlForge/bin/controlforge-runtime"
    binary.parent.mkdir(parents=True)
    binary.write_bytes(b"package-fixture")
    scripts.mkdir()
    shutil.copy2(project_root / "deployment/macos/scripts/postinstall", scripts / "postinstall")

    build = subprocess.run(  # noqa: S603
        [
            "/usr/bin/pkgbuild",
            "--root",
            str(package_root),
            "--scripts",
            str(scripts),
            "--identifier",
            "com.controlforge.lifecycle-test",
            "--version",
            "0.3.0",
            str(output),
        ],
        check=False,
        capture_output=True,
        text=True,
        timeout=30,
    )
    assert build.returncode == 0, build.stderr
    payload = subprocess.run(  # noqa: S603
        ["/usr/sbin/pkgutil", "--payload-files", str(output)],
        check=False,
        capture_output=True,
        text=True,
        timeout=10,
    )
    assert payload.returncode == 0, payload.stderr
    assert "collector.default.yml" in payload.stdout
    assert "collector.yml" not in payload.stdout.replace("collector.default.yml", "")

    expand = subprocess.run(  # noqa: S603
        ["/usr/sbin/pkgutil", "--expand", str(output), str(expanded)],
        check=False,
        capture_output=True,
        text=True,
        timeout=10,
    )
    assert expand.returncode == 0, expand.stderr
    archived_postinstall = (expanded / "Scripts/postinstall").read_bytes()
    assert archived_postinstall == (scripts / "postinstall").read_bytes()
