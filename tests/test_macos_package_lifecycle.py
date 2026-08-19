from __future__ import annotations

import json
import platform
import plistlib
import shutil
import subprocess
from pathlib import Path

import pytest

from controlforge.macos_installer import write_installer_defaults


def test_pyinstaller_entrypoint_bundles_hardened_appliance_dispatch(
    project_root: Path,
) -> None:
    build_script = (project_root / "deployment/macos/build-pkg.sh").read_text(encoding="utf-8")
    entrypoint = (project_root / "deployment/macos/entrypoint.py").read_text(encoding="utf-8")

    assert "--collect-data controlforge" in build_script
    assert '"$package_root/Library/ControlForge/rules"' in build_script
    assert '"$project_root"/rules/*.yml' in build_script
    assert "deployment/macos/entrypoint.py" in build_script
    assert '"$script_dir/account-onboarding.swift"' in build_script
    assert "controlforge.macos_installer" in build_script
    assert "CONTROLFORGE_ACCOUNT_SERVER_HOST" in build_script
    assert "CONTROLFORGE_RELEASE_CHANNEL" in build_script
    assert "CONTROLFORGE_PYTHON" in build_script
    assert "import pydantic, PyInstaller" in build_script
    assert "/usr/bin/python3" not in build_script
    assert "Production releases require a clean source tree." in build_script
    assert "CONTROLFORGE_PRODUCTION_ACCOUNT_SERVER_HOST" in build_script
    assert '"$source_tag" != "v$version"' in build_script
    assert "controlforge.release_manifest" in build_script
    assert 'release-build.json"' in build_script
    assert 'release_manifest="$output_dir/ControlForge-${version}.release.json"' in build_script
    assert "/usr/bin/xcrun stapler validate" in build_script
    assert '"$package_root/Library/ControlForge/status/account-server.json"' not in build_script
    assert "preview_mac_account" not in build_script
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
    assert "/Library/ControlForge/bin/controlforge agent-provision-account-server" in postinstall
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
    shutil.copy2(project_root / "deployment/macos/scripts/preinstall", scripts / "preinstall")
    defaults = package_root / "Library/ControlForge/installer/account-server.default.json"
    defaults.parent.mkdir(parents=True)
    write_installer_defaults(defaults, "accounts.example.com", 8443)

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
    assert "account-server.default.json" in payload.stdout
    assert "status/account-server.json" not in payload.stdout
    assert "network-membership.json" not in payload.stdout
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
    assert (expanded / "Scripts/preinstall").read_bytes() == (scripts / "preinstall").read_bytes()
    assert json.loads(defaults.read_bytes()) == {
        "schema_version": "controlforge-account-installer-v1",
        "mode": "account",
        "api_host": "accounts.example.com",
        "api_port": 8443,
    }


def test_package_scripts_are_parseable_and_reject_another_install_volume(project_root):
    scripts = project_root / "deployment/macos/scripts"
    preinstall = (scripts / "preinstall").read_text()
    # find -perm -022 requires BOTH write bits; reject either bit instead.
    assert "-perm -020 -o -perm -002" in preinstall
    assert "-perm -022" not in preinstall
    for name in ("preinstall", "postinstall"):
        script = scripts / name
        subprocess.run(["/bin/sh", "-n", str(script)], check=True, capture_output=True)  # noqa: S603
        # Both scripts must fail before filesystem changes. Never execute an
        # installation path against the current machine in the test suite.
        result = subprocess.run(  # noqa: S603
            ["/bin/sh", str(script), "fixture.pkg", "/", "/Volumes/NotTheStartupVolume"],
            check=False,
            capture_output=True,
            timeout=5,
        )
        assert result.returncode == 1 and b"startup volume" in result.stderr
