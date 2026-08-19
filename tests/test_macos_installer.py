from __future__ import annotations

import json
import os
import platform
import subprocess
import sys

import pytest
from test_macos_account_enrollment import MemoryCredentialStore

from controlforge import cli
from controlforge.collector_agent import CollectorDefinition, MacOSSystemKeychain
from controlforge.endpoint_enrollment import install_collector_definition
from controlforge.macos_account_enrollment import (
    MacAccountEnrollment,
    MacAccountError,
    read_account_profile,
)
from controlforge.macos_installer import MacInstallerProvisioning, write_installer_defaults


@pytest.fixture
def installer_mac(tmp_path):
    root = tmp_path.resolve()
    config = root / "collector.yml"
    install_collector_definition(
        config,
        CollectorDefinition(
            api_host="existing.example.com",
            device_id="old-default",
            keychain_service="com.controlforge.collector.v2",
        ),
    )
    defaults = root / "account-server.default.json"
    write_installer_defaults(defaults, "accounts.example.com", 8443)
    store = MemoryCredentialStore()
    enroller = MacAccountEnrollment(
        profile_path=root / "account-server.json",
        receipt_path=root / "membership.json",
        config_path=config,
        expected_uid=os.getuid(),
        euid=lambda: 0,
        system=lambda: "Darwin",
        credential_store=store,
    )
    state_calls = []

    def credential_state():
        state_calls.append(True)
        return "present" if store.pair else "empty"

    provisioner = MacInstallerProvisioning(
        enroller, defaults_path=defaults, credential_state=credential_state
    )
    return provisioner, enroller, store, state_calls


def test_fresh_installer_creates_stable_local_profile_without_credentials(installer_mac):
    service, enroller, store, calls = installer_mac
    original = enroller.config_path.read_bytes()
    assert service.provision() == {"status": "account_sign_in_ready"}
    profile = read_account_profile(enroller.profile_path, expected_uid=os.getuid())
    assert profile.api_host == "accounts.example.com" and profile.api_port == 8443
    assert profile.device_id != "old-default"
    assert len(profile.device_id) == 36
    assert store.pair is None and enroller.config_path.read_bytes() == original
    assert not enroller.receipt_path.exists() and calls == [True]
    before = enroller.profile_path.read_bytes()
    assert service.provision() == {
        "status": "preserved_existing_profile",
        "matches_installer": True,
    }
    assert enroller.profile_path.read_bytes() == before and calls == [True]


def test_same_installer_does_not_clone_device_identity(installer_mac, tmp_path):
    service, first, _, _ = installer_mac
    service.provision()
    other = tmp_path.resolve() / "another-mac"
    other.mkdir()
    config = other / "collector.yml"
    install_collector_definition(
        config,
        CollectorDefinition(
            api_host="existing.example.com",
            device_id="old-default",
            keychain_service="com.controlforge.collector.v2",
        ),
    )
    second = MacAccountEnrollment(
        profile_path=other / "account-server.json",
        receipt_path=other / "membership.json",
        config_path=config,
        expected_uid=os.getuid(),
        euid=lambda: 0,
        system=lambda: "Darwin",
        credential_store=MemoryCredentialStore(),
    )
    MacInstallerProvisioning(
        second, defaults_path=service.defaults_path, credential_state=lambda: "empty"
    ).provision()
    assert (
        read_account_profile(first.profile_path, expected_uid=os.getuid()).device_id
        != read_account_profile(second.profile_path, expected_uid=os.getuid()).device_id
    )


def test_package_upgrade_preserves_profile_even_when_destination_changes(installer_mac):
    service, enroller, store, calls = installer_mac
    service.provision()
    store.pair = ("existing-id", "existing-secret")
    before = enroller.profile_path.read_bytes()
    changed = service.defaults_path.with_name("next-package.json")
    write_installer_defaults(changed, "different.example.com")
    service.defaults_path = changed
    assert service.provision() == {
        "status": "preserved_existing_profile",
        "matches_installer": False,
    }
    assert enroller.profile_path.read_bytes() == before and calls == [True]
    assert store.pair == ("existing-id", "existing-secret")


def test_existing_legacy_collector_is_never_retargeted(installer_mac):
    service, enroller, store, calls = installer_mac
    store.pair = ("existing-id", "existing-secret")
    before = enroller.config_path.read_bytes()
    assert service.provision() == {"status": "preserved_existing_collector"}
    assert not enroller.profile_path.exists()
    assert enroller.config_path.read_bytes() == before and calls == [True]


def test_manual_package_does_not_probe_keychain_or_create_a_profile(installer_mac):
    service, enroller, _, calls = installer_mac
    manual = service.defaults_path.with_name("manual.json")
    write_installer_defaults(manual, None)
    service.defaults_path = manual
    assert service.provision() == {"status": "manual_setup_required"}
    assert calls == [] and not enroller.profile_path.exists()


@pytest.mark.parametrize(
    "mutation", ["symlink", "hardlink", "mode", "oversize", "secret", "bad_host", "port_type"]
)
def test_untrusted_package_defaults_fail_before_keychain_or_profile(installer_mac, mutation):
    service, enroller, _, calls = installer_mac
    path = service.defaults_path
    if mutation == "symlink":
        other = path.with_suffix(".saved")
        path.rename(other)
        path.symlink_to(other)
    elif mutation == "hardlink":
        os.link(path, path.with_suffix(".alias"))
    elif mutation == "mode":
        path.chmod(0o666)
    elif mutation == "oversize":
        path.write_bytes(b"x" * 4097)
    else:
        values = json.loads(path.read_text())
        if mutation == "secret":
            values["password"] = "do-not-package-credentials"  # noqa: S105 - rejected test input
        elif mutation == "bad_host":
            values["api_host"] = "https://example.com/redirect"
        else:
            values["api_port"] = True
        path.write_text(json.dumps(values))
    with pytest.raises((ValueError, MacAccountError, OSError)):
        service.provision()
    assert calls == [] and not enroller.profile_path.exists()


def test_unknown_keychain_state_and_concurrent_import_fail_closed(installer_mac):
    service, enroller, store, _ = installer_mac
    service._credential_state = lambda: "unknown"
    with pytest.raises(MacAccountError, match="unavailable"):
        service.provision()

    def imported_during_check():
        store.pair = ("another-id", "another-secret")
        return "empty"

    service._credential_state = imported_during_check
    with pytest.raises(ValueError, match="existing"):
        service.provision()
    assert not enroller.profile_path.exists()


def test_missing_profile_with_existing_receipt_needs_repair(installer_mac):
    service, enroller, _, calls = installer_mac
    enroller.receipt_path.write_text("{}")
    enroller.receipt_path.chmod(0o644)
    with pytest.raises(MacAccountError, match="repair"):
        service.provision()
    assert calls == [] and not enroller.profile_path.exists()


def test_build_defaults_reject_secrets_and_never_overwrite(tmp_path):
    target = tmp_path / "defaults.json"
    for host, port in [(None, 8443), ("https://example.com", 443), ("example.com", 0)]:
        with pytest.raises(ValueError):
            write_installer_defaults(target, host, port)
    assert not target.exists()
    write_installer_defaults(target, None)
    before = target.read_bytes()
    with pytest.raises(FileExistsError):
        write_installer_defaults(target, "replacement.example.com")
    assert target.read_bytes() == before
    assert json.loads(before) == {
        "schema_version": "controlforge-account-installer-v1",
        "mode": "manual",
        "api_host": None,
        "api_port": 443,
    }


@pytest.mark.parametrize(
    "output,expected",
    [(b"empty\n", "empty"), (b"present\n", "present"), (b"unexpected secret", None)],
)
def test_keychain_enrollment_state_is_a_fixed_metadata_only_contract(monkeypatch, output, expected):
    monkeypatch.setattr("controlforge.collector_agent.platform.system", lambda: "Darwin")

    def run(args, **kwargs):
        assert args == ["/Library/ControlForge/bin/controlforge", "keychain-enrollment-state"]
        assert kwargs == {"check": True, "capture_output": True, "timeout": 5}
        return subprocess.CompletedProcess(args, 0, stdout=output)

    monkeypatch.setattr("controlforge.collector_agent.subprocess.run", run)
    keychain = MacOSSystemKeychain("com.controlforge.collector.v2")
    if expected is None:
        with pytest.raises(ValueError, match="invalid") as error:
            keychain.enrollment_state()
        assert "secret" not in str(error.value)
    else:
        assert keychain.enrollment_state() == expected


def test_keychain_failure_does_not_look_like_an_empty_mac(monkeypatch):
    monkeypatch.setattr("controlforge.collector_agent.platform.system", lambda: "Darwin")

    def run(*args, **kwargs):
        raise subprocess.CalledProcessError(74, "helper", output=b"private detail")

    monkeypatch.setattr("controlforge.collector_agent.subprocess.run", run)
    with pytest.raises(ValueError, match="unavailable") as error:
        MacOSSystemKeychain("com.controlforge.collector.v2").enrollment_state()
    assert "private" not in str(error.value)
    with pytest.raises(ValueError, match="current macOS"):
        MacOSSystemKeychain("unrelated.service").enrollment_state()


def test_installer_cli_dispatch_redacts_validation_inputs(monkeypatch, capsys):
    class Provisioner:
        def __init__(self, enrollment):
            assert isinstance(enrollment, MacAccountEnrollment)

        def provision(self):
            return {"status": "account_sign_in_ready"}

    monkeypatch.setattr(cli, "MacInstallerProvisioning", Provisioner)
    assert cli.run(["agent-provision-account-server"]) == 0
    assert json.loads(capsys.readouterr().out) == {"status": "account_sign_in_ready"}

    def broken(self):
        raise ValueError("provider-secret-do-not-print")

    monkeypatch.setattr(Provisioner, "provision", broken)
    with pytest.raises(MacAccountError) as error:
        cli.run(["agent-provision-account-server"])
    assert "provider-secret" not in str(error.value)


def test_defaults_builder_cli_generates_only_nonsecret_metadata(tmp_path):
    output = tmp_path / "built.json"
    result = subprocess.run(  # noqa: S603 - fixed local module and temporary output
        [
            sys.executable,
            "-m",
            "controlforge.macos_installer",
            "--api-host",
            "accounts.example.com",
            "--output",
            str(output),
        ],
        check=False,
        capture_output=True,
        timeout=15,
    )
    assert result.returncode == 0 and not result.stdout
    assert json.loads(output.read_bytes())["api_host"] == "accounts.example.com"


@pytest.mark.skipif(platform.system() != "Darwin", reason="native macOS wrapper")
def test_metadata_wrapper_compiles_and_denies_unprivileged_use(project_root, tmp_path):
    wrapper = tmp_path / "controlforge-wrapper"
    subprocess.run(  # noqa: S603 - compile the repository wrapper into a temporary directory
        [
            "/usr/bin/xcrun",
            "swiftc",
            "-target",
            "arm64-apple-macos13.0",
            "-framework",
            "Security",
            "-o",
            str(wrapper),
            str(project_root / "deployment/macos/collector-wrapper.swift"),
        ],
        check=True,
        capture_output=True,
        timeout=60,
    )
    if os.geteuid() != 0:
        result = subprocess.run(  # noqa: S603 - compiled wrapper must refuse non-root execution
            [str(wrapper), "keychain-enrollment-state"], check=False, capture_output=True, timeout=5
        )
        assert result.returncode == 77 and result.stdout == b""
