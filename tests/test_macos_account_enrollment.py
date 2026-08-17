from __future__ import annotations

import fcntl
import hashlib
import json
import os
from datetime import datetime, timedelta, timezone

import pytest

from controlforge.collector_agent import CollectorDefinition, load_collector_definition
from controlforge.endpoint_enrollment import (
    AccountEndpointEnrollmentResult,
    install_collector_definition,
)
from controlforge.macos_account_enrollment import (
    MacAccountEnrollment,
    MacAccountError,
    read_account_profile,
    read_account_request,
)


class MemoryCredentialStore:
    def __init__(self):
        self.pair = None

    def require_initial_empty(self):
        if self.pair is not None:
            raise ValueError("existing credentials")

    def store_initial(self, identifier, secret):
        self.require_initial_empty()
        self.pair = (identifier, secret)


@pytest.fixture
def account_mac(tmp_path):
    # Resolve /var's system symlink only in the injected test root. Production
    # paths are fixed /Library paths and never resolve caller-controlled links.
    root = tmp_path.resolve()
    config = root / "collector.yml"
    install_collector_definition(
        config,
        CollectorDefinition(
            api_host="old.example.com",
            device_id="old-mac",
            keychain_service="com.controlforge.collector.v2",
        ),
    )
    store = MemoryCredentialStore()
    calls = []
    result_mutation = {}

    class Client:
        def __init__(self, host, **kwargs):
            calls.append((host, kwargs))

        def claim(self, grant, device, name):
            assert grant == "g" * 43
            calls.append((device, name))
            return AccountEndpointEnrollmentResult.model_validate(
                {
                    "tenant_id": "network-alpha",
                    "account_id": "account-alex",
                    "network_name": "Alpha School",
                    "device_id": device,
                    "credential_id": "3970e11f-f87c-4e14-9a90-d574cd2bcd95",
                    "credential_secret": "s" * 43,
                    "expires_at": datetime.now(timezone.utc) + timedelta(days=30),
                    **result_mutation,
                }
            )

    activations = []
    service = MacAccountEnrollment(
        profile_path=root / "account-server.json",
        receipt_path=root / "network-membership.json",
        config_path=config,
        request_directory=root,
        expected_uid=os.getuid(),
        euid=lambda: 0,
        system=lambda: "Darwin",
        credential_store=store,
        client_factory=Client,
        activate=lambda: activations.append(True),
    )
    profile = service.configure_server("accounts.example.com", 443)
    request = {
        "schema_version": "controlforge-account-enrollment-v1",
        "grant": "g" * 43,
        "expected_account_id": "account-alex",
        "expected_tenant_id": "network-alpha",
        "expected_device_id": profile.device_id,
        "display_name": "Alex's Mac",
    }
    data = json.dumps(request).encode()
    digest = hashlib.sha256(data).hexdigest()
    path = root / f"controlforge-enroll-{os.getuid()}-{digest}.json"
    path.write_bytes(data)
    path.chmod(0o600)
    return service, store, calls, activations, digest, path, result_mutation


def test_account_mac_claim_uses_fixed_server_and_public_receipt(account_mac):
    service, store, calls, activated, digest, _, _ = account_mac
    result = service.enroll(os.getuid(), digest, datetime.now(timezone.utc))
    assert result.activation_state == "reporting"
    assert result.network_name == "Alpha School"
    assert store.pair[1] == "s" * 43
    assert calls[0] == ("accounts.example.com", {"api_port": 443, "account_context": True})
    assert activated == [True]
    definition = load_collector_definition(service.config_path)
    assert definition.device_id == result.device_id
    assert not definition.access_proxy_required
    receipt = service.receipt_path.read_text()
    for secret in ["s" * 43, "g" * 43, "credential_secret", "password"]:
        assert secret not in receipt
    assert service.receipt_path.stat().st_mode & 0o777 == 0o644


def test_profile_is_stable_and_never_silently_migrates(account_mac):
    service, store, calls, _, _, _, _ = account_mac
    first = read_account_profile(service.profile_path, expected_uid=os.getuid())
    assert service.configure_server(first.api_host, first.api_port) == first
    with pytest.raises(MacAccountError, match="explicit migration"):
        service.configure_server("other.example.com", 443)
    store.pair = ("existing", "secret")
    with pytest.raises(ValueError, match="existing"):
        service.configure_server(first.api_host, first.api_port)
    assert calls == []


@pytest.mark.parametrize(
    "mutation", ["mode", "link", "hardlink", "digest", "old", "future", "oversize"]
)
def test_handoff_tampering_rejected_before_network_or_keychain(account_mac, mutation):
    service, store, calls, _, digest, path, _ = account_mac
    now = datetime.now(timezone.utc)
    if mutation == "mode":
        path.chmod(0o644)
    elif mutation == "link":
        target = path.with_suffix(".target")
        path.rename(target)
        path.symlink_to(target)
    elif mutation == "hardlink":
        os.link(path, path.with_suffix(".linked"))
    elif mutation == "digest":
        path.write_bytes(path.read_bytes().replace(b"Alex", b"Evil"))
    elif mutation in {"old", "future"}:
        timestamp = now.timestamp() + (-301 if mutation == "old" else 61)
        os.utime(path, (timestamp, timestamp))
    else:
        path.write_bytes(b"x" * 4097)
    with pytest.raises(MacAccountError):
        service.enroll(os.getuid(), digest, now)
    assert calls == [] and store.pair is None


@pytest.mark.parametrize("uid,digest", [(0, "a" * 64), (501, "../escape"), (501, "A" * 64)])
def test_handoff_identity_is_not_a_path(tmp_path, uid, digest):
    with pytest.raises(MacAccountError, match="identity"):
        read_account_request(uid, digest, datetime.now(timezone.utc), directory=tmp_path)


@pytest.mark.parametrize(
    "field,value",
    [
        ("account_id", "someone-else"),
        ("tenant_id", "other-network"),
        ("device_id", "other-device"),
        ("expires_at", "2020-01-01T00:00:00Z"),
    ],
)
def test_server_scope_mismatch_never_stores_credentials(account_mac, field, value):
    service, store, _, activated, digest, _, mutation = account_mac
    mutation[field] = value
    with pytest.raises(MacAccountError, match="unexpected"):
        service.enroll(os.getuid(), digest, datetime.now(timezone.utc))
    assert store.pair is None and activated == [] and not service.receipt_path.exists()


def test_activation_failure_is_resumable_without_reclaiming(account_mac):
    service, store, calls, activated, digest, _, _ = account_mac

    def fail():
        raise RuntimeError("synthetic activation failure")

    service._activate = fail
    with pytest.raises(MacAccountError, match="finish activation"):
        service.enroll(os.getuid(), digest, datetime.now(timezone.utc))
    assert store.pair is not None
    assert json.loads(service.receipt_path.read_text())["activation_state"] == "configured"
    with pytest.raises(MacAccountError, match="local account"):
        service.finish_activation(os.getuid() + 1)
    with pytest.raises(MacAccountError, match="already has"):
        service.enroll(os.getuid(), digest, datetime.now(timezone.utc))
    service._activate = lambda: activated.append(True)
    assert service.finish_activation(os.getuid()).activation_state == "reporting"
    assert len(calls) == 2 and activated == [True]
    definition = load_collector_definition(service.config_path)
    install_collector_definition(
        service.config_path, definition.model_copy(update={"device_id": "changed"})
    )
    with pytest.raises(MacAccountError, match="no longer matches"):
        service.finish_activation(os.getuid())


def test_enrollment_requires_root_and_excludes_concurrent_claims(account_mac):
    service, store, calls, _, digest, _, _ = account_mac
    service._euid = lambda: os.getuid()
    with pytest.raises(MacAccountError, match="administrator"):
        service.enroll(os.getuid(), digest, datetime.now(timezone.utc))
    service._euid = lambda: 0
    lock = service.config_path.parent / "account-enrollment.lock"
    with lock.open("rb") as stream:
        fcntl.flock(stream.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        with pytest.raises(MacAccountError, match="already running"):
            service.enroll(os.getuid(), digest, datetime.now(timezone.utc))
    assert calls == [] and store.pair is None


@pytest.mark.parametrize("tamper", ["profile", "parent", "credentials"])
def test_configuration_preflight_cannot_overwrite_or_follow_links(account_mac, tamper):
    service, store, calls, _, digest, _, _ = account_mac
    if tamper == "profile":
        service.profile_path.chmod(0o666)
    elif tamper == "parent":
        service.profile_path.parent.chmod(0o777)
    else:
        store.pair = ("existing", "secret")
    try:
        with pytest.raises((MacAccountError, ValueError)):
            service.enroll(os.getuid(), digest, datetime.now(timezone.utc))
        assert calls == []
    finally:
        service.profile_path.parent.chmod(0o700)
