from __future__ import annotations

import hashlib
import json
import os
import sqlite3
from dataclasses import replace
from datetime import timedelta
from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from test_standalone_identity import NOW, ORIGIN, FakePasskeyAdapter, complete_bootstrap

from controlforge.collector_agent import CollectorDefinition
from controlforge.endpoint_enrollment import (
    StandaloneEndpointEnrollmentClient,
    install_collector_definition,
)
from controlforge.macos_account_enrollment import MacAccountEnrollment, read_account_profile
from controlforge.macos_installer import MacInstallerProvisioning, write_installer_defaults
from controlforge.standalone.accounts import EndpointAccountService
from controlforge.standalone.api import StandaloneApiServices, create_standalone_app
from controlforge.standalone.audit import StandaloneAuditLog
from controlforge.standalone.auth import DeviceHmacAuthenticator
from controlforge.standalone.cases import StandaloneCaseService
from controlforge.standalone.database import StandaloneDatabase
from controlforge.standalone.enrollment import (
    AesGcmDeviceCredentialCipher,
    DeviceEnrollmentService,
    EnrollmentError,
)
from controlforge.standalone.identity import (
    HumanAuthorizationError,
    HumanIdentityService,
    SessionError,
)
from controlforge.standalone.ingestion import CollectorIngestionService
from controlforge.standalone.networks import NetworkError, NetworkService, normalize_domain
from controlforge.standalone.operations import StandaloneOperationsRepository
from controlforge.standalone.passwords import PasswordBusyError, PasswordError, PasswordHasher
from controlforge.standalone.presentation import StandalonePresentationRepository
from controlforge.standalone.replay import DecisionReplayService
from controlforge.standalone.retention import StandaloneRetentionService
from controlforge.standalone.settings import StandaloneSettings
from controlforge.standalone.store import StandaloneStore

PEPPER = b"test-network-account-pepper-value-001"


def test_privileged_handoff_claims_real_account_http_contract(network_setup, tmp_path):
    _, _, accounts, _, admin, alpha, _, _, client = network_setup
    root = tmp_path.resolve()
    config = root / "collector.yml"
    install_collector_definition(
        config,
        CollectorDefinition(
            api_host="old.example.com",
            device_id="old",
            keychain_service="com.controlforge.collector.v2",
        ),
    )
    stored = []

    class CredentialStore:
        def require_initial_empty(self):
            assert not stored

        def store_initial(self, credential_id, secret):
            stored.append((credential_id, secret))

    class HttpTransport:
        def claim(self, host, port, body, timeout_seconds):
            assert host == "accounts.example.com" and port == 443
            response = client.post(
                "/v1/devices/enroll", content=body, headers={"content-type": "application/json"}
            )
            return response.status_code, response.content

    service = MacAccountEnrollment(
        profile_path=root / "profile.json",
        receipt_path=root / "membership.json",
        config_path=config,
        request_directory=root,
        expected_uid=os.getuid(),
        euid=lambda: 0,
        system=lambda: "Darwin",
        credential_store=CredentialStore(),
        activate=lambda: None,
        client_factory=lambda host, **kwargs: StandaloneEndpointEnrollmentClient(
            host,
            transport=HttpTransport(),
            **kwargs,
        ),
    )
    defaults = root / "account-server.default.json"
    write_installer_defaults(defaults, "accounts.example.com")
    assert MacInstallerProvisioning(
        service, defaults_path=defaults, credential_state=lambda: "empty"
    ).provision() == {"status": "account_sign_in_ready"}
    profile = read_account_profile(service.profile_path, expected_uid=os.getuid())
    created = accounts.create_account(admin.principal, "native", "Native Test", NOW)
    login = accounts.login(str(created["username"]), str(created["initial_password"]), NOW)
    ready = accounts.change_password(
        str(login["token"]), "Swift and Python share one contract!", NOW
    )
    grant = accounts.enrollment_grant(str(ready["token"]), profile.device_id, NOW)
    payload = json.dumps(
        {
            "schema_version": "controlforge-account-enrollment-v1",
            "grant": grant["token"],
            "expected_account_id": created["account_id"],
            "expected_tenant_id": alpha["tenant_id"],
            "expected_device_id": profile.device_id,
            "display_name": "Native Test Mac",
        }
    ).encode()
    digest = hashlib.sha256(payload).hexdigest()
    request = root / f"controlforge-enroll-{os.getuid()}-{digest}.json"
    request.write_bytes(payload)
    request.chmod(0o600)
    os.utime(request, (NOW.timestamp(), NOW.timestamp()))
    result = service.enroll(os.getuid(), digest, NOW)
    assert result.account_id == created["account_id"]
    assert result.tenant_id == alpha["tenant_id"] and result.network_name == "Alpha School"
    assert len(stored) == 1
    assert stored[0][1] not in service.receipt_path.read_text()


def test_device_details_do_not_cross_network_or_endpoint_authority(network_setup):
    database, _, accounts, _, admin, alpha, beta, _, client = network_setup
    store = StandaloneStore(database)
    for network, name in [(alpha, "Alpha Mac"), (beta, "Beta private Mac")]:
        store.register_device(str(network["tenant_id"]), "shared-mac", name, "macos", NOW)
    store.register_device(str(beta["tenant_id"]), "beta-only", "Beta only", "macos", NOW)
    path = "/v1/dashboard/devices/shared-mac"
    assert client.get(path).json()["device"]["display_name"] == "Alpha Mac"
    assert client.get("/v1/dashboard/devices/beta-only").status_code == 404
    client.headers["x-network-id"] = str(beta["tenant_id"])
    assert client.get(path).json()["device"]["display_name"] == "Beta private Mac"
    client.cookies.set("controlforge_session", admin.token)
    assert client.get(path).status_code == 403
    client.headers["x-network-id"] = str(alpha["tenant_id"])
    assert client.get(path).json()["device"]["display_name"] == "Alpha Mac"
    created = accounts.create_account(admin.principal, "viewer", "Endpoint viewer", NOW)
    login = accounts.login(str(created["username"]), str(created["initial_password"]), NOW)
    client.cookies.clear()
    assert (
        client.get(path, headers={"authorization": "Bearer " + str(login["token"])}).status_code
        == 401
    )


@pytest.fixture
def network_setup(tmp_path: Path):
    return build_network_setup(tmp_path)


def build_network_setup(
    tmp_path: Path, *, ingress_mode="direct", client_address=("testclient", 50000)
):
    database = StandaloneDatabase(StandaloneSettings(database_path=tmp_path / "network.db"))
    database.initialize()
    audit = StandaloneAuditLog(database, b"a" * 32)
    identity = HumanIdentityService(database, FakePasskeyAdapter(), PEPPER, b"r" * 32, audit=audit)
    _, issue = complete_bootstrap(identity)
    networks = NetworkService(database, identity, audit, "controlforge.test")
    accounts = EndpointAccountService(networks, PEPPER)
    alpha = networks.create_network(issue.principal, "alpha", "Alpha School", NOW)
    beta = networks.create_network(issue.principal, "beta", "Beta Clinic", NOW)
    alpha_owner = networks.scope(issue.principal, str(alpha["tenant_id"]))
    invite = identity.issue_human_invite(
        alpha_owner, "admin@alpha.controlforge.test", "Alice", "admin", NOW
    )
    ceremony = identity.begin_human_invite(invite.token, NOW)
    admin_issue = identity.complete_human_invite(
        invite.token,
        ceremony.challenge_id,
        {"id": "alpha-admin", "challenge": ceremony.options["challenge"]},
        NOW,
    )
    cipher = AesGcmDeviceCredentialCipher(b"c" * 32)
    enrollment = DeviceEnrollmentService(database, cipher)
    store = StandaloneStore(database)
    app = create_standalone_app(
        StandaloneApiServices(
            identity=identity,
            ingestion=CollectorIngestionService(DeviceHmacAuthenticator(database, cipher), store),
            enrollment=enrollment,
            operations=StandaloneOperationsRepository(database),
            replay=DecisionReplayService(database, [], "test"),
            cases=StandaloneCaseService(database, identity, audit),
            retention=StandaloneRetentionService(database, identity, audit),
            presentation=StandalonePresentationRepository(database),
            networks=networks,
            accounts=accounts,
        ),
        ORIGIN,
        clock=lambda: NOW,
        ingress_mode=ingress_mode,
    )
    client = TestClient(app, base_url=ORIGIN, client=client_address)
    client.cookies.set("controlforge_session", issue.token)
    client.headers.update(
        {
            "origin": ORIGIN,
            "x-csrf-token": issue.csrf_token,
            "x-network-id": str(alpha["tenant_id"]),
        }
    )
    return database, networks, accounts, issue, admin_issue, alpha, beta, enrollment, client


def test_owner_and_network_admin_are_distinct_and_scoping_is_enforced(network_setup):
    db, networks, _, owner, admin, alpha, beta, _, client = network_setup
    assert networks.is_owner(owner.principal)
    assert not networks.is_owner(admin.principal)
    assert len(networks.list_networks(owner.principal)) == 3
    assert [row["tenant_id"] for row in networks.list_networks(admin.principal)] == [
        alpha["tenant_id"]
    ]
    scoped = networks.scope(owner.principal, str(beta["tenant_id"]))
    assert scoped.user_id == owner.principal.user_id
    with pytest.raises(HumanAuthorizationError):
        networks.scope(admin.principal, str(beta["tenant_id"]))
    with pytest.raises(HumanAuthorizationError):
        networks.create_network(admin.principal, "other", "Other", NOW)
    with pytest.raises(NetworkError):
        networks.create_network(owner.principal, "alpha", "Duplicate", NOW)
    with pytest.raises(HumanAuthorizationError):
        networks.scope(owner.principal, "missing")
    assert client.get("/v1/dashboard/summary").status_code == 200
    client.cookies.set("controlforge_session", admin.token)
    client.headers["x-csrf-token"] = admin.csrf_token
    client.headers["x-network-id"] = str(beta["tenant_id"])
    for path in ["/v1/dashboard/summary", "/v1/network/accounts", "/v1/network/password-resets"]:
        assert client.get(path).status_code == 403
    assert (
        client.post(
            "/v1/network/accounts", json={"alias": "joe", "display_name": "Joe"}
        ).status_code
        == 403
    )
    with db.connect() as connection:
        connection.execute("DELETE FROM platform_owners")
    assert not networks.is_owner(owner.principal)
    with pytest.raises(HumanAuthorizationError):
        networks.scope(owner.principal, str(alpha["tenant_id"]))


def test_owner_projections_cannot_acquire_passkey_or_recovery_identity(network_setup):
    db, _, _, owner, _, alpha, _, _, _ = network_setup
    with db.connect() as connection, pytest.raises(sqlite3.IntegrityError):
        connection.execute(
            "INSERT INTO recovery_codes(tenant_id,user_id,code_hash,created_at) VALUES(?,?,?,?)",
            (alpha["tenant_id"], owner.principal.user_id, "arbitrary", NOW.isoformat()),
        )


def test_first_login_blocks_enrollment_then_uses_existing_device_binding(network_setup):
    _, _, accounts, _, admin, alpha, _, enrollment, _ = network_setup
    created = accounts.create_account(admin.principal, "alex", "Alex", NOW)
    first = accounts.login(str(created["username"]), str(created["initial_password"]), NOW)
    token = str(first["token"])
    assert accounts.me(token, NOW)["must_change_password"]
    with pytest.raises(HumanAuthorizationError):
        accounts.enrollment_grant(token, "mac-alex", NOW)
    changed = accounts.change_password(token, "Clouds dance across the quiet sky!", NOW)
    with pytest.raises(SessionError):
        accounts.me(token, NOW)
    new_token = str(changed["token"])
    assert not accounts.me(new_token, NOW)["must_change_password"]
    grant = accounts.enrollment_grant(new_token, "mac-alex", NOW)
    with pytest.raises(EnrollmentError):
        enrollment.claim_grant(str(grant["token"]), "other-mac", "Other", "macos", NOW)
    credential = enrollment.claim_grant(str(grant["token"]), "mac-alex", "Alex's Mac", "macos", NOW)
    assert credential.tenant_id == alpha["tenant_id"]
    resumed = enrollment.claim_grant(str(grant["token"]), "mac-alex", "Alex's Mac", "macos", NOW)
    assert resumed.credential_id == credential.credential_id


def test_account_context_never_upgrades_an_admin_grant(network_setup):
    _, _, _, _, admin, alpha, _, enrollment, client = network_setup
    grant = enrollment.issue_grant(
        str(alpha["tenant_id"]), admin.principal.user_id, NOW, expected_device_id="legacy-mac"
    )
    with pytest.raises(EnrollmentError, match="context"):
        enrollment.account_context_for_grant(grant.token, NOW)
    response = client.post(
        "/v1/devices/enroll",
        json={
            "token": grant.token,
            "device_id": "legacy-mac",
            "display_name": "Legacy",
            "platform": "macos",
            "include_account_context": True,
        },
    )
    assert response.status_code == 409
    # The failed opt-in claim did not consume or change the existing grant.
    assert (
        enrollment.claim_grant(grant.token, "legacy-mac", "Legacy", "macos", NOW).tenant_id
        == alpha["tenant_id"]
    )


def test_reset_preserves_completed_setup_revokes_sessions_and_grants(network_setup):
    db, networks, accounts, _, admin, alpha, beta, enrollment, _ = network_setup
    created = accounts.create_account(admin.principal, "alex", "Alex", NOW)
    first = accounts.login(str(created["username"]), str(created["initial_password"]), NOW)
    changed = accounts.change_password(
        str(first["token"]), "A durable personal passphrase 987!", NOW
    )
    grant = accounts.enrollment_grant(str(changed["token"]), "mac-alex", NOW)
    accounts.request_reset(str(created["username"]), NOW)
    accounts.request_reset(str(created["username"]), NOW)
    accounts.request_reset("nobody@alpha.controlforge.test", NOW)
    pending = accounts.reset_requests(admin.principal)
    assert len(pending) == 1
    wrong_scope = replace(admin.principal, tenant_id=str(beta["tenant_id"]))
    with pytest.raises(HumanAuthorizationError):
        accounts.reset_password(wrong_scope, str(pending[0]["request_id"]), NOW)
    reset = accounts.reset_password(admin.principal, str(pending[0]["request_id"]), NOW)
    assert not reset["must_change_password"]
    assert accounts.reset_requests(admin.principal) == []
    with pytest.raises(NetworkError):
        accounts.reset_password(admin.principal, str(pending[0]["request_id"]), NOW)
    with pytest.raises(SessionError):
        accounts.me(str(changed["token"]), NOW)
    with pytest.raises(EnrollmentError):
        enrollment.claim_grant(str(grant["token"]), "mac-alex", "Alex", "macos", NOW)
    assert (
        accounts.login(str(reset["username"]), str(reset["password"]), NOW)["account"][
            "must_change_password"
        ]
        is False
    )
    with db.connect() as connection:
        rows = connection.execute("SELECT payload_json FROM audit_log").fetchall()
        stored = connection.execute("SELECT password_hash FROM endpoint_accounts").fetchone()[0]
    assert str(reset["password"]) not in json.dumps([list(row) for row in rows])
    assert str(reset["password"]) not in stored
    assert networks.audit.verify(str(alpha["tenant_id"])).valid


def test_expired_initial_password_and_reset_do_not_skip_first_login(network_setup):
    db, _, accounts, _, admin, _, _, _, _ = network_setup
    created = accounts.create_account(admin.principal, "alex", "Alex", NOW)
    with pytest.raises(SessionError):
        accounts.login(
            str(created["username"]), str(created["initial_password"]), NOW + timedelta(days=7)
        )
    accounts.request_reset(str(created["username"]), NOW)
    request = accounts.reset_requests(admin.principal)[0]
    reset = accounts.reset_password(admin.principal, str(request["request_id"]), NOW)
    assert reset["must_change_password"]
    with db.connect() as connection:
        connection.execute("UPDATE endpoint_accounts SET status='disabled'")
    with pytest.raises(SessionError):
        accounts.login(str(reset["username"]), str(reset["password"]), NOW)


def test_api_redacts_validation_and_endpoint_sessions_cannot_administer(network_setup):
    _, _, _, _, _, _, _, _, client = network_setup
    created = client.post("/v1/network/accounts", json={"alias": "alex", "display_name": "Alex"})
    assert created.status_code == 201
    payload = created.json()
    login = client.post(
        "/v1/endpoint/login",
        json={"username": payload["username"], "password": payload["initial_password"]},
    )
    assert login.status_code == 200
    token = login.json()["token"]
    client.cookies.clear()
    client.headers["authorization"] = "Bearer " + token
    assert client.get("/v1/endpoint/me").status_code == 200
    assert client.get("/v1/network/accounts").status_code == 401
    assert client.get("/v1/dashboard/summary").status_code == 401
    assert (
        client.post("/v1/endpoint/enrollment-grant", json={"device_id": "mac"}).status_code == 403
    )
    secret = "do-not-echo-this-plaintext-secret"  # noqa: S105 - synthetic validation fixture
    invalid = client.post("/v1/endpoint/login", json={"username": {}, "password": secret})
    assert invalid.status_code == 422
    assert secret not in invalid.text
    known = client.post("/v1/endpoint/password-reset", json={"username": payload["username"]})
    unknown = client.post("/v1/endpoint/password-reset", json={"username": "no@unknown.test"})
    assert known.status_code == unknown.status_code == 202
    assert known.json() == unknown.json()
    client.headers["origin"] = "https://evil.test"
    assert client.get("/v1/endpoint/me").status_code == 403


def test_api_requires_csrf_owner_and_reset_identity_confirmation(network_setup):
    _, _, accounts, _, admin, _, _, _, client = network_setup
    created = accounts.create_account(admin.principal, "alex", "Alex", NOW)
    accounts.request_reset(str(created["username"]), NOW)
    request_id = accounts.reset_requests(admin.principal)[0]["request_id"]
    path = f"/v1/network/password-resets/{request_id}/resolve"
    assert client.post(path, json={"identity_verified": False}).status_code == 422
    assert (
        client.post(
            path, json={"identity_verified": True}, headers={"x-csrf-token": "fake"}
        ).status_code
        == 403
    )
    assert client.post(path, json={"identity_verified": True}).status_code == 200
    assert (
        client.post("/v1/networks", json={"slug": "gamma", "display_name": "Gamma"}).status_code
        == 201
    )
    assert client.get("/v1/networks").json()["is_platform_owner"]
    client.cookies.set("controlforge_session", admin.token)
    client.headers["x-csrf-token"] = admin.csrf_token
    assert (
        client.post("/v1/networks", json={"slug": "delta", "display_name": "Delta"}).status_code
        == 403
    )


def test_public_endpoint_limits_and_password_policy(network_setup):
    _, _, _, _, _, _, _, _, client = network_setup
    for _ in range(10):
        assert (
            client.post(
                "/v1/endpoint/password-reset", json={"username": "no@unknown.test"}
            ).status_code
            == 202
        )
    assert (
        client.post("/v1/endpoint/password-reset", json={"username": "no@unknown.test"}).status_code
        == 429
    )
    hasher = PasswordHasher(PEPPER)
    with pytest.raises(PasswordError):
        hasher.hash("too-short")
    with pytest.raises(PasswordError):
        hasher.hash("a" * 20)
    assert not hasher.verify("some-password", "broken")
    assert not hasher.verify("x" * 129, "broken")
    assert not hasher.verify("some-password", "other$abcd$defg")
    assert hasher._slots.acquire(blocking=False)
    assert hasher._slots.acquire(blocking=False)
    try:
        with pytest.raises(PasswordBusyError):
            hasher.hash("A good but capacity limited password")
    finally:
        hasher._slots.release()
        hasher._slots.release()


def test_full_http_account_setup_and_grant_lifecycle(network_setup):
    db, _, _, _, _, alpha, _, _, client = network_setup
    payload = client.post(
        "/v1/network/accounts", json={"alias": "sam", "display_name": "Sam"}
    ).json()
    assert len(client.get("/v1/network/accounts").json()["accounts"]) == 1
    assert "password" not in client.get("/v1/network/accounts").text
    assert client.get("/v1/network/password-resets").json() == {"requests": []}
    client.cookies.clear()
    login = client.post(
        "/v1/endpoint/login",
        json={"username": payload["username"], "password": payload["initial_password"]},
    ).json()
    client.headers["authorization"] = "Bearer " + login["token"]
    changed = client.post(
        "/v1/endpoint/password", json={"password": "River birds circle before dusk!"}
    )
    assert changed.status_code == 200
    client.headers["authorization"] = "Bearer " + changed.json()["token"]
    assert (
        client.post(
            "/v1/endpoint/password", json={"password": "Changing again is not requested!"}
        ).status_code
        == 403
    )
    grant = client.post("/v1/endpoint/enrollment-grant", json={"device_id": "mac-sam"})
    assert grant.status_code == 201
    # The old enrollment endpoint consumes the exact-account/exact-device grant.
    enrolled = client.post(
        "/v1/devices/enroll",
        json={
            "token": grant.json()["token"],
            "device_id": "mac-sam",
            "display_name": "Sam's Mac",
            "platform": "macos",
        },
    )
    assert enrolled.status_code == 201
    assert enrolled.json()["tenant_id"] == alpha["tenant_id"]
    assert "account_id" not in enrolled.json()
    contextual = client.post(
        "/v1/devices/enroll",
        json={
            "token": grant.json()["token"],
            "device_id": "mac-sam",
            "display_name": "Sam's Mac",
            "platform": "macos",
            "include_account_context": True,
        },
    )
    assert contextual.status_code == 201
    assert contextual.json()["account_id"] == payload["account_id"]
    assert contextual.json()["network_name"] == "Alpha School"
    assert client.post("/v1/endpoint/logout").status_code == 200
    assert client.get("/v1/endpoint/me").status_code == 401
    with db.connect() as connection:
        assert connection.execute("PRAGMA foreign_key_check").fetchall() == []


def test_account_service_validation_expiry_and_revocation(network_setup):
    db, networks, accounts, owner, admin, alpha, _, enrollment, _ = network_setup
    with pytest.raises(NetworkError):
        accounts.create_account(admin.principal, "bad@other.test", "Bad", NOW)
    with pytest.raises(NetworkError):
        accounts.create_account(admin.principal, "test", "\n", NOW)
    with pytest.raises(NetworkError):
        networks.create_network(owner.principal, "admin", "Reserved", NOW)
    with pytest.raises(NetworkError):
        NetworkService(db, networks.identity, networks.audit).create_network(
            owner.principal, "new", "New", NOW
        )
    made = accounts.create_account(admin.principal, "alex", "Alex", NOW)
    with pytest.raises(NetworkError):
        accounts.create_account(admin.principal, "alex", "Duplicate", NOW)
    with pytest.raises(SessionError):
        accounts.login("alex@other.controlforge.test", str(made["initial_password"]), NOW)
    with pytest.raises(SessionError):
        accounts.login("not-a-username", "wrong", NOW)
    with pytest.raises(SessionError):
        accounts.login(str(made["username"]), "wrong", NOW)
    login = accounts.login(str(made["username"]), str(made["initial_password"]), NOW)
    token = str(login["token"])
    with pytest.raises(NetworkError):
        accounts.change_password(token, str(made["initial_password"]), NOW)
    with pytest.raises(SessionError):
        accounts.me(token, NOW + timedelta(minutes=16))
    with pytest.raises(SessionError):
        accounts.me("invalid", NOW)
    accounts.request_reset("bad-input", NOW)
    changed = accounts.change_password(token, "A change with enough words and variety!", NOW)
    with pytest.raises(NetworkError):
        accounts.enrollment_grant(str(changed["token"]), "bad/device", NOW)
    first = accounts.enrollment_grant(str(changed["token"]), "mac-1", NOW)
    second = accounts.enrollment_grant(str(changed["token"]), "mac-2", NOW)
    with pytest.raises(EnrollmentError):
        enrollment.claim_grant(str(first["token"]), "mac-1", "Mac", "macos", NOW)
    with db.connect() as connection:
        connection.execute("UPDATE endpoint_accounts SET status='disabled'")
    with pytest.raises(EnrollmentError):
        enrollment.claim_grant(str(second["token"]), "mac-2", "Mac", "macos", NOW)
    with db.connect() as connection:
        connection.execute("DELETE FROM platform_owners")
    with pytest.raises(HumanAuthorizationError):
        accounts.list_accounts(replace(owner.principal, tenant_id=str(alpha["tenant_id"])))


def test_console_nonce_and_existing_appliance_upgrade_do_not_promote_admins(network_setup):
    db, networks, _, owner, _, _, _, _, client = network_setup
    first = client.get("/console")
    second = client.get("/console")
    assert first.status_code == 200
    assert "What needs your attention?" in first.text
    assert "Password reset requests" in first.text
    assert "__CSP_NONCE__" not in first.text
    assert first.headers["content-security-policy"] != second.headers["content-security-policy"]
    assert "location.replace('/console'+" in client.get("/admin").text
    assert "location.replace('/console'+" not in client.get("/admin?investigate=1").text
    with db.connect() as connection:
        connection.execute("DELETE FROM platform_owners")
    db.initialize()
    assert not networks.is_owner(owner.principal)


def test_account_body_limit_includes_streamed_requests(network_setup):
    _, _, _, _, _, _, _, _, client = network_setup
    response = client.post("/v1/endpoint/login", content=(b"x" * 4096 for _ in range(3)))
    assert response.status_code == 413
    assert response.headers["cache-control"] == "no-store"
    assert len(response.content) < 100


@pytest.mark.parametrize(
    "domain",
    [
        "https://example.com",
        "example.com/path",
        "*.example.com",
        "localhost",
        "a..com",
        "example.com:443",
    ],
)
def test_namespace_rejects_untrusted_host_syntax(domain):
    with pytest.raises(NetworkError):
        normalize_domain(domain)
