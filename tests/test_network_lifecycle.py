from __future__ import annotations

import json
import os
from dataclasses import replace
from datetime import timedelta

import pytest
from test_network_accounts import network_setup as make_network_setup
from test_standalone_identity import NOW, FakePasskeyAdapter, complete_bootstrap
from test_standalone_response import signed_request

from controlforge import cli
from controlforge.standalone.audit import StandaloneAuditLog
from controlforge.standalone.auth import CollectorAuthenticationError, DeviceHmacAuthenticator
from controlforge.standalone.backup import ApplianceOperationLock
from controlforge.standalone.database import StandaloneDatabase
from controlforge.standalone.enrollment import AesGcmDeviceCredentialCipher, EnrollmentError
from controlforge.standalone.identity import (
    ChallengeError,
    HumanAuthorizationError,
    HumanIdentityService,
    HumanInviteError,
    SessionError,
)
from controlforge.standalone.network_lifecycle import NetworkLifecycleService
from controlforge.standalone.networks import NetworkConflictError, NetworkError
from controlforge.standalone.ownership import (
    OWNER_CONFIRMATION,
    OwnerSetupError,
    PlatformOwnerSetup,
)
from controlforge.standalone.response import StandaloneResponseService
from controlforge.standalone.secrets import StandaloneSecretBundle
from controlforge.standalone.settings import StandaloneSettings


@pytest.fixture
def network_setup(tmp_path):
    return make_network_setup.__wrapped__(tmp_path)


def ready_account(accounts, admin, alias="alex"):
    created = accounts.create_account(admin.principal, alias, alias.title(), NOW)
    signed = accounts.login(str(created["username"]), str(created["initial_password"]), NOW)
    changed = accounts.change_password(
        str(signed["token"]), "Sunny mountains above quiet water!", NOW
    )
    return created, changed


def test_network_configuration_namespace_revision_and_scope(network_setup):
    db, networks, _, owner, admin, alpha, beta, _, client = network_setup
    service = NetworkLifecycleService(networks)
    result = service.adopt_namespace(
        owner.principal, owner.principal.tenant_id, "headquarters", 1, NOW
    )
    assert result["routing_status"] == "namespace_only"
    assert result["login_domain"] == "headquarters.controlforge.test"
    assert result["revision"] == 2
    with pytest.raises(NetworkConflictError):
        service.adopt_namespace(owner.principal, owner.principal.tenant_id, "new", 2, NOW)
    result = service.update_network(
        owner.principal, str(alpha["tenant_id"]), "Alpha Design", "active", 1, NOW
    )
    assert result["revision"] == 2
    with pytest.raises(NetworkConflictError):
        service.update_network(
            owner.principal, str(alpha["tenant_id"]), "Old tab", "suspended", 1, NOW
        )
    with pytest.raises(NetworkError, match="home network"):
        service.update_network(
            owner.principal, owner.principal.tenant_id, "Owner", "suspended", 2, NOW
        )
    with pytest.raises(HumanAuthorizationError):
        service.update_network(admin.principal, str(beta["tenant_id"]), "Wrong", "active", 1, NOW)
    with pytest.raises(HumanAuthorizationError):
        service.adopt_namespace(admin.principal, owner.principal.tenant_id, "test", 2, NOW)
    with db.connect() as connection:
        assert (
            connection.execute(
                "SELECT slug FROM tenants WHERE tenant_id=?", (alpha["tenant_id"],)
            ).fetchone()[0]
            == "alpha"
        )
    client.cookies.set("controlforge_session", admin.token)
    client.headers["x-csrf-token"] = admin.csrf_token
    assert (
        client.post(
            f"/v1/networks/{alpha['tenant_id']}/configure",
            json={
                "display_name": "Escalated",
                "status": "active",
                "revision": 2,
                "confirmed": True,
            },
        ).status_code
        == 403
    )
    assert networks.audit.verify(str(alpha["tenant_id"])).valid


def test_pause_resume_revokes_pending_authority_without_erasing_devices(network_setup):
    db, networks, accounts, owner, admin, alpha, _, enrollment, client = network_setup
    service = NetworkLifecycleService(networks)
    created, signed = ready_account(accounts, admin)
    grant = accounts.enrollment_grant(str(signed["token"]), "mac-alex", NOW)
    credential = enrollment.claim_grant(str(grant["token"]), "mac-alex", "Alex Mac", "macos", NOW)
    spare = accounts.enrollment_grant(str(signed["token"]), "mac-spare", NOW)
    invite = networks.identity.issue_human_invite(
        admin.principal, "new@alpha.test", "New", "admin", NOW
    )
    ceremony = networks.identity.begin_human_invite(invite.token, NOW)
    authentication = networks.identity.begin_authentication("alpha", admin.principal.email, NOW)
    paused = service.update_network(
        owner.principal, str(alpha["tenant_id"]), "Alpha School", "suspended", 1, NOW
    )
    with pytest.raises(SessionError):
        accounts.me(str(signed["token"]), NOW)
    with pytest.raises(SessionError):
        networks.identity.authenticate_session(admin.token, NOW)
    with pytest.raises(HumanAuthorizationError):
        networks.scope(owner.principal, str(alpha["tenant_id"]))
    with pytest.raises(EnrollmentError):
        enrollment.claim_grant(str(spare["token"]), "mac-spare", "Spare", "macos", NOW)
    with pytest.raises(HumanInviteError):
        networks.identity.complete_human_invite(
            invite.token,
            ceremony.challenge_id,
            {"id": "new-key", "challenge": ceremony.options["challenge"]},
            NOW,
        )
    resumed = service.update_network(
        owner.principal,
        str(alpha["tenant_id"]),
        "Alpha School",
        "active",
        int(paused["revision"]),
        NOW,
    )
    assert resumed["revision"] == 3
    with pytest.raises(SessionError):
        networks.identity.authenticate_session(admin.token, NOW)
    with pytest.raises(ChallengeError):
        networks.identity.complete_authentication(
            authentication.challenge_id,
            {"id": "alpha-admin", "challenge": authentication.options["challenge"]},
            NOW,
        )
    with pytest.raises(HumanInviteError):
        networks.identity.begin_human_invite(invite.token, NOW)
    with db.connect() as connection:
        row = connection.execute(
            "SELECT revoked_at FROM device_credentials WHERE credential_id=?",
            (credential.credential_id,),
        ).fetchone()
        assert row[0] is None
        assert (
            connection.execute(
                "SELECT status FROM endpoint_accounts WHERE account_id=?", (created["account_id"],)
            ).fetchone()[0]
            == "active"
        )
    assert accounts.login(str(created["username"]), "Sunny mountains above quiet water!", NOW)[
        "token"
    ]
    assert client.get("/v1/network/accounts").status_code == 200  # owner's home session survives


def test_team_disable_revokes_old_authority_and_invitations(network_setup):
    _, networks, accounts, owner, admin, alpha, beta, enrollment, _ = network_setup
    service = NetworkLifecycleService(networks)
    scoped = networks.scope(owner.principal, str(alpha["tenant_id"]))
    invite = networks.identity.issue_human_invite(
        admin.principal, "another@alpha.test", "Another", "admin", NOW
    )
    grant = enrollment.issue_grant(
        str(alpha["tenant_id"]), admin.principal.user_id, NOW, expected_device_id="future"
    )
    result = service.update_member(
        scoped, admin.principal.user_id, "viewer", "disabled", "admin", "active", 1, NOW
    )
    assert result["revision"] == 2
    with pytest.raises(SessionError):
        networks.identity.authenticate_session(admin.token, NOW)
    for operation in [
        lambda: accounts.create_account(admin.principal, "forbidden", "Forbidden", NOW),
        lambda: networks.identity.issue_human_invite(
            admin.principal, "forbidden@alpha.test", "Forbidden", "admin", NOW
        ),
        lambda: service.team(admin.principal, NOW),
    ]:
        with pytest.raises(HumanAuthorizationError):
            operation()
    with pytest.raises(HumanInviteError):
        networks.identity.begin_human_invite(invite.token, NOW)
    with pytest.raises(EnrollmentError):
        enrollment.claim_grant(grant.token, "future", "Future", "macos", NOW)
    service.update_member(
        scoped, admin.principal.user_id, "admin", "active", "viewer", "disabled", 2, NOW
    )
    with pytest.raises(NetworkConflictError):
        service.update_member(
            scoped, admin.principal.user_id, "viewer", "disabled", "admin", "active", 1, NOW
        )
    with pytest.raises(SessionError):
        networks.identity.authenticate_session(admin.token, NOW)
    assert service.team(scoped, NOW)["invitations"] == []
    with pytest.raises(NetworkError):
        service.update_member(
            scoped, owner.principal.user_id, "viewer", "disabled", "admin", "active", 1, NOW
        )
    with pytest.raises(NetworkError):
        service.update_member(
            networks.scope(owner.principal, str(beta["tenant_id"])),
            admin.principal.user_id,
            "viewer",
            "disabled",
            "admin",
            "active",
            1,
            NOW,
        )
    assert networks.audit.verify(str(alpha["tenant_id"])).valid


def test_account_disable_and_reenable_keep_collectors_but_not_sessions(network_setup):
    db, networks, accounts, _, admin, _, beta, enrollment, _ = network_setup
    service = NetworkLifecycleService(networks)
    created, signed = ready_account(accounts, admin)
    grant = accounts.enrollment_grant(str(signed["token"]), "mac", NOW)
    credential = enrollment.claim_grant(str(grant["token"]), "mac", "Mac", "macos", NOW)
    accounts.request_reset(str(created["username"]), NOW)
    updated = service.update_account(
        admin.principal, str(created["account_id"]), "Alex Renamed", "disabled", 1, NOW
    )
    assert updated["revision"] == 2 and accounts.reset_requests(admin.principal) == []
    with pytest.raises(SessionError):
        accounts.me(str(signed["token"]), NOW)
    with pytest.raises(SessionError):
        accounts.login(str(created["username"]), "Sunny mountains above quiet water!", NOW)
    with pytest.raises(EnrollmentError):
        enrollment.claim_grant(str(grant["token"]), "mac", "Mac", "macos", NOW)
    with pytest.raises(HumanAuthorizationError):
        service.update_account(
            replace(admin.principal, tenant_id=str(beta["tenant_id"])),
            str(created["account_id"]),
            "Wrong",
            "active",
            2,
            NOW,
        )
    service.update_account(
        admin.principal, str(created["account_id"]), "Alex Renamed", "active", 2, NOW
    )
    with pytest.raises(NetworkConflictError):
        service.update_account(
            admin.principal, str(created["account_id"]), "Old", "disabled", 1, NOW
        )
    with db.connect() as connection:
        assert (
            connection.execute(
                "SELECT revoked_at FROM device_credentials WHERE credential_id=?",
                (credential.credential_id,),
            ).fetchone()[0]
            is None
        )
    assert not accounts.login(str(created["username"]), "Sunny mountains above quiet water!", NOW)[
        "account"
    ]["must_change_password"]
    assert accounts.list_accounts(admin.principal)[0]["revision"] == 3


def test_management_http_confirmations_csrf_and_endpoint_denial(network_setup):
    _, _, accounts, _, admin, alpha, _, _, client = network_setup
    account, issue = ready_account(accounts, admin)
    path = f"/v1/network/accounts/{account['account_id']}/configure"
    body = {"display_name": "Alex", "status": "disabled", "revision": 1, "confirmed": True}
    assert (
        client.post(path, json={k: v for k, v in body.items() if k != "confirmed"}).status_code
        == 422
    )
    assert client.post(path, json=body, headers={"origin": "https://evil.test"}).status_code == 403
    assert client.post(path, json=body, headers={"x-csrf-token": "invalid"}).status_code == 403
    assert client.get("/v1/network/team").status_code == 200
    assert client.post(path, json=body).status_code == 200
    assert client.post(path, json=body).status_code == 409
    client.cookies.clear()
    client.headers["authorization"] = "Bearer " + str(issue["token"])
    assert client.get("/v1/network/team").status_code == 401
    assert client.post(path, json=body).status_code == 401
    assert (
        client.post(
            f"/v1/networks/{alpha['tenant_id']}/configure",
            json={
                "display_name": "Alpha",
                "status": "suspended",
                "revision": 1,
                "confirmed": True,
            },
        ).status_code
        == 401
    )


@pytest.fixture
def legacy_owner(tmp_path):
    root = tmp_path.resolve()
    db = StandaloneDatabase(StandaloneSettings(database_path=root / "legacy.db"))
    db.initialize()
    bundle = StandaloneSecretBundle.load_or_create(root / "secrets")
    audit = StandaloneAuditLog(db, bundle.audit_key)
    identity = HumanIdentityService(
        db, FakePasskeyAdapter(), bundle.session_pepper, bundle.recovery_pepper, audit=audit
    )
    _, issue = complete_bootstrap(identity)
    with db.connect() as connection:
        connection.execute("BEGIN IMMEDIATE")
        connection.execute("DELETE FROM platform_owners")
        connection.execute(
            "INSERT INTO tenants VALUES('legacy-other','other','Other network','active',?)",
            (NOW.isoformat(),),
        )
        audit.append(
            connection,
            issue.principal.tenant_id,
            "fixture.existing_history",
            "user",
            issue.principal.user_id,
            "network",
            issue.principal.tenant_id,
            {},
            NOW,
        )
        connection.commit()
    return db, identity, audit, issue, root


def test_offline_owner_adoption_is_explicit_atomic_and_nontransferring(legacy_owner):
    db, identity, audit, issue, _ = legacy_owner
    setup = PlatformOwnerSetup(db, audit)
    assert setup.status()["owner"] is None
    assert len(setup.status()["candidates"]) == 1
    with pytest.raises(OwnerSetupError, match="confirm"):
        setup.designate(issue.principal.tenant_id, issue.principal.user_id, "yes", NOW)
    with (
        ApplianceOperationLock(db.settings.database_path).shared(),
        pytest.raises(OwnerSetupError, match="stop"),
    ):
        setup.designate(issue.principal.tenant_id, issue.principal.user_id, OWNER_CONFIRMATION, NOW)
    result = setup.designate(
        issue.principal.tenant_id, issue.principal.user_id, OWNER_CONFIRMATION, NOW
    )
    assert result["sign_in_again"] and result["networks"] == 2
    with pytest.raises(SessionError):
        identity.authenticate_session(issue.token, NOW)
    with db.connect() as connection:
        assert connection.execute("SELECT COUNT(*) FROM owner_memberships").fetchone()[0] == 1
        assert (
            connection.execute(
                "SELECT COUNT(*) FROM passkey_credentials WHERE tenant_id='legacy-other'"
            ).fetchone()[0]
            == 0
        )
        assert connection.execute("PRAGMA foreign_key_check").fetchall() == []
    assert audit.verify("legacy-other").valid
    assert (
        setup.designate(
            issue.principal.tenant_id, issue.principal.user_id, OWNER_CONFIRMATION, NOW
        )["status"]
        == "already_designated"
    )
    with pytest.raises(OwnerSetupError, match="owner-transfer"):
        setup.designate("legacy-other", "someone", OWNER_CONFIRMATION, NOW)


def test_owner_adoption_conflict_rolls_back_and_bad_key_fails_closed(legacy_owner):
    db, _, audit, issue, _ = legacy_owner
    with db.connect() as connection:
        connection.execute(
            """INSERT INTO users(tenant_id,user_id,email,display_name,role,status,created_at)
               VALUES('legacy-other','existing',?,'Existing','admin','active',?)""",
            (issue.principal.email, NOW.isoformat()),
        )
    with pytest.raises(OwnerSetupError, match="conflicts"):
        PlatformOwnerSetup(db, audit).designate(
            issue.principal.tenant_id, issue.principal.user_id, OWNER_CONFIRMATION, NOW
        )
    with db.connect() as connection:
        assert connection.execute("SELECT COUNT(*) FROM platform_owners").fetchone()[0] == 0
        assert connection.execute("SELECT COUNT(*) FROM owner_memberships").fetchone()[0] == 0
    with pytest.raises(OwnerSetupError, match="audit key"):
        PlatformOwnerSetup(db, StandaloneAuditLog(db, b"wrong" * 8)).designate(
            issue.principal.tenant_id, issue.principal.user_id, OWNER_CONFIRMATION, NOW
        )


def test_owner_cli_uses_existing_secrets_and_never_bootstraps_runtime(legacy_owner, capsys):
    db, _, _, issue, root = legacy_owner
    args = [
        "--database",
        str(db.settings.database_path),
        "--secrets-directory",
        str(root / "secrets"),
    ]
    assert cli.run(["standalone", "owner", "status", *args]) == 0
    assert json.loads(capsys.readouterr().out)["owner"] is None
    assert (
        cli.run(
            [
                "standalone",
                "owner",
                "designate",
                *args,
                "--tenant-id",
                issue.principal.tenant_id,
                "--user-id",
                issue.principal.user_id,
                "--confirm",
                OWNER_CONFIRMATION,
            ]
        )
        == 0
    )
    assert json.loads(capsys.readouterr().out)["status"] == "designated"


def test_management_rejects_expired_or_revoked_owner_principal(network_setup):
    db, networks, _, owner, _, alpha, _, _, _ = network_setup
    service = NetworkLifecycleService(networks)
    with pytest.raises(HumanAuthorizationError):
        service.update_network(
            owner.principal, str(alpha["tenant_id"]), "No", "active", 1, NOW + timedelta(days=1)
        )
    with db.connect() as connection:
        connection.execute("DELETE FROM platform_owners")
    with pytest.raises(HumanAuthorizationError):
        service.update_network(owner.principal, str(alpha["tenant_id"]), "No", "active", 1, NOW)


@pytest.mark.parametrize("change", ["pause_network", "disable_admin"])
def test_authority_changes_cancel_undelivered_responses_only(network_setup, change):
    db, networks, _, owner, admin, alpha, _, enrollment, _ = network_setup
    tenant_id = str(alpha["tenant_id"])
    scoped = networks.scope(owner.principal, tenant_id)
    auth = DeviceHmacAuthenticator(db, AesGcmDeviceCredentialCipher(b"c" * 32))
    responses = StandaloneResponseService(db, networks.identity, networks.audit, auth)
    lifecycle = NetworkLifecycleService(networks)
    with db.connect() as connection:
        connection.execute(
            """INSERT INTO cases(tenant_id,case_id,title,priority,status,opened_at,updated_at)
               VALUES(?,'case','Synthetic lifecycle case','critical','open',?,?)""",
            (tenant_id, NOW.isoformat(), NOW.isoformat()),
        )
    actions = {}
    credentials = {}
    for state in ("proposed", "approved", "dispatched"):
        grant = enrollment.issue_grant(tenant_id, admin.principal.user_id, NOW)
        credential = enrollment.claim_grant(grant.token, state, state, "macos", NOW)
        credentials[state] = credential
        action = responses.propose(
            admin.principal, "case", "isolate_endpoint", state, "Synthetic test only", NOW
        )
        actions[state] = action.action_id
        if state != "proposed":
            responses.approve(scoped, action.action_id, NOW)
        if state == "dispatched":
            assert (
                len(
                    responses.poll_device(
                        signed_request(
                            "GET",
                            "/v1/agent/actions",
                            nonce="before-change-000001",
                            credential_id=credential.credential_id,
                            secret=credential.secret.encode(),
                            timestamp=NOW,
                        ),
                        state,
                        NOW,
                    )
                )
                == 1
            )
    if change == "pause_network":
        lifecycle.update_network(owner.principal, tenant_id, "Alpha", "suspended", 1, NOW)
    else:
        lifecycle.update_member(
            scoped, admin.principal.user_id, "viewer", "disabled", "admin", "active", 1, NOW
        )
    with db.connect() as connection:
        states = dict(
            connection.execute(
                "SELECT action_id,status FROM response_actions WHERE tenant_id=?", (tenant_id,)
            ).fetchall()
        )
        assert states[actions["proposed"]] == states[actions["approved"]] == "expired"
        assert states[actions["dispatched"]] == "dispatched"
    for mutation in (
        lambda: responses.propose(
            admin.principal, "case", "isolate_endpoint", "proposed", "Old request", NOW
        ),
        lambda: responses.approve(admin.principal, actions["proposed"], NOW),
        lambda: responses.reject(admin.principal, actions["proposed"], "Old request", NOW),
    ):
        with pytest.raises(HumanAuthorizationError):
            mutation()
    # A pause is a delivery boundary, not a credential deletion or an undo.
    credential = credentials["dispatched"]
    request = signed_request(
        "POST",
        "/v1/ingest/events",
        b"{}",
        nonce="after-change-000001",
        credential_id=credential.credential_id,
        secret=credential.secret.encode(),
        timestamp=NOW,
    )
    if change == "pause_network":
        with pytest.raises(CollectorAuthenticationError):
            auth.authenticate(request, NOW)
        lifecycle.update_network(owner.principal, tenant_id, "Alpha", "active", 2, NOW)
    assert auth.authenticate(request, NOW).device_id == "dispatched"
    assert networks.audit.verify(tenant_id).valid


def test_invitation_cancellation_is_scoped_audited_and_cancels_ceremony(network_setup):
    _, networks, _, _, admin, alpha, beta, _, client = network_setup
    invite = networks.identity.issue_human_invite(
        admin.principal, "cancel@alpha.test", "Cancel Test", "admin", NOW
    )
    ceremony = networks.identity.begin_human_invite(invite.token, NOW)
    path = f"/v1/network/invitations/{invite.invite_id}/revoke"
    client.headers["x-network-id"] = str(beta["tenant_id"])
    assert client.post(path, json={"confirmed": True}).status_code == 409
    client.headers["x-network-id"] = str(alpha["tenant_id"])
    result = client.post(path, json={"confirmed": True})
    assert result.status_code == 200
    assert client.get("/v1/network/team").json()["invitations"] == []
    assert client.post(path, json={"confirmed": True}).status_code == 409
    with pytest.raises(HumanInviteError):
        networks.identity.complete_human_invite(
            invite.token,
            ceremony.challenge_id,
            {"id": "cancelled-key", "challenge": ceremony.options["challenge"]},
            NOW,
        )
    assert networks.audit.verify(str(alpha["tenant_id"])).valid


def test_owner_setup_rejects_unsafe_paths_and_nonpasskey_candidates(legacy_owner):
    db, _, audit, issue, root = legacy_owner
    setup = PlatformOwnerSetup(db, audit)
    with pytest.raises(OwnerSetupError, match="active administrator"):
        setup.designate("legacy-other", "missing", OWNER_CONFIRMATION, NOW)
    root.chmod(0o777)
    try:
        with pytest.raises(OwnerSetupError, match="trusted"):
            setup.status()
    finally:
        root.chmod(0o700)
    os.link(db.settings.database_path, root / "database-alias")
    with pytest.raises(OwnerSetupError, match="hard links"):
        setup.designate(issue.principal.tenant_id, issue.principal.user_id, OWNER_CONFIRMATION, NOW)


def test_management_audit_failure_rolls_back_access_changes(network_setup, monkeypatch):
    db, networks, accounts, owner, admin, alpha, _, _, _ = network_setup
    lifecycle = NetworkLifecycleService(networks)
    scoped = networks.scope(owner.principal, str(alpha["tenant_id"]))
    account, signed = ready_account(accounts, admin)
    invite = networks.identity.issue_human_invite(
        admin.principal, "rollback@alpha.test", "Rollback", "admin", NOW
    )

    def broken_audit(*args, **kwargs):
        raise RuntimeError("synthetic audit failure")

    monkeypatch.setattr(networks.audit, "append", broken_audit)
    mutations = (
        lambda: lifecycle.update_network(
            owner.principal, str(alpha["tenant_id"]), "Changed", "suspended", 1, NOW
        ),
        lambda: lifecycle.update_member(
            scoped, admin.principal.user_id, "viewer", "disabled", "admin", "active", 1, NOW
        ),
        lambda: lifecycle.update_account(
            scoped, str(account["account_id"]), "Changed", "disabled", 1, NOW
        ),
        lambda: lifecycle.revoke_invite(scoped, invite.invite_id, NOW),
        lambda: lifecycle.adopt_namespace(
            owner.principal, owner.principal.tenant_id, "rollback", 1, NOW
        ),
    )
    for mutation in mutations:
        with pytest.raises(RuntimeError, match="synthetic audit failure"):
            mutation()
    assert networks.identity.authenticate_session(admin.token, NOW).role == "admin"
    assert accounts.me(str(signed["token"]), NOW)["account_id"] == account["account_id"]
    assert lifecycle.team(scoped, NOW)["invitations"][0]["invite_id"] == invite.invite_id
    with db.connect() as connection:
        assert connection.execute("SELECT COUNT(*) FROM management_revisions").fetchone()[0] == 0
        assert (
            connection.execute(
                "SELECT COUNT(*) FROM network_namespaces WHERE tenant_id=?",
                (owner.principal.tenant_id,),
            ).fetchone()[0]
            == 0
        )
