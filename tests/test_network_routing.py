"""Hostnames are entry hints, never an alternative for network authorization."""

from __future__ import annotations

import secrets
import sqlite3
from datetime import timedelta
from pathlib import Path

import pytest
from test_network_accounts import network_setup as make_network_setup
from test_standalone_identity import NOW, ORIGIN

from controlforge.standalone.identity import HumanAuthorizationError, SessionError
from controlforge.standalone.migrations import MIGRATIONS
from controlforge.standalone.network_lifecycle import NetworkLifecycleService
from controlforge.standalone.network_routing import NetworkRoutingService
from controlforge.standalone.networks import NetworkConflictError, NetworkError


@pytest.fixture
def network_setup(tmp_path: Path):
    return make_network_setup.__wrapped__(tmp_path)


def enable(network_setup):
    _, networks, _, owner, _, alpha, _, _, _ = network_setup
    routes = NetworkRoutingService(networks, ORIGIN)
    result = routes.configure(owner.principal, str(alpha["tenant_id"]), True, 1, NOW)
    assert result["revision"] == 2
    return routes


def test_owner_opt_in_redirect_is_fixed_and_keeps_auth_on_canonical_host(network_setup):
    _, networks, _, _, _, alpha, _, _, client = network_setup
    address = "https://" + str(alpha["login_domain"])
    assert client.get(address + "/", follow_redirects=False).status_code == 421
    enable(network_setup)
    response = client.get(
        address + "/?next=https://evil.example&token=must-not-propagate",
        follow_redirects=False,
    )
    assert response.status_code == 303
    assert response.headers["location"] == ORIGIN + "/console?network=" + str(alpha["tenant_id"])
    assert "set-cookie" not in response.headers
    assert response.headers["cache-control"] == "no-store"
    assert response.headers["referrer-policy"] == "no-referrer"
    assert "must-not-propagate" not in str(response.headers) + response.text
    assert client.head(address + "/", follow_redirects=False).status_code == 303
    assert networks.audit.verify(str(alpha["tenant_id"])).valid
    listing = client.get("/v1/networks").json()
    row = next(n for n in listing["networks"] if n["tenant_id"] == alpha["tenant_id"])
    assert row["routing_status"] == "entry_enabled"
    assert row["external_verification"] == "not_verified"
    assert row["entry_url"] == address + "/"
    assert listing["canonical_origin"] == ORIGIN


@pytest.mark.parametrize(
    "method,path",
    [
        ("GET", "/v1/me"),
        ("GET", "/health"),
        ("GET", "/console"),
        ("POST", "/v1/endpoint/login"),
        ("POST", "/v1/devices/enroll"),
        ("POST", "/v1/auth/logout"),
        ("POST", "/"),
        ("OPTIONS", "/"),
    ],
)
def test_alias_never_serves_auth_api_or_redirects_mutations(network_setup, method, path):
    _, _, _, _, _, alpha, _, _, client = network_setup
    enable(network_setup)
    response = client.request(
        method,
        "https://" + str(alpha["login_domain"]) + path,
        content=b"x" * 9000,
        follow_redirects=False,
    )
    assert response.status_code == 421
    assert "location" not in response.headers and "set-cookie" not in response.headers
    assert client.get("/v1/me").status_code == 200


@pytest.mark.parametrize(
    "host",
    [
        "unknown.controlforge.test",
        "deep.alpha.controlforge.test",
        "alpha.controlforge.test.evil.test",
        "alpha.controlforge.test.",
        "alpha.controlforge.test:444",
        "alpha.controlforge.test:0",
        "alpha.controlforge.test:",
        "alpha.controlforge.test@evil.test",
        "alpha.controlforge.test/path",
        "alpha.controlforge.test?x",
        "alpha.controlforge.test,admin.controlforge.test",
        "alpha%2econtrolforge.test",
        "admin.controlforge.test\\@evil.test",
    ],
)
def test_unknown_malformed_or_ambiguous_hosts_fail_closed(network_setup, host):
    enable(network_setup)
    client = network_setup[-1]
    result = client.get("/", headers={"host": host}, follow_redirects=False)
    assert result.status_code == 421
    assert "location" not in result.headers


def test_forwarded_headers_duplicate_hosts_and_http_cannot_bypass_host_gate(network_setup):
    enable(network_setup)
    client = network_setup[-1]
    fake = {
        "x-forwarded-host": "admin.controlforge.test",
        "x-forwarded-proto": "https",
        "forwarded": 'host="admin.controlforge.test";proto=https',
    }
    assert client.get("https://evil.test/v1/me", headers=fake).status_code == 421
    assert client.get("http://admin.controlforge.test/v1/me", headers=fake).status_code == 421
    assert client.get("/v1/me", headers={"x-forwarded-host": "evil.test"}).status_code == 200
    duplicate = [("host", "admin.controlforge.test"), ("host", "alpha.controlforge.test")]
    assert client.get("/v1/me", headers=duplicate).status_code == 421
    assert client.get("/v1/me", headers={"host": "ADMIN.CONTROLFORGE.TEST:443"}).status_code == 200


def test_only_current_owner_can_mutate_routes_with_csrf_confirmation_and_revision(network_setup):
    database, _, _, owner, admin, alpha, _, _, client = network_setup
    path = "/v1/networks/" + str(alpha["tenant_id"]) + "/routing"
    payload = {"enabled": True, "revision": 1, "confirmed": True}
    assert (
        client.post(path, json=payload, headers={"origin": "https://evil.test"}).status_code == 403
    )
    assert client.post(path, json=payload, headers={"x-csrf-token": "wrong"}).status_code == 403
    for change in ({"confirmed": False}, {"enabled": "true"}, {"revision": 0}):
        assert client.post(path, json={**payload, **change}).status_code == 422
    client.cookies.set("controlforge_session", admin.token)
    client.headers["x-csrf-token"] = admin.csrf_token
    assert client.post(path, json=payload).status_code == 403
    client.cookies.set("controlforge_session", owner.token)
    client.headers["x-csrf-token"] = owner.csrf_token
    assert client.post(path, json=payload).status_code == 200
    assert client.post(path, json=payload).status_code == 409
    with database.connect() as connection:
        assert connection.execute("SELECT COUNT(*) FROM network_routes").fetchone()[0] == 1


def test_route_change_is_audited_atomically_and_rechecks_live_owner(network_setup, monkeypatch):
    database, networks, _, owner, _, alpha, _, _, _ = network_setup
    routes = NetworkRoutingService(networks, ORIGIN)
    original = networks.audit.append

    def fail_home(*args, **kwargs):
        if args[1] == owner.principal.tenant_id:
            raise RuntimeError("injected audit failure")
        return original(*args, **kwargs)

    monkeypatch.setattr(networks.audit, "append", fail_home)
    with pytest.raises(RuntimeError, match="audit failure"):
        routes.configure(owner.principal, str(alpha["tenant_id"]), True, 1, NOW)
    with database.connect() as connection:
        assert connection.execute("SELECT COUNT(*) FROM network_routes").fetchone()[0] == 0
        assert (
            connection.execute(
                "SELECT COUNT(*) FROM audit_log WHERE action='network.entry_route_updated'"
            ).fetchone()[0]
            == 0
        )
        connection.execute("UPDATE sessions SET revoked_at=?", (NOW.isoformat(),))
    with pytest.raises(HumanAuthorizationError):
        routes.configure(owner.principal, str(alpha["tenant_id"]), True, 1, NOW)


def test_paused_disabled_and_changed_base_routes_fail_without_changing_accounts(network_setup):
    _, networks, accounts, owner, admin, alpha, _, _, client = network_setup
    created = accounts.create_account(admin.principal, "alice", "Alice", NOW)
    signed = accounts.login(str(created["username"]), str(created["initial_password"]), NOW)
    routes = enable(network_setup)
    tenant_id = str(alpha["tenant_id"])
    address = "https://" + str(alpha["login_domain"]) + "/"
    routes.configure(owner.principal, tenant_id, False, 2, NOW)
    assert client.get(address, follow_redirects=False).status_code == 421
    assert accounts.me(str(signed["token"]), NOW)["username"] == created["username"]
    with pytest.raises(NetworkConflictError):
        routes.configure(owner.principal, tenant_id, True, 2, NOW)
    routes.configure(owner.principal, tenant_id, True, 3, NOW)
    lifecycle = NetworkLifecycleService(networks)
    lifecycle.update_network(owner.principal, tenant_id, "Alpha School", "suspended", 4, NOW)
    assert client.get(address, follow_redirects=False).status_code == 421
    with pytest.raises(NetworkError, match="active network"):
        routes.configure(owner.principal, tenant_id, True, 5, NOW)
    lifecycle.update_network(owner.principal, tenant_id, "Alpha School", "active", 5, NOW)
    assert client.get(address, follow_redirects=False).status_code == 303
    networks.base_domain = "other.test"
    assert client.get(address, follow_redirects=False).status_code == 421
    assert (
        routes.describe(
            {"login_domain": alpha["login_domain"], "route_enabled": 1, "status": "active"}
        )["routing_status"]
        == "unavailable"
    )


def test_entry_hint_never_grants_another_network_membership(network_setup):
    _, _, _, _, admin, _, beta, _, client = network_setup
    client.cookies.set("controlforge_session", admin.token)
    response = client.get("/console?network=" + str(beta["tenant_id"]))
    assert response.status_code == 200  # Public shell only, not Beta data.
    assert client.get("/v1/networks").json()["is_platform_owner"] is False
    assert (
        client.get(
            "/v1/dashboard/summary", headers={"x-network-id": str(beta["tenant_id"])}
        ).status_code
        == 403
    )
    login = client.get("/admin?network=" + str(beta["tenant_id"]))
    assert "encodeURIComponent(hint)" in login.text


def test_multiple_tabs_keep_session_csrf_but_not_stale_network_revision(network_setup):
    _, _, _, owner, _, alpha, _, _, client = network_setup
    first = client.get("/v1/auth/csrf").json()["csrf_token"]
    second = client.get("/v1/auth/csrf").json()["csrf_token"]
    assert first == second == owner.csrf_token
    path = "/v1/networks/" + str(alpha["tenant_id"]) + "/routing"
    body = {"enabled": True, "revision": 1, "confirmed": True}
    assert client.post(path, json=body, headers={"x-csrf-token": first}).status_code == 200
    assert client.post(path, json=body, headers={"x-csrf-token": second}).status_code == 409


def test_session_csrf_does_not_cross_sessions_or_survive_logout(network_setup):
    _, networks, _, owner, admin, _, _, _, client = network_setup
    token = client.get("/v1/auth/csrf").json()["csrf_token"]
    assert token != admin.csrf_token
    client.cookies.set("controlforge_session", admin.token)
    assert client.post("/v1/auth/logout", headers={"x-csrf-token": token}).status_code == 403
    networks.identity.revoke_session(owner.principal, NOW)
    with pytest.raises(SessionError, match="session is inactive"):
        networks.identity.session_csrf(owner.principal, NOW)
    with pytest.raises(SessionError, match="session is inactive"):
        networks.identity.session_csrf(admin.principal, NOW + timedelta(days=10))


def test_legacy_random_csrf_converges_once_without_persisting_plaintext(network_setup):
    database, networks, _, owner, _, _, _, _, client = network_setup
    old_token = secrets.token_urlsafe(32)
    old_hash = networks.identity._hash(networks.identity._session_pepper, "csrf", old_token)
    with database.connect() as connection:
        connection.execute(
            "UPDATE sessions SET csrf_hash=? WHERE session_id=?",
            (old_hash, owner.principal.session_id),
        )
    current = client.get("/v1/auth/csrf").json()["csrf_token"]
    assert current != old_token
    assert client.get("/v1/auth/csrf").json()["csrf_token"] == current
    principal = networks.identity.authenticate_session(owner.token, NOW)
    networks.identity.verify_csrf(principal, current)
    with pytest.raises(HumanAuthorizationError):
        networks.identity.verify_csrf(principal, old_token)
    with database.connect() as connection:
        stored = connection.execute(
            "SELECT csrf_hash FROM sessions WHERE session_id=?", (owner.principal.session_id,)
        ).fetchone()[0]
    assert current not in stored and old_token not in stored


def test_database_failure_cannot_fall_through_to_canonical_auth(network_setup, monkeypatch):
    database = network_setup[0]
    client = network_setup[-1]
    enable(network_setup)

    def failed_connection():
        raise sqlite3.OperationalError("synthetic database failure, do not reflect")

    monkeypatch.setattr(database, "connect", failed_connection)
    response = client.get("https://alpha.controlforge.test/", follow_redirects=False)
    assert response.status_code == 503
    assert response.headers["cache-control"] == "no-store"
    assert "location" not in response.headers and "set-cookie" not in response.headers
    assert "synthetic" not in response.text


def test_upgrade_keeps_existing_identities_namespaces_and_routes_disabled(network_setup):
    database, networks, accounts, owner, admin, alpha, _, _, _ = network_setup
    created = accounts.create_account(admin.principal, "upgrade", "Existing person", NOW)
    with database.connect() as connection:
        connection.execute("DROP TABLE network_routes")
        connection.execute("DELETE FROM schema_migrations WHERE version=11")
        before = tuple(connection.execute("SELECT * FROM network_namespaces ORDER BY tenant_id"))
        owner_before = tuple(connection.execute("SELECT * FROM platform_owners"))
    assert database.applied_versions() == tuple(range(1, 11))
    database.initialize()
    assert database.applied_versions() == tuple(m.version for m in MIGRATIONS)
    with database.connect() as connection:
        assert (
            tuple(connection.execute("SELECT * FROM network_namespaces ORDER BY tenant_id"))
            == before
        )
        assert tuple(connection.execute("SELECT * FROM platform_owners")) == owner_before
        assert connection.execute("SELECT COUNT(*) FROM network_routes").fetchone()[0] == 0
    assert networks.is_owner(owner.principal)
    assert (
        accounts.login(str(created["username"]), str(created["initial_password"]), NOW)["account"][
            "tenant_id"
        ]
        == alpha["tenant_id"]
    )


@pytest.mark.parametrize(
    "origin",
    [
        "http://admin.test",
        "https://admin.test/path",
        "https://admin.test?",
        "https://admin.test#",
        "https://user@admin.test",
        "https://admin.test:0",
        "https://admin.test:99999",
    ],
)
def test_invalid_canonical_origin_is_rejected(origin):
    with pytest.raises(ValueError):
        NetworkRoutingService(None, origin)


def test_expired_owner_and_canonical_alias_collision_cannot_enable_route(network_setup):
    _, networks, _, owner, _, alpha, _, _, _ = network_setup
    tenant_id = str(alpha["tenant_id"])
    routes = NetworkRoutingService(networks, "https://" + str(alpha["login_domain"]))
    with pytest.raises(NetworkError):
        routes.configure(owner.principal, tenant_id, True, 1, NOW)
    with pytest.raises(HumanAuthorizationError):
        NetworkRoutingService(networks, ORIGIN).configure(
            owner.principal, tenant_id, True, 1, NOW + timedelta(days=10)
        )
