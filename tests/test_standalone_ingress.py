"""Real HTTPS origin and bounded connector metadata; no deployed Tunnel assumed."""

from __future__ import annotations

import http.client
import socket
import ssl
import threading
import time
from dataclasses import replace
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest
import uvicorn
import yaml
from fastapi import Request
from test_network_accounts import build_network_setup
from test_standalone_appliance import launch_config, tls_material
from test_standalone_identity import NOW, ORIGIN

from controlforge.cli import run as cli_run
from controlforge.standalone.__main__ import run
from controlforge.standalone.ingress import IngressPolicy, rate_limit_client
from controlforge.standalone.network_routing import NetworkRoutingService
from controlforge.standalone.tunnel import render_tunnel_config

TUNNEL_ID = "ab65c5bd-8056-408b-918e-5963b1531447"
CF_HEADERS = {"cf-connecting-ip": "198.51.100.5"}


@pytest.fixture
def setup(tmp_path):
    return build_network_setup(
        tmp_path, ingress_mode="cloudflare-tunnel", client_address=("127.0.0.1", 50000)
    )


def test_connector_headers_never_replace_auth_or_host_and_reject_before_body(setup):
    _, networks, _, owner, _, alpha, _, _, client = setup
    client.cookies.clear()
    assert client.get("/health", headers=CF_HEADERS).status_code == 200
    assert client.get("/v1/me", headers=CF_HEADERS).status_code == 401
    for path in ("/health", "/v1/endpoint/login"):
        response = client.post(path, content=b"x" * 9000)
        assert response.status_code == 403
        assert response.headers["cache-control"] == "no-store"
        assert "x" * 30 not in response.text
    response = client.get(
        "/health",
        headers={**CF_HEADERS, "host": "unknown.example.com", "x-forwarded-host": ORIGIN[8:]},
    )
    assert response.status_code == 421
    routing = NetworkRoutingService(networks, ORIGIN)
    routing.configure(owner.principal, str(alpha["tenant_id"]), True, 1, NOW)
    alias = "https://" + str(alpha["login_domain"])
    assert client.get(alias + "/", headers=CF_HEADERS, follow_redirects=False).status_code == 303
    assert client.get(alias + "/v1/me", headers=CF_HEADERS).status_code == 421
    assert (
        client.get("http://admin.controlforge.test/health", headers=CF_HEADERS).status_code == 403
    )


@pytest.mark.parametrize(
    "headers",
    [
        [],
        [("cf-connecting-ip", "")],
        [("cf-connecting-ip", "198.51.100.1,198.51.100.2")],
        [("cf-connecting-ip", "198.51.100.1:443")],
        [("cf-connecting-ip", "[2001:db8::1]")],
        [("cf-connecting-ip", "fe80::1%en0")],
        [("cf-connecting-ip", " 198.51.100.1")],
        [("cf-connecting-ip", "a" * 100)],
        [("cf-connecting-ip", "198.51.100.1"), ("CF-Connecting-IP", "198.51.100.2")],
        [("x-forwarded-for", "198.51.100.1")],
        [("forwarded", "for=198.51.100.1;proto=https")],
    ],
)
def test_invalid_or_duplicate_metadata_fails_closed(setup, headers):
    response = setup[-1].get("/health", headers=headers)
    assert response.status_code == 403
    assert response.json() == {"error": "Request did not arrive through the configured connector."}


def test_non_loopback_peer_cannot_claim_connector_identity(tmp_path):
    client = build_network_setup(
        tmp_path, ingress_mode="cloudflare-tunnel", client_address=("198.51.100.10", 50000)
    )[-1]
    assert client.get("/health", headers=CF_HEADERS).status_code == 403


def test_direct_mode_ignores_forged_headers(tmp_path):
    client = build_network_setup(tmp_path)[-1]
    for index in range(20):
        assert (
            client.post(
                "/v1/endpoint/password-reset",
                json={"username": f"missing{index}@controlforge.test"},
                headers={"cf-connecting-ip": f"198.51.100.{index + 1}"},
            ).status_code
            == 202
        )
    assert (
        client.post(
            "/v1/endpoint/password-reset",
            json={"username": "another@controlforge.test"},
            headers={"cf-connecting-ip": "203.0.113.88", "x-forwarded-for": "203.0.113.88"},
        ).status_code
        == 429
    )


def test_separate_proxy_clients_have_separate_ip_budgets(setup):
    client = setup[-1]
    for index in range(20):
        assert (
            client.post(
                "/v1/endpoint/password-reset",
                json={"username": f"missing{index}@controlforge.test"},
                headers=CF_HEADERS,
            ).status_code
            == 202
        )
    assert (
        client.post(
            "/v1/endpoint/password-reset",
            json={"username": "next@controlforge.test"},
            headers=CF_HEADERS,
        ).status_code
        == 429
    )
    assert (
        client.post(
            "/v1/endpoint/password-reset",
            json={"username": "next@controlforge.test"},
            headers={"cf-connecting-ip": "198.51.100.6"},
        ).status_code
        == 202
    )


def test_account_and_global_budgets_survive_client_ip_changes(setup):
    client = setup[-1]
    for index in range(10):
        assert (
            client.post(
                "/v1/endpoint/password-reset",
                json={"username": "missing@controlforge.test"},
                headers={"cf-connecting-ip": f"198.51.100.{index + 1}"},
            ).status_code
            == 202
        )
    assert (
        client.post(
            "/v1/endpoint/password-reset",
            json={"username": "missing@controlforge.test"},
            headers={"cf-connecting-ip": "198.51.100.100"},
        ).status_code
        == 429
    )
    for index in range(49):
        assert (
            client.post(
                "/v1/endpoint/password-reset",
                json={"username": f"another{index}@controlforge.test"},
                headers={"cf-connecting-ip": f"203.0.113.{index + 1}"},
            ).status_code
            == 202
        )
    assert (
        client.post(
            "/v1/endpoint/password-reset",
            json={"username": "last@controlforge.test"},
            headers={"cf-connecting-ip": "203.0.113.100"},
        ).status_code
        == 429
    )


@pytest.mark.parametrize(
    "raw,canonical",
    [(b"2001:db8:0::1", "2001:db8::1"), (b"::ffff:198.51.100.5", "198.51.100.5")],
)
def test_normalizes_equivalent_client_address_forms(raw, canonical):
    request = Request(
        {
            "type": "http",
            "scheme": "https",
            "client": ("127.0.0.1", 1),
            "headers": [(b"cf-connecting-ip", raw)],
        }
    )
    assert IngressPolicy("cloudflare-tunnel").prepare(request) is None
    assert rate_limit_client(request) == canonical
    assert request.client.host == "127.0.0.1"
    request.scope["headers"] = [(b"cf-connecting-ip", b"\xff")]
    assert IngressPolicy("cloudflare-tunnel").prepare(request).status_code == 403


def test_passkey_recovery_uses_validated_client_budget(setup):
    client = setup[-1]
    payload = {
        "tenant_slug": "controlforge",
        "email": "unknown@example.com",
        "recovery_code": "invalid-recovery-code-value",
    }
    for _ in range(5):
        assert client.post("/v1/auth/recovery", json=payload, headers=CF_HEADERS).status_code == 401
    blocked = client.post("/v1/auth/recovery", json=payload, headers=CF_HEADERS)
    assert blocked.status_code == 429 and int(blocked.headers["retry-after"]) > 0
    assert (
        client.post(
            "/v1/auth/recovery", json=payload, headers={"cf-connecting-ip": "203.0.113.5"}
        ).status_code
        == 401
    )


def snapshot(setup, **overrides):
    arguments = dict(
        database_path=setup[0].settings.database_path,
        admin_origin=ORIGIN,
        base_domain="controlforge.test",
        origin_port=8443,
        tunnel_id=TUNNEL_ID,
        credentials_file=Path("/private/not-read/tunnel.json"),
    )
    arguments.update(overrides)
    return render_tunnel_config(**arguments)


def test_snapshot_is_exact_current_read_only_and_does_not_read_credentials(setup, tmp_path, capsys):
    database, networks, _, owner, _, alpha, beta, _, _ = setup
    routes = NetworkRoutingService(networks, ORIGIN)
    routes.configure(owner.principal, str(alpha["tenant_id"]), True, 1, NOW)
    credentials = tmp_path / "credentials.json"
    credentials.write_text("SYNTHETIC-SECRET-MUST-NOT-BE-READ")
    ca_pool = tmp_path / "private-ca.pem"
    with database.connect() as connection:
        before = list(connection.iterdump())
    text = snapshot(setup, credentials_file=credentials, ca_pool=ca_pool)
    config = yaml.safe_load(text)
    assert config["credentials-file"] == str(credentials)
    assert config["originRequest"] == {
        "originServerName": "admin.controlforge.test",
        "noTLSVerify": False,
        "matchSNItoHost": False,
        "caPool": str(ca_pool),
    }
    assert config["ingress"] == [
        {"hostname": "admin.controlforge.test", "service": "https://127.0.0.1:8443"},
        {"hostname": alpha["login_domain"], "service": "https://127.0.0.1:8443"},
        {"service": "http_status:404"},
    ]
    assert str(beta["login_domain"]) not in text
    assert "SYNTHETIC-SECRET" not in text and "httpHostHeader" not in text and "*" not in text
    assert (
        run(
            [
                "tunnel-config",
                "--database",
                str(database.settings.database_path),
                "--admin-origin",
                ORIGIN,
                "--network-base-domain",
                "controlforge.test",
                "--tunnel-id",
                TUNNEL_ID,
                "--credentials-file",
                str(credentials),
                "--ca-pool",
                str(ca_pool),
            ]
        )
        == 0
    )
    assert capsys.readouterr().out == text
    with database.connect() as connection:
        assert list(connection.iterdump()) == before
    routes.configure(owner.principal, str(alpha["tenant_id"]), False, 2, NOW)
    assert str(alpha["login_domain"]) not in snapshot(setup)


@pytest.mark.parametrize(
    "overrides",
    [
        {"admin_origin": "http://admin.controlforge.test"},
        {"admin_origin": "https://admin.controlforge.test:8443"},
        {"admin_origin": "https://127.0.0.1"},
        {"admin_origin": "https://localhost"},
        {"admin_origin": "https://admin.controlforge.test?"},
        {"base_domain": "*.controlforge.test"},
        {"tunnel_id": "invalid"},
        {"tunnel_id": "00000000-0000-0000-0000-000000000000"},
        {"origin_port": 0},
        {"origin_port": 65536},
        {"credentials_file": Path("relative.json")},
        {"credentials_file": Path("/private/../secret.json")},
        {"ca_pool": Path("/private/unsafe\nfile.pem")},
    ],
)
def test_invalid_snapshot_configuration_is_rejected(setup, overrides):
    with pytest.raises(ValueError):
        snapshot(setup, **overrides)


def test_snapshot_excludes_paused_or_old_domain_entries_and_rejects_older_schema(setup):
    database, networks, _, owner, _, alpha, _, _, _ = setup
    NetworkRoutingService(networks, ORIGIN).configure(
        owner.principal, str(alpha["tenant_id"]), True, 1, NOW
    )
    assert str(alpha["login_domain"]) not in snapshot(setup, base_domain="changed.test")
    with database.connect() as connection:
        connection.execute(
            "UPDATE tenants SET status='suspended' WHERE tenant_id=?", (alpha["tenant_id"],)
        )
    assert str(alpha["login_domain"]) not in snapshot(setup)
    with database.connect() as connection:
        connection.execute("DELETE FROM schema_migrations WHERE version=11")
    with pytest.raises(ValueError, match="upgrade"):
        snapshot(setup)


def test_snapshot_rejects_unsafe_missing_and_corrupt_database(setup, tmp_path):
    path = setup[0].settings.database_path
    link = tmp_path / "link.db"
    link.symlink_to(path)
    with pytest.raises(ValueError, match="private operator"):
        snapshot(setup, database_path=link)
    path.chmod(0o644)
    with pytest.raises(ValueError, match="private operator"):
        snapshot(setup)
    path.chmod(0o600)
    with pytest.raises(FileNotFoundError):
        snapshot(setup, database_path=tmp_path / "missing.db")
    corrupt = tmp_path / "corrupt.db"
    corrupt.write_bytes(b"not-a-database")
    corrupt.chmod(0o600)
    with pytest.raises(ValueError, match="could not read"):
        snapshot(setup, database_path=corrupt)
    assert not (tmp_path / "missing.db").exists()


def test_tunnel_mode_refuses_public_bind_before_runtime_creation(tmp_path):
    config = launch_config(tmp_path)
    with pytest.raises(ValueError, match=r"127\.0\.0\.1"):
        replace(config, ingress_mode="cloudflare-tunnel", host="0.0.0.0")  # noqa: S104 -- rejection test
    with pytest.raises(ValueError, match="unsupported"):
        replace(config, ingress_mode="automatic")
    with pytest.raises(ValueError, match=r"127\.0\.0\.1"):
        cli_run(
            [
                "standalone",
                "serve",
                "--database",
                str(tmp_path / "unused.db"),
                "--secrets-directory",
                str(tmp_path / "unused-secrets"),
                "--host",
                "0.0.0.0",  # noqa: S104 -- rejected before binding
                "--ingress-mode",
                "cloudflare-tunnel",
                "--tls-certificate",
                str(config.tls_certificate),
                "--tls-private-key",
                str(config.tls_private_key),
            ]
        )
    assert not (tmp_path / "unused.db").exists()
    assert not config.root.exists()


def test_real_tls_origin_validates_certificate_and_keeps_host_distinct_from_sni(setup, tmp_path):
    _, networks, _, owner, _, alpha, _, _, client = setup
    NetworkRoutingService(networks, ORIGIN).configure(
        owner.principal, str(alpha["tenant_id"]), True, 1, NOW
    )
    now = datetime.now(timezone.utc)
    certificate, key = tls_material(
        tmp_path / "wire-tls",
        hostname="admin.controlforge.test",
        not_before=now - timedelta(minutes=5),
        not_after=now + timedelta(hours=1),
    )
    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.bind(("127.0.0.1", 0))
    port = listener.getsockname()[1]
    server = uvicorn.Server(
        uvicorn.Config(
            client.app,
            host="127.0.0.1",
            port=port,
            ssl_certfile=str(certificate),
            ssl_keyfile=str(key),
            proxy_headers=False,
            log_level="critical",
            access_log=False,
            lifespan="off",
        )
    )
    thread = threading.Thread(target=server.run, kwargs={"sockets": [listener]}, daemon=True)
    thread.start()
    try:
        deadline = time.monotonic() + 5
        while not server.started and time.monotonic() < deadline and thread.is_alive():
            time.sleep(0.01)
        assert server.started
        trusted = ssl.create_default_context(cafile=str(certificate))
        assert trusted.check_hostname and trusted.verify_mode == ssl.CERT_REQUIRED

        def request(
            host,
            path="/health",
            *,
            headers=CF_HEADERS,
            context=trusted,
            sni="admin.controlforge.test",
        ):
            with (
                socket.create_connection(("127.0.0.1", port), timeout=3) as raw,
                context.wrap_socket(raw, server_hostname=sni) as stream,
            ):
                message = f"GET {path} HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n"
                message += "".join(f"{key}: {value}\r\n" for key, value in headers.items())
                stream.sendall((message + "\r\n").encode("ascii"))
                response = http.client.HTTPResponse(stream)
                response.begin()
                body = response.read()
                return response.status, dict(response.getheaders()), body

        assert request("admin.controlforge.test")[0] == 200
        assert request("admin.controlforge.test", headers={})[0] == 403
        assert (
            request(
                "unknown.example.com",
                headers={**CF_HEADERS, "X-Forwarded-Host": "admin.controlforge.test"},
            )[0]
            == 421
        )
        status, headers, _ = request(str(alpha["login_domain"]), "/?ignored=secret")
        assert status == 303
        assert headers["location"] == ORIGIN + "/console?network=" + str(alpha["tenant_id"])
        assert "set-cookie" not in headers
        assert request(str(alpha["login_domain"]), "/v1/me")[0] == 421
        with pytest.raises(ssl.SSLCertVerificationError):
            request("admin.controlforge.test", context=ssl.create_default_context())
        with pytest.raises(ssl.SSLCertVerificationError):
            request("admin.controlforge.test", sni="unknown.example.com")
    finally:
        server.should_exit = True
        thread.join(timeout=5)
        listener.close()
        assert not thread.is_alive()
