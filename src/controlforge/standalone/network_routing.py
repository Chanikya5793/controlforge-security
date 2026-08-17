"""Exact-host entry routing; subdomains never become authentication authorities."""

from __future__ import annotations

import ipaddress
import re
import sqlite3
from datetime import datetime
from typing import Optional
from urllib.parse import quote, urlsplit

from fastapi import Request
from fastapi.responses import JSONResponse, RedirectResponse, Response

from .identity import SessionPrincipal
from .network_lifecycle import NetworkLifecycleService
from .networks import NetworkError, NetworkService, normalize_domain
from .store import _utc_text


def _authority(value: str) -> tuple[str, int]:
    # Work from the raw Host field, not forwarded headers or a reconstructed URL.
    if not value or len(value) > 255 or re.search(r"[\s/@?#\\%]", value):
        raise ValueError("invalid host authority")
    parsed = urlsplit("https://" + value)
    host = parsed.hostname or ""
    if not host or parsed.username is not None or parsed.password is not None:
        raise ValueError("invalid host authority")
    if host != "localhost":
        try:
            ipaddress.ip_address(host)
        except ValueError:
            if normalize_domain(host) != host or host.endswith("."):
                raise ValueError("invalid host authority") from None
    port = parsed.port or 443
    if not 1 <= port <= 65535 or value.endswith(":") or parsed.port == 0:
        raise ValueError("invalid host port")
    return host, port


def eligible_entry_domain(value: object, base_domain: Optional[str], canonical_host: str) -> bool:
    if base_domain is None or not isinstance(value, str):
        return False
    try:
        domain = normalize_domain(value)
    except NetworkError:
        return False
    prefix, _, suffix = domain.partition(".")
    return bool(prefix) and domain == value and suffix == base_domain and domain != canonical_host


class NetworkRoutingService:
    """Owner opt-in redirects with separate, unclaimed external DNS/TLS evidence."""

    def __init__(self, networks: Optional[NetworkService], admin_origin: str) -> None:
        parsed = urlsplit(admin_origin)
        if (
            parsed.scheme != "https"
            or parsed.path not in {"", "/"}
            or parsed.query
            or parsed.fragment
            or "?" in admin_origin
            or "#" in admin_origin
        ):
            raise ValueError("standalone admin origin must be a fixed HTTPS origin")
        self.host, self.port = _authority(parsed.netloc)
        self.origin = admin_origin.rstrip("/")
        self.networks = networks

    def _eligible_domain(self, value: object) -> bool:
        return eligible_entry_domain(
            value, self.networks.base_domain if self.networks is not None else None, self.host
        )

    def describe(self, network: dict[str, object]) -> dict[str, object]:
        eligible = self._eligible_domain(network.get("login_domain"))
        enabled = bool(network.get("route_enabled"))
        active = network.get("status") == "active"
        domain = str(network.get("login_domain") or "")
        port = "" if self.port == 443 else f":{self.port}"
        return {
            "entry_url": f"https://{domain}{port}/" if eligible else None,
            "entry_enabled": enabled,
            "routing_status": (
                "unavailable"
                if not eligible
                else "paused"
                if not active
                else "entry_enabled"
                if enabled
                else "namespace_only"
            ),
            "external_verification": "not_verified",
        }

    def configure(
        self,
        principal: SessionPrincipal,
        tenant_id: str,
        enabled: bool,
        revision: int,
        now: datetime,
    ) -> dict[str, object]:
        if self.networks is None:
            raise NetworkError("network routing is not configured")
        lifecycle = NetworkLifecycleService(self.networks)
        with self.networks.database.connect() as connection, connection:
            connection.execute("BEGIN IMMEDIATE")
            lifecycle._owner(connection, principal, now)
            network = lifecycle._network(connection, tenant_id, revision)
            if enabled and (
                not self._eligible_domain(network["login_domain"]) or network["status"] != "active"
            ):
                raise NetworkError(
                    "configure an active network namespace under the current base domain first"
                )
            previous = connection.execute(
                "SELECT enabled FROM network_routes WHERE tenant_id=?", (tenant_id,)
            ).fetchone()
            if bool(previous[0] if previous else False) == enabled:
                return {"tenant_id": tenant_id, "revision": revision, "entry_enabled": enabled}
            connection.execute(
                """INSERT INTO network_routes VALUES(?,?,?) ON CONFLICT(tenant_id)
                   DO UPDATE SET enabled=excluded.enabled,updated_at=excluded.updated_at""",
                (tenant_id, int(enabled), _utc_text(now)),
            )
            updated = lifecycle._bump(connection, tenant_id, revision)
            payload: dict[str, object] = {
                "entry_enabled": enabled,
                "login_domain": network["login_domain"],
                "revision": updated,
                "external_verification": "not_verified",
            }
            for scope in dict.fromkeys((tenant_id, principal.tenant_id)):
                self.networks.audit.append(
                    connection,
                    scope,
                    "network.entry_route_updated",
                    "platform_owner",
                    principal.user_id,
                    "network",
                    tenant_id,
                    payload,
                    now,
                )
        return {"tenant_id": tenant_id, "revision": updated, "entry_enabled": enabled}

    def response_for(self, request: Request) -> Optional[Response]:
        """Reject before body parsing/authentication; only exact canonical APIs run."""
        rejected = JSONResponse(
            {"error": "This host is not an available entry point."}, status_code=421
        )
        hosts = [value for key, value in request.scope["headers"] if key.lower() == b"host"]
        if len(hosts) != 1 or request.scope.get("scheme") != "https":
            return rejected
        try:
            host, port = _authority(hosts[0].decode("ascii"))
        except (ValueError, UnicodeError):
            return rejected
        if (host, port) == (self.host, self.port):
            return None
        if (
            self.networks is None
            or port != self.port
            or not self._eligible_domain(host)
            or request.method not in {"GET", "HEAD"}
            or request.scope["path"] != "/"
        ):
            return rejected
        try:
            with self.networks.database.connect() as connection:
                row = connection.execute(
                    """SELECT n.tenant_id FROM network_namespaces n
                       JOIN tenants t ON t.tenant_id=n.tenant_id
                       JOIN network_routes r ON r.tenant_id=n.tenant_id
                       WHERE n.login_domain=? AND t.status='active' AND r.enabled=1""",
                    (host,),
                ).fetchone()
        except sqlite3.Error:
            return JSONResponse(
                {"error": "Network entry is temporarily unavailable."}, status_code=503
            )
        if row is None:
            return rejected
        # Query/path/header input is never reflected into the redirect target.
        # The hint is only used after canonical-host membership authentication.
        return RedirectResponse(
            self.origin + "/console?network=" + quote(str(row[0]), safe=""), status_code=303
        )
