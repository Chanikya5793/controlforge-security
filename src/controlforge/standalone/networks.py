"""Explicit platform ownership and server-authorized network selection."""

from __future__ import annotations

import re
import sqlite3
import uuid
from dataclasses import replace
from datetime import datetime
from typing import Optional

from .audit import StandaloneAuditLog
from .database import StandaloneDatabase
from .identity import Capability, HumanAuthorizationError, HumanIdentityService, SessionPrincipal
from .store import _utc_text


class NetworkError(ValueError):
    """A bounded network configuration request could not be applied."""


class NetworkConflictError(NetworkError):
    """A stale management view must be refreshed before applying a change."""


def normalize_domain(value: str) -> str:
    domain = value.strip().lower()
    label = r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?"
    if len(domain) > 190 or re.fullmatch(rf"{label}(?:\.{label})+", domain) is None:
        raise NetworkError("Use a DNS domain without a scheme, port, path, or wildcard.")
    return domain


class NetworkService:
    """Tenant admin is not platform owner; every cross-network selection is checked."""

    def __init__(
        self,
        database: StandaloneDatabase,
        identity: HumanIdentityService,
        audit: StandaloneAuditLog,
        base_domain: Optional[str] = None,
    ) -> None:
        self.database = database
        self.identity = identity
        self.audit = audit
        self.base_domain = normalize_domain(base_domain) if base_domain else None

    @staticmethod
    def _owner(connection: sqlite3.Connection, principal: SessionPrincipal) -> bool:
        return (
            connection.execute(
                """SELECT 1 FROM platform_owners o
               JOIN users u ON u.tenant_id = o.home_tenant_id AND u.user_id = o.user_id
               JOIN tenants t ON t.tenant_id = u.tenant_id
               WHERE o.home_tenant_id = ? AND o.user_id = ?
                 AND u.status = 'active' AND u.role = 'admin' AND t.status = 'active'""",
                (principal.tenant_id, principal.user_id),
            ).fetchone()
            is not None
        )

    def is_owner(self, principal: SessionPrincipal) -> bool:
        with self.database.connect() as connection:
            return self._owner(connection, principal)

    def scope(self, principal: SessionPrincipal, tenant_id: str) -> SessionPrincipal:
        """Project only a verified owner into an explicit active membership."""
        if not tenant_id or tenant_id == principal.tenant_id:
            return principal
        with self.database.connect() as connection:
            if not self._owner(connection, principal):
                raise HumanAuthorizationError("network is not available to this identity")
            membership = connection.execute(
                """SELECT 1 FROM owner_memberships m
                   JOIN tenants t ON t.tenant_id = m.tenant_id
                   JOIN users u ON u.tenant_id = m.tenant_id AND u.user_id = m.user_id
                   WHERE m.tenant_id = ? AND m.home_tenant_id = ? AND m.user_id = ?
                     AND t.status = 'active' AND u.status = 'active' AND u.role = 'admin'""",
                (tenant_id, principal.tenant_id, principal.user_id),
            ).fetchone()
            if membership is None:
                raise HumanAuthorizationError("network is not available to this identity")
        return replace(principal, tenant_id=tenant_id, role="admin")

    def list_networks(self, principal: SessionPrincipal) -> list[dict[str, object]]:
        with self.database.connect() as connection:
            owner = self._owner(connection, principal)
            rows = connection.execute(
                """SELECT t.tenant_id, t.slug, t.display_name, t.status, n.login_domain,
                    COALESCE(r.revision,1) AS revision, COALESCE(entry.enabled,0) AS route_enabled,
                    EXISTS(SELECT 1 FROM platform_owners o
                        WHERE o.home_tenant_id=t.tenant_id) AS is_owner_home,
                    (SELECT COUNT(*) FROM devices d WHERE d.tenant_id=t.tenant_id
                      AND d.status='active') AS devices,
                    (SELECT COUNT(*) FROM endpoint_accounts a WHERE a.tenant_id=t.tenant_id
                      AND a.status='active') AS people,
                    (SELECT COUNT(*) FROM password_reset_requests r
                      WHERE r.tenant_id=t.tenant_id AND r.resolved_at IS NULL) AS reset_requests
                   FROM tenants t LEFT JOIN network_namespaces n ON n.tenant_id=t.tenant_id
                   LEFT JOIN network_revisions r ON r.tenant_id=t.tenant_id
                   LEFT JOIN network_routes entry ON entry.tenant_id=t.tenant_id
                   WHERE ? = 1 OR t.tenant_id = ? ORDER BY t.created_at, t.tenant_id LIMIT 200""",
                (int(owner), principal.tenant_id),
            ).fetchall()
        return [dict(row) for row in rows]

    def create_network(
        self, principal: SessionPrincipal, slug: str, display_name: str, now: datetime
    ) -> dict[str, object]:
        if (
            re.fullmatch(r"[a-z0-9]+(?:-[a-z0-9]+)*", slug) is None
            or not 3 <= len(slug) <= 48
            or slug in {"www", "admin", "api", "soc", "mail", "owner", "support"}
        ):
            raise NetworkError("Choose a 3-48 character network name using letters and hyphens.")
        name = display_name.strip()
        if not name or len(name) > 120 or any(ord(char) < 32 for char in name):
            raise NetworkError("Enter a network display name of 1-120 characters.")
        if self.base_domain is None:
            raise NetworkError("Configure CONTROLFORGE_NETWORK_BASE_DOMAIN on the appliance first.")
        domain = normalize_domain(f"{slug}.{self.base_domain}")
        tenant_id = str(uuid.uuid4())
        with self.database.connect() as connection, connection:
            connection.execute("BEGIN IMMEDIATE")
            self.require_admin_in(connection, principal, now)
            if not self._owner(connection, principal):
                raise HumanAuthorizationError("only the platform owner can create networks")
            if connection.execute("SELECT COUNT(*) FROM tenants").fetchone()[0] >= 200:
                raise NetworkError("This appliance has reached its 200-network safety limit.")
            try:
                connection.execute(
                    "INSERT INTO tenants VALUES (?, ?, ?, 'active', ?)",
                    (tenant_id, slug, name, _utc_text(now)),
                )
                connection.execute(
                    "INSERT INTO network_namespaces VALUES (?, ?, ?)",
                    (tenant_id, domain, _utc_text(now)),
                )
            except sqlite3.IntegrityError as exc:
                raise NetworkError("That network name is already in use.") from exc
            connection.execute(
                """INSERT INTO users(tenant_id,user_id,email,display_name,role,status,created_at)
                       VALUES (?, ?, ?, ?, 'admin', 'active', ?)""",
                (
                    tenant_id,
                    principal.user_id,
                    principal.email,
                    principal.display_name,
                    _utc_text(now),
                ),
            )
            connection.execute(
                "INSERT INTO owner_memberships VALUES (?, ?, ?)",
                (tenant_id, principal.user_id, principal.tenant_id),
            )
            self.audit.append(
                connection,
                tenant_id,
                "network.created",
                "platform_owner",
                principal.user_id,
                "network",
                tenant_id,
                {"login_domain": domain},
                now,
            )
            self.audit.append(
                connection,
                principal.tenant_id,
                "network.created",
                "platform_owner",
                principal.user_id,
                "network",
                tenant_id,
                {},
                now,
            )
        return {
            "tenant_id": tenant_id,
            "slug": slug,
            "display_name": name,
            "login_domain": domain,
            "routing_status": "namespace_only",
            "revision": 1,
        }

    def require_admin_in(
        self,
        connection: sqlite3.Connection,
        principal: SessionPrincipal,
        now: datetime,
    ) -> None:
        self.identity.require_current_capability(connection, principal, Capability.MANAGE, now)

    def require_admin(self, principal: SessionPrincipal) -> None:
        self.identity.require_capability(principal, principal.tenant_id, Capability.MANAGE)
        with self.database.connect() as connection:
            active = connection.execute(
                """SELECT s.tenant_id AS home_tenant_id FROM sessions s
                   JOIN users u ON u.tenant_id=s.tenant_id AND u.user_id=s.user_id
                   JOIN users member ON member.tenant_id=? AND member.user_id=s.user_id
                   JOIN tenants t ON t.tenant_id=member.tenant_id
                   WHERE s.session_id=? AND s.user_id=? AND s.revoked_at IS NULL
                     AND u.role='admin' AND u.status='active' AND member.role='admin'
                     AND member.status='active' AND t.status='active'""",
                (principal.tenant_id, principal.session_id, principal.user_id),
            ).fetchone()
            if active is None:
                raise HumanAuthorizationError("network administrator authority is inactive")
            if active["home_tenant_id"] != principal.tenant_id:
                home = replace(principal, tenant_id=str(active["home_tenant_id"]))
                if not self._owner(connection, home):
                    raise HumanAuthorizationError("platform owner authority is inactive")
