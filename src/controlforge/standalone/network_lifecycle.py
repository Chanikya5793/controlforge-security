"""Revisioned, auditable management without implicit endpoint disconnection."""

from __future__ import annotations

import re
import sqlite3
from datetime import datetime
from typing import Literal, cast

from .identity import ROLE_CAPABILITIES, HumanAuthorizationError, Role, SessionPrincipal
from .networks import NetworkConflictError, NetworkError, NetworkService, normalize_domain
from .store import _utc_text


class NetworkLifecycleService:
    def __init__(self, networks: NetworkService) -> None:
        self.networks = networks
        self.database = networks.database
        self.audit = networks.audit

    def _owner(
        self, connection: sqlite3.Connection, principal: SessionPrincipal, now: datetime
    ) -> None:
        self.networks.require_admin_in(connection, principal, now)
        if not self.networks._owner(connection, principal):
            raise HumanAuthorizationError("only the platform owner can configure networks")

    @staticmethod
    def _network(connection: sqlite3.Connection, tenant_id: str, revision: int) -> sqlite3.Row:
        row = connection.execute(
            """SELECT t.*,n.login_domain,COALESCE(r.revision,1) AS revision FROM tenants t
               LEFT JOIN network_namespaces n ON n.tenant_id=t.tenant_id
               LEFT JOIN network_revisions r ON r.tenant_id=t.tenant_id WHERE t.tenant_id=?""",
            (tenant_id,),
        ).fetchone()
        if row is None:
            raise NetworkError("that network is unavailable")
        if revision != row["revision"]:
            raise NetworkConflictError("the network changed; refresh before trying again")
        return cast(sqlite3.Row, row)

    @staticmethod
    def _bump(connection: sqlite3.Connection, tenant_id: str, revision: int) -> int:
        connection.execute(
            """INSERT INTO network_revisions VALUES(?,?)
               ON CONFLICT(tenant_id) DO UPDATE SET revision=excluded.revision""",
            (tenant_id, revision + 1),
        )
        return revision + 1

    def _expire_undelivered_actions(
        self,
        connection: sqlite3.Connection,
        tenant_id: str,
        user_id: str | None,
        now: datetime,
    ) -> int:
        # Dispatch already completed is not reversed or represented as undone.
        return connection.execute(
            """UPDATE response_actions SET status='expired',completed_at=?
               WHERE tenant_id=? AND status IN ('proposed','approved')
                 AND (? IS NULL OR proposed_by=? OR approved_by=?)""",
            (_utc_text(now), tenant_id, user_id, user_id, user_id),
        ).rowcount

    def update_network(
        self,
        principal: SessionPrincipal,
        tenant_id: str,
        display_name: str,
        status: Literal["active", "suspended"],
        revision: int,
        now: datetime,
    ) -> dict[str, object]:
        name = display_name.strip()
        if (
            not name
            or len(name) > 120
            or any(ord(char) < 32 for char in name)
            or status not in {"active", "suspended"}
        ):
            raise NetworkError("enter a valid network name and status")
        with self.database.connect() as connection, connection:
            connection.execute("BEGIN IMMEDIATE")
            self._owner(connection, principal, now)
            previous = self._network(connection, tenant_id, revision)
            if (
                status == "suspended"
                and connection.execute(
                    "SELECT 1 FROM platform_owners WHERE home_tenant_id=?",
                    (tenant_id,),
                ).fetchone()
            ):
                raise NetworkError("the platform owner's home network must remain active")
            if previous["display_name"] == name and previous["status"] == status:
                return {"tenant_id": tenant_id, "revision": revision, "status": status}
            revoked: dict[str, object] = {}
            if status == "suspended" and previous["status"] != status:
                revoked["human_sessions"] = connection.execute(
                    "UPDATE sessions SET revoked_at=? WHERE tenant_id=? AND revoked_at IS NULL",
                    (_utc_text(now), tenant_id),
                ).rowcount
                revoked["endpoint_sessions"] = connection.execute(
                    "DELETE FROM endpoint_sessions WHERE tenant_id=?", (tenant_id,)
                ).rowcount
                connection.execute(
                    """UPDATE auth_challenges SET consumed_at=?
                       WHERE tenant_id=? AND consumed_at IS NULL""",
                    (_utc_text(now), tenant_id),
                )
                revoked["invitations"] = connection.execute(
                    """UPDATE human_invites SET revoked_at=?
                       WHERE tenant_id=? AND revoked_at IS NULL AND consumed_at IS NULL""",
                    (_utc_text(now), tenant_id),
                ).rowcount
                revoked["enrollment_grants"] = connection.execute(
                    """UPDATE enrollment_tokens SET revoked_at=?
                       WHERE tenant_id=? AND revoked_at IS NULL""",
                    (_utc_text(now), tenant_id),
                ).rowcount
                revoked["undelivered_responses"] = self._expire_undelivered_actions(
                    connection, tenant_id, None, now
                )
            connection.execute(
                "UPDATE tenants SET display_name=?,status=? WHERE tenant_id=?",
                (name, status, tenant_id),
            )
            updated = self._bump(connection, tenant_id, revision)
            payload: dict[str, object] = {
                "previous_status": previous["status"],
                "status": status,
                "previous_name": previous["display_name"],
                "display_name": name,
                "revision": updated,
                "revoked": revoked,
            }
            self.audit.append(
                connection,
                tenant_id,
                "network.updated",
                "platform_owner",
                principal.user_id,
                "network",
                tenant_id,
                payload,
                now,
            )
            if principal.tenant_id != tenant_id:
                self.audit.append(
                    connection,
                    principal.tenant_id,
                    "network.updated",
                    "platform_owner",
                    principal.user_id,
                    "network",
                    tenant_id,
                    payload,
                    now,
                )
        return {"tenant_id": tenant_id, "revision": updated, "status": status}

    def adopt_namespace(
        self,
        principal: SessionPrincipal,
        tenant_id: str,
        slug: str,
        revision: int,
        now: datetime,
    ) -> dict[str, object]:
        if self.networks.base_domain is None:
            raise NetworkError("configure CONTROLFORGE_NETWORK_BASE_DOMAIN first")
        if (
            not 3 <= len(slug) <= 48
            or re.fullmatch(r"[a-z0-9]+(?:-[a-z0-9]+)*", slug) is None
            or slug in {"www", "admin", "api", "soc", "mail", "owner", "support"}
        ):
            raise NetworkError(
                "choose a 3-48 character account subdomain using letters and hyphens"
            )
        domain = normalize_domain(f"{slug}.{self.networks.base_domain}")
        with self.database.connect() as connection, connection:
            connection.execute("BEGIN IMMEDIATE")
            self._owner(connection, principal, now)
            previous = self._network(connection, tenant_id, revision)
            if previous["login_domain"] is not None:
                raise NetworkConflictError("this network already has an immutable login namespace")
            if previous["status"] != "active":
                raise NetworkError("resume the network before configuring its account namespace")
            try:
                connection.execute(
                    "INSERT INTO network_namespaces VALUES(?,?,?)",
                    (tenant_id, domain, _utc_text(now)),
                )
            except sqlite3.IntegrityError as exc:
                raise NetworkConflictError("that account subdomain is already in use") from exc
            updated = self._bump(connection, tenant_id, revision)
            self.audit.append(
                connection,
                tenant_id,
                "network.namespace_adopted",
                "platform_owner",
                principal.user_id,
                "network",
                tenant_id,
                {"login_domain": domain, "revision": updated},
                now,
            )
        return {
            "tenant_id": tenant_id,
            "login_domain": domain,
            "revision": updated,
            "routing_status": "namespace_only",
        }

    def team(self, principal: SessionPrincipal, now: datetime) -> dict[str, object]:
        with self.database.connect() as connection:
            self.networks.require_admin_in(connection, principal, now)
            users = connection.execute(
                """SELECT u.user_id,u.email,u.display_name,u.role,u.status,
                     COALESCE(r.revision,1) AS revision,
                     EXISTS(SELECT 1 FROM platform_owners o WHERE o.user_id=u.user_id)
                       OR EXISTS(SELECT 1 FROM owner_memberships m
                           WHERE m.tenant_id=u.tenant_id AND m.user_id=u.user_id)
                       AS is_platform_owner
                   FROM users u LEFT JOIN management_revisions r
                     ON r.tenant_id=u.tenant_id AND r.kind='user' AND r.identity_id=u.user_id
                   WHERE u.tenant_id=? ORDER BY u.display_name,u.user_id LIMIT 1000""",
                (principal.tenant_id,),
            ).fetchall()
            invites = connection.execute(
                """SELECT invite_id,email,display_name,role,created_at,expires_at FROM human_invites
                   WHERE tenant_id=? AND consumed_at IS NULL AND revoked_at IS NULL AND expires_at>?
                   ORDER BY created_at LIMIT 1000""",
                (principal.tenant_id, _utc_text(now)),
            ).fetchall()
        return {
            "members": [dict(row) for row in users],
            "invitations": [dict(row) for row in invites],
        }

    def update_member(
        self,
        principal: SessionPrincipal,
        user_id: str,
        role: Role,
        status: Literal["active", "disabled"],
        expected_role: Role,
        expected_status: str,
        revision: int,
        now: datetime,
    ) -> dict[str, object]:
        if role not in ROLE_CAPABILITIES or status not in {"active", "disabled"}:
            raise NetworkError("select a valid network role and sign-in state")
        with self.database.connect() as connection, connection:
            connection.execute("BEGIN IMMEDIATE")
            self.networks.require_admin_in(connection, principal, now)
            target = connection.execute(
                "SELECT * FROM users WHERE tenant_id=? AND user_id=?",
                (principal.tenant_id, user_id),
            ).fetchone()
            self._identity_revision(connection, principal.tenant_id, "user", user_id, revision)
            if target is None:
                raise NetworkError("that team member is not in this network")
            if target["role"] != expected_role or target["status"] != expected_status:
                raise NetworkConflictError("this team member changed; refresh before trying again")
            if (
                user_id == principal.user_id
                or connection.execute(
                    """SELECT 1 FROM platform_owners WHERE user_id=? UNION ALL
                   SELECT 1 FROM owner_memberships WHERE tenant_id=? AND user_id=?""",
                    (user_id, principal.tenant_id, user_id),
                ).fetchone()
            ):
                raise NetworkError(
                    "your own sign-in and platform owner identities cannot be changed here"
                )
            if target["role"] == role and target["status"] == status:
                return {"user_id": user_id, "role": role, "status": status, "revision": revision}
            connection.execute(
                "UPDATE users SET role=?,status=? WHERE tenant_id=? AND user_id=?",
                (role, status, principal.tenant_id, user_id),
            )
            revoked_sessions = connection.execute(
                """UPDATE sessions SET revoked_at=?
                   WHERE tenant_id=? AND user_id=? AND revoked_at IS NULL""",
                (_utc_text(now), principal.tenant_id, user_id),
            ).rowcount
            revoked_invites = connection.execute(
                """UPDATE human_invites SET revoked_at=? WHERE tenant_id=? AND created_by=?
                   AND consumed_at IS NULL AND revoked_at IS NULL""",
                (_utc_text(now), principal.tenant_id, user_id),
            ).rowcount
            revoked_grants = connection.execute(
                """UPDATE enrollment_tokens SET revoked_at=?
                   WHERE tenant_id=? AND created_by=? AND revoked_at IS NULL""",
                (_utc_text(now), principal.tenant_id, user_id),
            ).rowcount
            cancelled = self._expire_undelivered_actions(
                connection, principal.tenant_id, user_id, now
            )
            connection.execute(
                """UPDATE auth_challenges SET consumed_at=?
                   WHERE tenant_id=? AND user_id=? AND consumed_at IS NULL""",
                (_utc_text(now), principal.tenant_id, user_id),
            )
            updated = self._bump_identity(
                connection, principal.tenant_id, "user", user_id, revision
            )
            self.audit.append(
                connection,
                principal.tenant_id,
                "team.member_updated",
                "user",
                principal.user_id,
                "user",
                user_id,
                {
                    "previous_role": expected_role,
                    "role": role,
                    "previous_status": expected_status,
                    "status": status,
                    "revoked_sessions": revoked_sessions,
                    "revoked_invitations": revoked_invites,
                    "revoked_enrollment_grants": revoked_grants,
                    "expired_undelivered_responses": cancelled,
                },
                now,
            )
        return {"user_id": user_id, "role": role, "status": status, "revision": updated}

    @staticmethod
    def _identity_revision(
        connection: sqlite3.Connection,
        tenant_id: str,
        kind: str,
        identity_id: str,
        revision: int,
    ) -> None:
        row = connection.execute(
            """SELECT revision FROM management_revisions
               WHERE tenant_id=? AND kind=? AND identity_id=?""",
            (tenant_id, kind, identity_id),
        ).fetchone()
        if revision != (row["revision"] if row else 1):
            raise NetworkConflictError("this account changed; refresh before trying again")

    @staticmethod
    def _bump_identity(
        connection: sqlite3.Connection,
        tenant_id: str,
        kind: str,
        identity_id: str,
        revision: int,
    ) -> int:
        connection.execute(
            """INSERT INTO management_revisions VALUES(?,?,?,?)
               ON CONFLICT(tenant_id,kind,identity_id) DO UPDATE SET revision=excluded.revision""",
            (tenant_id, kind, identity_id, revision + 1),
        )
        return revision + 1

    def update_account(
        self,
        principal: SessionPrincipal,
        account_id: str,
        display_name: str,
        status: Literal["active", "disabled"],
        revision: int,
        now: datetime,
    ) -> dict[str, object]:
        name = display_name.strip()
        if (
            not name
            or len(name) > 120
            or any(ord(c) < 32 for c in name)
            or status not in {"active", "disabled"}
        ):
            raise NetworkError("enter a valid name and sign-in state")
        with self.database.connect() as connection, connection:
            connection.execute("BEGIN IMMEDIATE")
            self.networks.require_admin_in(connection, principal, now)
            target = connection.execute(
                "SELECT * FROM endpoint_accounts WHERE tenant_id=? AND account_id=?",
                (principal.tenant_id, account_id),
            ).fetchone()
            if target is None:
                raise NetworkError("this person is not in the selected network")
            self._identity_revision(
                connection, principal.tenant_id, "account", account_id, revision
            )
            if target["display_name"] == name and target["status"] == status:
                return {"account_id": account_id, "revision": revision, "status": status}
            revoked = 0
            if target["status"] != status:
                revoked = connection.execute(
                    "DELETE FROM endpoint_sessions WHERE tenant_id=? AND account_id=?",
                    (principal.tenant_id, account_id),
                ).rowcount
                connection.execute(
                    """UPDATE enrollment_tokens SET revoked_at=? WHERE token_id IN
                       (SELECT token_id FROM account_enrollment_grants
                        WHERE tenant_id=? AND account_id=?)""",
                    (_utc_text(now), principal.tenant_id, account_id),
                )
                connection.execute(
                    """UPDATE endpoint_accounts SET password_version=password_version+1
                       WHERE tenant_id=? AND account_id=?""",
                    (principal.tenant_id, account_id),
                )
                if status == "disabled":
                    connection.execute(
                        """UPDATE password_reset_requests SET resolved_at=?,resolved_by=?
                           WHERE tenant_id=? AND account_id=? AND resolved_at IS NULL""",
                        (_utc_text(now), principal.user_id, principal.tenant_id, account_id),
                    )
            connection.execute(
                """UPDATE endpoint_accounts SET display_name=?,status=?
                   WHERE tenant_id=? AND account_id=?""",
                (name, status, principal.tenant_id, account_id),
            )
            updated = self._bump_identity(
                connection, principal.tenant_id, "account", account_id, revision
            )
            self.audit.append(
                connection,
                principal.tenant_id,
                "endpoint_account.updated",
                "user",
                principal.user_id,
                "endpoint_account",
                account_id,
                {
                    "previous_status": target["status"],
                    "status": status,
                    "display_name": name,
                    "revision": updated,
                    "revoked_sessions": revoked,
                    "collector_credentials_unchanged": True,
                },
                now,
            )
        return {"account_id": account_id, "revision": updated, "status": status}

    def revoke_invite(
        self, principal: SessionPrincipal, invite_id: str, now: datetime
    ) -> dict[str, str]:
        with self.database.connect() as connection, connection:
            connection.execute("BEGIN IMMEDIATE")
            self.networks.require_admin_in(connection, principal, now)
            changed = connection.execute(
                """UPDATE human_invites SET revoked_at=? WHERE tenant_id=? AND invite_id=?
                   AND consumed_at IS NULL AND revoked_at IS NULL""",
                (_utc_text(now), principal.tenant_id, invite_id),
            ).rowcount
            if changed != 1:
                raise NetworkConflictError(
                    "this invitation was already used or revoked; refresh the team list"
                )
            self.audit.append(
                connection,
                principal.tenant_id,
                "human_invite.revoked",
                "user",
                principal.user_id,
                "human_invite",
                invite_id,
                {},
                now,
            )
        return {"status": "revoked"}
