"""Endpoint-only accounts, first-login setup, and admin-mediated password recovery."""

from __future__ import annotations

import hashlib
import hmac
import re
import secrets
import sqlite3
import uuid
from datetime import datetime, timedelta
from typing import cast

from .identity import HumanAuthorizationError, SessionError, SessionPrincipal
from .networks import NetworkError, NetworkService
from .passwords import PasswordHasher
from .store import _utc_text


class EndpointAccountService:
    """Never issue an administrator session or accept an endpoint-supplied tenant."""

    def __init__(self, networks: NetworkService, pepper: bytes) -> None:
        self.networks = networks
        self.database = networks.database
        self.hasher = PasswordHasher(pepper)
        self._pepper = hmac.digest(pepper, b"endpoint-session-v1", "sha256")

    @staticmethod
    def username(value: str) -> str:
        normalized = value.strip().lower()
        if (
            len(normalized) > 254
            or re.fullmatch(r"[a-z0-9][a-z0-9._-]{0,63}@[a-z0-9.-]+", normalized) is None
        ):
            raise NetworkError("Enter the full account name your network admin gave you.")
        return normalized

    def _token_hash(self, token: str) -> str:
        return hmac.digest(self._pepper, token.encode(), "sha256").hex()

    def create_account(
        self, principal: SessionPrincipal, alias: str, display_name: str, now: datetime
    ) -> dict[str, object]:
        self.networks.require_admin(principal)
        if re.fullmatch(r"[a-z0-9][a-z0-9._-]{0,63}", alias) is None:
            raise NetworkError("Use a lowercase account name without an @domain suffix.")
        name = display_name.strip()
        if not name or len(name) > 120 or any(ord(char) < 32 for char in name):
            raise NetworkError("Enter a display name of 1-120 characters.")
        password = secrets.token_urlsafe(24)
        encoded = self.hasher.hash(password)
        account_id = str(uuid.uuid4())
        with self.database.connect() as connection, connection:
            connection.execute("BEGIN IMMEDIATE")
            self.networks.require_admin_in(connection, principal, now)
            domain = connection.execute(
                """SELECT n.login_domain FROM network_namespaces n JOIN tenants t
                   ON t.tenant_id=n.tenant_id WHERE n.tenant_id=? AND t.status='active'""",
                (principal.tenant_id,),
            ).fetchone()
            if domain is None:
                raise NetworkError("This network needs a login namespace before adding people.")
            username = self.username(f"{alias}@{domain['login_domain']}")
            count = connection.execute(
                "SELECT COUNT(*) FROM endpoint_accounts WHERE tenant_id=?",
                (principal.tenant_id,),
            ).fetchone()[0]
            if count >= 1000:
                raise NetworkError("This network has reached its 1,000-account safety limit.")
            try:
                connection.execute(
                    """INSERT INTO endpoint_accounts(tenant_id,account_id,username,display_name,
                       password_hash,initial_password_expires_at,status,created_at)
                       VALUES (?, ?, ?, ?, ?, ?, 'active', ?)""",
                    (
                        principal.tenant_id,
                        account_id,
                        username,
                        name,
                        encoded,
                        _utc_text(now + timedelta(days=7)),
                        _utc_text(now),
                    ),
                )
            except sqlite3.IntegrityError as exc:
                raise NetworkError("That account name is already in use.") from exc
            self._audit(
                connection,
                principal.tenant_id,
                "endpoint_account.created",
                principal.user_id,
                account_id,
                now,
            )
        return {
            "account_id": account_id,
            "username": username,
            "initial_password": password,
            "must_change_password": bool(len(password)),
            "expires_at": _utc_text(now + timedelta(days=7)),
        }

    def list_accounts(self, principal: SessionPrincipal) -> list[dict[str, object]]:
        self.networks.require_admin(principal)
        with self.database.connect() as connection:
            rows = connection.execute(
                """SELECT a.account_id,a.username,a.display_name,a.status,
                          a.created_at,a.setup_completed_at,
                          COALESCE(r.revision,1) AS revision
                   FROM endpoint_accounts a LEFT JOIN management_revisions r
                     ON r.tenant_id=a.tenant_id AND r.kind='account' AND r.identity_id=a.account_id
                   WHERE a.tenant_id=? ORDER BY a.created_at LIMIT 1000""",
                (principal.tenant_id,),
            ).fetchall()
        return [dict(row) for row in rows]

    def login(self, username: str, password: str, now: datetime) -> dict[str, object]:
        try:
            normalized = self.username(username)
        except NetworkError as exc:
            self.hasher.dummy_verify(password)
            raise SessionError("account credentials are invalid") from exc
        with self.database.connect() as connection:
            row = connection.execute(
                """SELECT a.* FROM endpoint_accounts a JOIN tenants t ON t.tenant_id=a.tenant_id
                   JOIN network_namespaces n ON n.tenant_id=a.tenant_id
                   WHERE a.username=? AND a.status='active' AND t.status='active'
                     AND n.login_domain=?""",
                (normalized, normalized.split("@")[1]),
            ).fetchone()
        if row is None:
            self.hasher.dummy_verify(password)
            raise SessionError("account credentials are invalid")
        if not self.hasher.verify(password, str(row["password_hash"])):
            raise SessionError("account credentials are invalid")
        with self.database.connect() as connection, connection:
            connection.execute("BEGIN IMMEDIATE")
            current = connection.execute(
                """SELECT a.* FROM endpoint_accounts a JOIN tenants t ON t.tenant_id=a.tenant_id
                   WHERE a.tenant_id=? AND a.account_id=? AND a.status='active'
                   AND t.status='active' AND a.password_version=?""",
                (row["tenant_id"], row["account_id"], row["password_version"]),
            ).fetchone()
            if current is None or (
                current["initial_password_expires_at"] is not None
                and str(current["initial_password_expires_at"]) <= _utc_text(now)
            ):
                raise SessionError("account credentials are invalid")
            return self._issue_session(connection, current, now)

    def _issue_session(
        self, connection: sqlite3.Connection, row: sqlite3.Row, now: datetime
    ) -> dict[str, object]:
        token = secrets.token_urlsafe(32)
        expires = now + timedelta(minutes=15)
        connection.execute("DELETE FROM endpoint_sessions WHERE expires_at<=?", (_utc_text(now),))
        # Keep the interactive account surface bounded; collectors have separate credentials.
        connection.execute(
            "DELETE FROM endpoint_sessions WHERE tenant_id=? AND account_id=?",
            (row["tenant_id"], row["account_id"]),
        )
        connection.execute(
            "INSERT INTO endpoint_sessions VALUES (?, ?, ?, ?, ?)",
            (
                self._token_hash(token),
                row["tenant_id"],
                row["account_id"],
                row["password_version"],
                _utc_text(expires),
            ),
        )
        return {
            "token": token,
            "expires_at": _utc_text(expires),
            "account": self._public_account(row),
        }

    def _session(
        self, connection: sqlite3.Connection, token: str, now: datetime, *, ready: bool = False
    ) -> sqlite3.Row:
        if not 32 <= len(token) <= 128:
            raise SessionError("endpoint session is inactive")
        row = connection.execute(
            """SELECT a.*,t.display_name AS network_name FROM endpoint_sessions s
               JOIN endpoint_accounts a ON a.tenant_id=s.tenant_id AND a.account_id=s.account_id
               JOIN tenants t ON t.tenant_id=a.tenant_id
               WHERE s.token_hash=? AND s.expires_at>? AND s.password_version=a.password_version
               AND a.status='active' AND t.status='active'""",
            (self._token_hash(token), _utc_text(now)),
        ).fetchone()
        if row is None:
            raise SessionError("endpoint session is inactive")
        if ready and row["setup_completed_at"] is None:
            raise HumanAuthorizationError("change the initial password before connecting this Mac")
        return cast(sqlite3.Row, row)

    @staticmethod
    def _public_account(row: sqlite3.Row) -> dict[str, object]:
        return {
            "account_id": row["account_id"],
            "username": row["username"],
            "display_name": row["display_name"],
            "tenant_id": row["tenant_id"],
            "must_change_password": row["setup_completed_at"] is None,
        }

    def me(self, token: str, now: datetime) -> dict[str, object]:
        with self.database.connect() as connection:
            row = self._session(connection, token, now)
            result = self._public_account(row)
            result["network_name"] = row["network_name"]
            return result

    def logout(self, token: str) -> None:
        with self.database.connect() as connection:
            connection.execute(
                "DELETE FROM endpoint_sessions WHERE token_hash=?", (self._token_hash(token),)
            )

    def change_password(self, token: str, password: str, now: datetime) -> dict[str, object]:
        with self.database.connect() as connection:
            prior = self._session(connection, token, now)
        if prior["setup_completed_at"] is not None:
            raise HumanAuthorizationError("ask your network admin for a password reset")
        if self.hasher.verify(password, str(prior["password_hash"])):
            raise NetworkError("Choose a different password from the one your admin supplied.")
        encoded = self.hasher.hash(password)
        with self.database.connect() as connection, connection:
            connection.execute("BEGIN IMMEDIATE")
            row = self._session(connection, token, now)
            self._replace_password(connection, row, encoded, now, complete_setup=True)
            self._audit(
                connection,
                str(row["tenant_id"]),
                "endpoint_account.password_changed",
                str(row["account_id"]),
                str(row["account_id"]),
                now,
            )
            updated = connection.execute(
                "SELECT * FROM endpoint_accounts WHERE tenant_id=? AND account_id=?",
                (row["tenant_id"], row["account_id"]),
            ).fetchone()
            assert updated is not None
            return self._issue_session(connection, updated, now)

    def request_reset(self, username: str, now: datetime) -> None:
        try:
            normalized = self.username(username)
        except NetworkError:
            return
        with self.database.connect() as connection, connection:
            connection.execute("BEGIN IMMEDIATE")
            row = connection.execute(
                """SELECT a.* FROM endpoint_accounts a JOIN tenants t ON t.tenant_id=a.tenant_id
                   WHERE a.username=? AND a.status='active' AND t.status='active'""",
                (normalized,),
            ).fetchone()
            if row is None:
                return
            request_id = str(uuid.uuid4())
            changed = connection.execute(
                """INSERT OR IGNORE INTO password_reset_requests(
                   request_id,tenant_id,account_id,requested_at) VALUES (?, ?, ?, ?)""",
                (request_id, row["tenant_id"], row["account_id"], _utc_text(now)),
            )
            if changed.rowcount:
                self._audit(
                    connection,
                    str(row["tenant_id"]),
                    "endpoint_account.reset_requested",
                    "unauthenticated",
                    str(row["account_id"]),
                    now,
                )

    def reset_requests(self, principal: SessionPrincipal) -> list[dict[str, object]]:
        self.networks.require_admin(principal)
        with self.database.connect() as connection:
            rows = connection.execute(
                """SELECT r.request_id,r.requested_at,a.account_id,a.username,a.display_name
                   FROM password_reset_requests r JOIN endpoint_accounts a
                   ON a.tenant_id=r.tenant_id AND a.account_id=r.account_id
                   WHERE r.tenant_id=? AND r.resolved_at IS NULL
                   ORDER BY r.requested_at LIMIT 1000""",
                (principal.tenant_id,),
            ).fetchall()
        return [dict(row) for row in rows]

    def reset_password(
        self, principal: SessionPrincipal, request_id: str, now: datetime
    ) -> dict[str, object]:
        self.networks.require_admin(principal)
        password = secrets.token_urlsafe(24)
        encoded = self.hasher.hash(password)
        with self.database.connect() as connection, connection:
            connection.execute("BEGIN IMMEDIATE")
            self.networks.require_admin_in(connection, principal, now)
            row = connection.execute(
                """SELECT a.* FROM password_reset_requests r JOIN endpoint_accounts a
                   ON a.tenant_id=r.tenant_id AND a.account_id=r.account_id
                   WHERE r.tenant_id=? AND r.request_id=? AND r.resolved_at IS NULL
                   AND a.status='active'""",
                (principal.tenant_id, request_id),
            ).fetchone()
            if row is None:
                raise NetworkError("That reset request is unavailable or already resolved.")
            self._replace_password(connection, row, encoded, now, complete_setup=False)
            connection.execute(
                "UPDATE password_reset_requests SET resolved_at=?,resolved_by=? WHERE request_id=?",
                (_utc_text(now), principal.user_id, request_id),
            )
            self._audit(
                connection,
                principal.tenant_id,
                "endpoint_account.password_reset",
                principal.user_id,
                str(row["account_id"]),
                now,
            )
        return {
            "username": row["username"],
            "password": password,
            "must_change_password": row["setup_completed_at"] is None,
        }

    @staticmethod
    def _replace_password(
        connection: sqlite3.Connection,
        row: sqlite3.Row,
        encoded: str,
        now: datetime,
        *,
        complete_setup: bool,
    ) -> None:
        completed = row["setup_completed_at"] or (_utc_text(now) if complete_setup else None)
        expires = None if completed else _utc_text(now + timedelta(days=7))
        connection.execute(
            """UPDATE endpoint_accounts SET password_hash=?,password_version=password_version+1,
               setup_completed_at=?,initial_password_expires_at=?
               WHERE tenant_id=? AND account_id=?""",
            (encoded, completed, expires, row["tenant_id"], row["account_id"]),
        )
        connection.execute(
            "DELETE FROM endpoint_sessions WHERE tenant_id=? AND account_id=?",
            (row["tenant_id"], row["account_id"]),
        )
        connection.execute(
            """UPDATE enrollment_tokens SET revoked_at=? WHERE used_at IS NULL AND token_id IN
               (SELECT token_id FROM account_enrollment_grants
                WHERE tenant_id=? AND account_id=?)""",
            (_utc_text(now), row["tenant_id"], row["account_id"]),
        )

    def enrollment_grant(self, token: str, device_id: str, now: datetime) -> dict[str, object]:
        if re.fullmatch(r"[A-Za-z0-9._:-]{1,128}", device_id) is None:
            raise NetworkError("This Mac needs a valid device identity.")
        grant = secrets.token_urlsafe(32)
        grant_id = str(uuid.uuid4())
        expires = now + timedelta(minutes=5)
        with self.database.connect() as connection, connection:
            connection.execute("BEGIN IMMEDIATE")
            row = self._session(connection, token, now, ready=True)
            # A user cannot mint an unbounded stockpile of usable enrollment credentials.
            connection.execute(
                """UPDATE enrollment_tokens SET revoked_at=? WHERE used_at IS NULL AND token_id IN
                   (SELECT token_id FROM account_enrollment_grants
                    WHERE tenant_id=? AND account_id=?)""",
                (_utc_text(now), row["tenant_id"], row["account_id"]),
            )
            connection.execute(
                """INSERT INTO enrollment_tokens(token_id,tenant_id,token_hash,expected_device_id,
                   created_by,created_at,expires_at) VALUES (?, ?, ?, ?, ?, ?, ?)""",
                (
                    grant_id,
                    row["tenant_id"],
                    hashlib.sha256(grant.encode()).hexdigest(),
                    device_id,
                    row["account_id"],
                    _utc_text(now),
                    _utc_text(expires),
                ),
            )
            connection.execute(
                "INSERT INTO account_enrollment_grants VALUES (?, ?, ?, ?)",
                (grant_id, row["tenant_id"], row["account_id"], row["password_version"]),
            )
            self._audit(
                connection,
                str(row["tenant_id"]),
                "endpoint_account.enrollment_requested",
                str(row["account_id"]),
                grant_id,
                now,
            )
        return {"token": grant, "device_id": device_id, "expires_at": _utc_text(expires)}

    def _audit(
        self,
        connection: sqlite3.Connection,
        tenant_id: str,
        action: str,
        actor_id: str,
        resource_id: str,
        now: datetime,
    ) -> None:
        self.networks.audit.append(
            connection,
            tenant_id,
            action,
            "account_workflow",
            actor_id,
            "endpoint_account",
            resource_id,
            {},
            now,
        )
