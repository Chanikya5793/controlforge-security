"""Standalone passkey identity, session, recovery, and authorization services."""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import re
import secrets
import sqlite3
import uuid
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from enum import Enum
from typing import Literal, Optional, cast

from .audit import StandaloneAuditLog
from .database import StandaloneDatabase
from .passkeys import PasskeyAdapter
from .store import _utc_text


class IdentityError(RuntimeError):
    """Base class for bounded human-identity failures."""


class BootstrapError(IdentityError):
    """Raised when standalone bootstrap cannot continue."""


class ChallengeError(IdentityError):
    """Raised for expired, replayed, or invalid passkey challenges."""


class SessionError(IdentityError):
    """Raised when a human session is absent or inactive."""


class HumanAuthorizationError(IdentityError):
    """Raised when a role lacks a capability or tenant context."""


class HumanInviteError(IdentityError):
    """Raised when a human invitation cannot safely continue."""


Role = Literal["viewer", "analyst", "responder", "admin"]
InviteRole = Literal["responder", "admin"]


class Capability(str, Enum):
    VIEW = "view"
    TRIAGE = "triage"
    DISPOSITION = "disposition"
    PROPOSE_RESPONSE = "propose_response"
    APPROVE_RESPONSE = "approve_response"
    MANAGE = "manage"


ROLE_CAPABILITIES: dict[Role, frozenset[Capability]] = {
    "viewer": frozenset({Capability.VIEW}),
    "analyst": frozenset({Capability.VIEW, Capability.TRIAGE, Capability.DISPOSITION}),
    "responder": frozenset(
        {
            Capability.VIEW,
            Capability.TRIAGE,
            Capability.DISPOSITION,
            Capability.PROPOSE_RESPONSE,
            Capability.APPROVE_RESPONSE,
        }
    ),
    "admin": frozenset(Capability),
}


@dataclass(frozen=True)
class AuthCeremony:
    challenge_id: str
    options: dict[str, object]
    expires_at: datetime


@dataclass(frozen=True)
class SessionPrincipal:
    tenant_id: str
    user_id: str
    email: str
    display_name: str
    role: Role
    session_id: str
    expires_at: datetime
    csrf_hash: str


@dataclass(frozen=True)
class SessionIssue:
    token: str
    csrf_token: str
    principal: SessionPrincipal
    recovery_codes: tuple[str, ...] = ()


@dataclass(frozen=True)
class BootstrapStatus:
    configured: bool


@dataclass(frozen=True)
class HumanInviteIssue:
    invite_id: str
    token: str
    role: InviteRole
    expires_at: datetime


class HumanIdentityService:
    """Own first-admin bootstrap, passkeys, opaque sessions, and recovery."""

    _SLUG = re.compile(r"^[a-z0-9]+(?:-[a-z0-9]+)*$")

    def __init__(
        self,
        database: StandaloneDatabase,
        passkeys: PasskeyAdapter,
        session_pepper: bytes,
        recovery_pepper: bytes,
        *,
        session_ttl_seconds: int = 28_800,
        challenge_ttl_seconds: int = 300,
        audit: Optional[StandaloneAuditLog] = None,
    ) -> None:
        if len(session_pepper) < 32 or len(recovery_pepper) < 32:
            raise ValueError("identity peppers must contain at least 32 bytes")
        if session_ttl_seconds < 300 or session_ttl_seconds > 86_400:
            raise ValueError("session_ttl_seconds must be between 300 and 86400")
        if challenge_ttl_seconds < 60 or challenge_ttl_seconds > 900:
            raise ValueError("challenge_ttl_seconds must be between 60 and 900")
        self._database = database
        self._passkeys = passkeys
        self._session_pepper = session_pepper
        self._recovery_pepper = recovery_pepper
        self._session_ttl_seconds = session_ttl_seconds
        self._challenge_ttl_seconds = challenge_ttl_seconds
        self._audit = audit

    def bootstrap_status(self) -> BootstrapStatus:
        with self._database.connect() as connection:
            count = connection.execute(
                "SELECT COUNT(*) FROM users WHERE role = 'admin' AND status = 'active'"
            ).fetchone()[0]
        return BootstrapStatus(configured=int(count) > 0)

    def issue_bootstrap_token(self, now: datetime, ttl_seconds: int = 900) -> str:
        """Issue a console-delivered bootstrap secret; never expose this over HTTP."""

        if ttl_seconds < 60 or ttl_seconds > 3_600:
            raise ValueError("bootstrap ttl must be between 60 and 3600 seconds")
        if self.bootstrap_status().configured:
            raise BootstrapError("standalone bootstrap is already complete")
        token = secrets.token_urlsafe(32)
        with self._database.connect() as connection:
            connection.execute(
                """
                INSERT INTO bootstrap_tokens(token_hash, created_at, expires_at)
                VALUES (?, ?, ?)
                """,
                (
                    self._hash(self._session_pepper, "bootstrap", token),
                    _utc_text(now),
                    _utc_text(now + timedelta(seconds=ttl_seconds)),
                ),
            )
        return token

    def begin_bootstrap(
        self,
        token: str,
        tenant_slug: str,
        tenant_display_name: str,
        email: str,
        display_name: str,
        now: datetime,
    ) -> AuthCeremony:
        normalized_email = self._normalize_email(email)
        if self._SLUG.fullmatch(tenant_slug) is None or len(tenant_slug) > 48:
            raise BootstrapError("tenant slug is invalid")
        if not tenant_display_name.strip() or len(tenant_display_name) > 120:
            raise BootstrapError("tenant display name is invalid")
        if not display_name.strip() or len(display_name) > 120:
            raise BootstrapError("administrator display name is invalid")
        token_hash = self._hash(self._session_pepper, "bootstrap", token)
        self._require_bootstrap_token(token_hash, now)
        user_id = str(uuid.uuid4())
        context: dict[str, object] = {
            "token_hash": token_hash,
            "tenant_slug": tenant_slug,
            "tenant_display_name": tenant_display_name.strip(),
            "email": normalized_email,
            "display_name": display_name.strip(),
            "user_id": user_id,
        }
        challenge, expires_at = self._create_challenge("bootstrap", None, None, context, now)
        return AuthCeremony(
            challenge_id=challenge[0],
            options=self._passkeys.registration_options(
                user_id,
                normalized_email,
                display_name.strip(),
                challenge[1],
                [],
            ),
            expires_at=expires_at,
        )

    def complete_bootstrap(
        self,
        token: str,
        challenge_id: str,
        response: dict[str, object],
        now: datetime,
    ) -> SessionIssue:
        row, context, challenge = self._load_challenge(challenge_id, "bootstrap", now)
        token_hash = self._hash(self._session_pepper, "bootstrap", token)
        if context.get("token_hash") != token_hash:
            raise BootstrapError("bootstrap token does not match the challenge")
        self._require_bootstrap_token(token_hash, now)
        try:
            verified = self._passkeys.verify_registration(response, challenge)
        except Exception as exc:
            raise ChallengeError("passkey registration verification failed") from exc
        tenant_id = str(uuid.uuid4())
        user_id = self._context_text(context, "user_id")
        recovery_codes = self._new_recovery_codes()
        with self._database.connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            try:
                self._consume_challenge(connection, row, now)
                token_change = connection.execute(
                    """
                    UPDATE bootstrap_tokens SET used_at = ?
                    WHERE token_hash = ? AND used_at IS NULL AND revoked_at IS NULL
                      AND expires_at > ?
                    """,
                    (_utc_text(now), token_hash, _utc_text(now)),
                )
                existing_admin = connection.execute(
                    "SELECT 1 FROM users WHERE role = 'admin' AND status = 'active'"
                ).fetchone()
                if token_change.rowcount != 1 or existing_admin is not None:
                    raise BootstrapError("bootstrap token is no longer active")
                connection.execute(
                    """
                    INSERT INTO tenants(tenant_id, slug, display_name, status, created_at)
                    VALUES (?, ?, ?, 'active', ?)
                    """,
                    (
                        tenant_id,
                        self._context_text(context, "tenant_slug"),
                        self._context_text(context, "tenant_display_name"),
                        _utc_text(now),
                    ),
                )
                connection.execute(
                    """
                    INSERT INTO users(
                        tenant_id, user_id, email, display_name, role, status, created_at
                    ) VALUES (?, ?, ?, ?, 'admin', 'active', ?)
                    """,
                    (
                        tenant_id,
                        user_id,
                        self._context_text(context, "email"),
                        self._context_text(context, "display_name"),
                        _utc_text(now),
                    ),
                )
                self._insert_passkey(
                    connection,
                    tenant_id,
                    user_id,
                    verified.credential_id,
                    verified.public_key,
                    verified.sign_count,
                    "Initial passkey",
                    now,
                )
                connection.execute(
                    "INSERT INTO platform_owners VALUES (1, ?, ?, ?)",
                    (tenant_id, user_id, _utc_text(now)),
                )
                for recovery_code in recovery_codes:
                    connection.execute(
                        """
                        INSERT INTO recovery_codes(
                            tenant_id, user_id, code_hash, created_at
                        ) VALUES (?, ?, ?, ?)
                        """,
                        (
                            tenant_id,
                            user_id,
                            self._recovery_hash(recovery_code),
                            _utc_text(now),
                        ),
                    )
                issue = self._issue_session(connection, tenant_id, user_id, now)
                connection.execute("COMMIT")
            except Exception:
                if connection.in_transaction:
                    connection.execute("ROLLBACK")
                raise
        return SessionIssue(
            issue.token,
            issue.csrf_token,
            issue.principal,
            tuple(recovery_codes),
        )

    def begin_authentication(
        self,
        tenant_slug: str,
        email: str,
        now: datetime,
    ) -> AuthCeremony:
        normalized_email = self._normalize_email(email)
        with self._database.connect() as connection:
            user = connection.execute(
                """
                SELECT u.tenant_id, u.user_id
                FROM users u JOIN tenants t ON t.tenant_id = u.tenant_id
                WHERE t.slug = ? AND t.status = 'active'
                  AND u.email = ? AND u.status = 'active'
                """,
                (tenant_slug, normalized_email),
            ).fetchone()
            if user is None:
                raise ChallengeError("authentication cannot be started")
            credentials = connection.execute(
                """
                SELECT credential_id FROM passkey_credentials
                WHERE tenant_id = ? AND user_id = ? AND revoked_at IS NULL
                ORDER BY created_at
                """,
                (user["tenant_id"], user["user_id"]),
            ).fetchall()
        credential_ids = [str(item["credential_id"]) for item in credentials]
        if not credential_ids:
            raise ChallengeError("authentication cannot be started")
        challenge, expires_at = self._create_challenge(
            "authentication",
            str(user["tenant_id"]),
            str(user["user_id"]),
            {},
            now,
        )
        return AuthCeremony(
            challenge[0],
            self._passkeys.authentication_options(challenge[1], credential_ids),
            expires_at,
        )

    def issue_human_invite(
        self,
        principal: SessionPrincipal,
        email: str,
        display_name: str,
        role: InviteRole,
        now: datetime,
        ttl_seconds: int = 900,
    ) -> HumanInviteIssue:
        """Create a tenant-bound one-use invite whose plaintext is returned once."""

        self.require_capability(principal, principal.tenant_id, Capability.MANAGE)
        if self._audit is None:
            raise HumanInviteError("human invite audit is unavailable")
        normalized_email = self._normalize_email(email)
        normalized_name = display_name.strip()
        if not normalized_name or len(normalized_name) > 120:
            raise HumanInviteError("invite display name is invalid")
        if role not in {"responder", "admin"}:
            raise HumanInviteError("invite role must be responder or admin")
        if ttl_seconds < 60 or ttl_seconds > 3_600:
            raise HumanInviteError("invite ttl must be between 60 and 3600 seconds")
        invite_id = str(uuid.uuid4())
        token = secrets.token_urlsafe(32)
        expires_at = now + timedelta(seconds=ttl_seconds)
        with self._database.connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            try:
                self.require_current_capability(connection, principal, Capability.MANAGE, now)
                existing_user = connection.execute(
                    """
                    SELECT 1 FROM users
                    WHERE tenant_id = ? AND email = ?
                    """,
                    (principal.tenant_id, normalized_email),
                ).fetchone()
                active_invite = connection.execute(
                    """
                    SELECT 1 FROM human_invites
                    WHERE tenant_id = ? AND email = ?
                      AND consumed_at IS NULL AND revoked_at IS NULL AND expires_at > ?
                    """,
                    (principal.tenant_id, normalized_email, _utc_text(now)),
                ).fetchone()
                if existing_user is not None or active_invite is not None:
                    raise HumanInviteError("invite identity is already active")
                connection.execute(
                    """
                    INSERT INTO human_invites(
                        invite_id, tenant_id, token_hash, email, display_name, role,
                        created_by, created_at, expires_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        invite_id,
                        principal.tenant_id,
                        self._hash(self._session_pepper, "human-invite", token),
                        normalized_email,
                        normalized_name,
                        role,
                        principal.user_id,
                        _utc_text(now),
                        _utc_text(expires_at),
                    ),
                )
                self._audit.append(
                    connection,
                    principal.tenant_id,
                    "human_invite.issued",
                    "user",
                    principal.user_id,
                    "human_invite",
                    invite_id,
                    {
                        "expires_at": _utc_text(expires_at),
                        "role": role,
                    },
                    now,
                )
                connection.execute("COMMIT")
            except Exception:
                if connection.in_transaction:
                    connection.execute("ROLLBACK")
                raise
        return HumanInviteIssue(invite_id, token, role, expires_at)

    def begin_human_invite(self, token: str, now: datetime) -> AuthCeremony:
        token_hash = self._hash(self._session_pepper, "human-invite", token)
        with self._database.connect() as connection:
            invite = connection.execute(
                """
                SELECT i.invite_id, i.email, i.display_name, i.expires_at
                FROM human_invites i
                JOIN tenants t ON t.tenant_id = i.tenant_id
                WHERE i.token_hash = ? AND i.consumed_at IS NULL AND i.revoked_at IS NULL
                  AND i.expires_at > ? AND t.status = 'active'
                """,
                (token_hash, _utc_text(now)),
            ).fetchone()
        if invite is None:
            raise HumanInviteError("human invite is inactive")
        user_id = str(uuid.uuid4())
        challenge_id = str(uuid.uuid4())
        challenge = secrets.token_bytes(32)
        invite_expiry = self._parse_time(str(invite["expires_at"]))
        expires_at = min(
            invite_expiry,
            now + timedelta(seconds=self._challenge_ttl_seconds),
        )
        with self._database.connect() as connection:
            connection.execute(
                """
                INSERT INTO human_invite_challenges(
                    challenge_id, invite_id, user_id, challenge_b64, created_at, expires_at
                ) VALUES (?, ?, ?, ?, ?, ?)
                """,
                (
                    challenge_id,
                    invite["invite_id"],
                    user_id,
                    base64.urlsafe_b64encode(challenge).decode("ascii"),
                    _utc_text(now),
                    _utc_text(expires_at),
                ),
            )
        return AuthCeremony(
            challenge_id,
            self._passkeys.registration_options(
                user_id,
                str(invite["email"]),
                str(invite["display_name"]),
                challenge,
                [],
            ),
            expires_at,
        )

    def complete_human_invite(
        self,
        token: str,
        challenge_id: str,
        response: dict[str, object],
        now: datetime,
    ) -> SessionIssue:
        if self._audit is None:
            raise HumanInviteError("human invite audit is unavailable")
        token_hash = self._hash(self._session_pepper, "human-invite", token)
        with self._database.connect() as connection:
            row = connection.execute(
                """
                SELECT c.challenge_id, c.user_id, c.challenge_b64,
                       c.expires_at AS challenge_expires_at, c.consumed_at AS challenge_used,
                       i.invite_id, i.tenant_id, i.email, i.display_name, i.role,
                       i.expires_at AS invite_expires_at, i.consumed_at AS invite_used,
                       i.revoked_at
                FROM human_invite_challenges c
                JOIN human_invites i ON i.invite_id = c.invite_id
                JOIN tenants t ON t.tenant_id = i.tenant_id
                WHERE c.challenge_id = ? AND i.token_hash = ? AND t.status = 'active'
                """,
                (challenge_id, token_hash),
            ).fetchone()
        if (
            row is None
            or row["challenge_used"] is not None
            or row["invite_used"] is not None
            or row["revoked_at"] is not None
            or self._parse_time(str(row["challenge_expires_at"])) <= now.astimezone(timezone.utc)
            or self._parse_time(str(row["invite_expires_at"])) <= now.astimezone(timezone.utc)
        ):
            raise HumanInviteError("human invite challenge is inactive")
        try:
            challenge = base64.urlsafe_b64decode(str(row["challenge_b64"]))
            verified = self._passkeys.verify_registration(response, challenge)
        except Exception as exc:
            raise HumanInviteError("invite passkey verification failed") from exc
        recovery_codes = self._new_recovery_codes()
        with self._database.connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            try:
                challenge_change = connection.execute(
                    """
                    UPDATE human_invite_challenges SET consumed_at = ?
                    WHERE challenge_id = ? AND consumed_at IS NULL AND expires_at > ?
                    """,
                    (_utc_text(now), challenge_id, _utc_text(now)),
                )
                invite_change = connection.execute(
                    """
                    UPDATE human_invites SET consumed_at = ?
                    WHERE invite_id = ? AND token_hash = ?
                      AND consumed_at IS NULL AND revoked_at IS NULL AND expires_at > ?
                    """,
                    (
                        _utc_text(now),
                        row["invite_id"],
                        token_hash,
                        _utc_text(now),
                    ),
                )
                if challenge_change.rowcount != 1 or invite_change.rowcount != 1:
                    raise HumanInviteError("human invite was already consumed or expired")
                tenant_id = str(row["tenant_id"])
                issuer = connection.execute(
                    "SELECT created_by FROM human_invites WHERE invite_id=?",
                    (row["invite_id"],),
                ).fetchone()
                if issuer is None or not self._active_admin(
                    connection, tenant_id, str(issuer["created_by"])
                ):
                    raise HumanInviteError("human invite issuer is no longer authorized")
                user_id = str(row["user_id"])
                connection.execute(
                    """
                    INSERT INTO users(
                        tenant_id, user_id, email, display_name, role, status, created_at
                    ) VALUES (?, ?, ?, ?, ?, 'active', ?)
                    """,
                    (
                        tenant_id,
                        user_id,
                        row["email"],
                        row["display_name"],
                        row["role"],
                        _utc_text(now),
                    ),
                )
                self._insert_passkey(
                    connection,
                    tenant_id,
                    user_id,
                    verified.credential_id,
                    verified.public_key,
                    verified.sign_count,
                    "Invited passkey",
                    now,
                )
                for recovery_code in recovery_codes:
                    connection.execute(
                        """
                        INSERT INTO recovery_codes(
                            tenant_id, user_id, code_hash, created_at
                        ) VALUES (?, ?, ?, ?)
                        """,
                        (
                            tenant_id,
                            user_id,
                            self._recovery_hash(recovery_code),
                            _utc_text(now),
                        ),
                    )
                self._audit.append(
                    connection,
                    tenant_id,
                    "human_invite.accepted",
                    "user",
                    user_id,
                    "human_invite",
                    str(row["invite_id"]),
                    {"role": str(row["role"])},
                    now,
                )
                issue = self._issue_session(connection, tenant_id, user_id, now)
                connection.execute("COMMIT")
            except Exception:
                if connection.in_transaction:
                    connection.execute("ROLLBACK")
                raise
        return SessionIssue(
            issue.token,
            issue.csrf_token,
            issue.principal,
            tuple(recovery_codes),
        )

    def complete_authentication(
        self,
        challenge_id: str,
        response: dict[str, object],
        now: datetime,
    ) -> SessionIssue:
        row, _, challenge = self._load_challenge(challenge_id, "authentication", now)
        tenant_id = self._required_row_text(row, "tenant_id")
        user_id = self._required_row_text(row, "user_id")
        try:
            credential_id = self._passkeys.response_credential_id(response)
        except Exception as exc:
            raise ChallengeError("passkey assertion has no valid credential") from exc
        with self._database.connect() as connection:
            credential = connection.execute(
                """
                SELECT public_key, sign_count FROM passkey_credentials
                WHERE tenant_id = ? AND user_id = ? AND credential_id = ?
                  AND revoked_at IS NULL
                """,
                (tenant_id, user_id, credential_id),
            ).fetchone()
        if credential is None:
            raise ChallengeError("passkey assertion credential is unavailable")
        try:
            verified = self._passkeys.verify_authentication(
                response,
                challenge,
                bytes(credential["public_key"]),
                int(credential["sign_count"]),
            )
        except Exception as exc:
            raise ChallengeError("passkey assertion verification failed") from exc
        if verified.credential_id != credential_id:
            raise ChallengeError("passkey assertion credential does not match")
        with self._database.connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            try:
                self._consume_challenge(connection, row, now)
                connection.execute(
                    """
                    UPDATE passkey_credentials
                    SET sign_count = ?, last_used_at = ?
                    WHERE tenant_id = ? AND credential_id = ? AND revoked_at IS NULL
                    """,
                    (
                        verified.new_sign_count,
                        _utc_text(now),
                        tenant_id,
                        credential_id,
                    ),
                )
                issue = self._issue_session(connection, tenant_id, user_id, now)
                connection.execute("COMMIT")
            except Exception:
                if connection.in_transaction:
                    connection.execute("ROLLBACK")
                raise
        return issue

    def begin_passkey_registration(
        self,
        principal: SessionPrincipal,
        now: datetime,
    ) -> AuthCeremony:
        with self._database.connect() as connection:
            credentials = connection.execute(
                """
                SELECT credential_id FROM passkey_credentials
                WHERE tenant_id = ? AND user_id = ? AND revoked_at IS NULL
                """,
                (principal.tenant_id, principal.user_id),
            ).fetchall()
        challenge, expires_at = self._create_challenge(
            "registration", principal.tenant_id, principal.user_id, {}, now
        )
        return AuthCeremony(
            challenge[0],
            self._passkeys.registration_options(
                principal.user_id,
                principal.email,
                principal.display_name,
                challenge[1],
                [str(row["credential_id"]) for row in credentials],
            ),
            expires_at,
        )

    def complete_passkey_registration(
        self,
        principal: SessionPrincipal,
        challenge_id: str,
        response: dict[str, object],
        label: str,
        now: datetime,
    ) -> str:
        row, _, challenge = self._load_challenge(challenge_id, "registration", now)
        if row["tenant_id"] != principal.tenant_id or row["user_id"] != principal.user_id:
            raise HumanAuthorizationError("passkey challenge belongs to another principal")
        if not label.strip() or len(label) > 120:
            raise ChallengeError("passkey label is invalid")
        try:
            verified = self._passkeys.verify_registration(response, challenge)
        except Exception as exc:
            raise ChallengeError("passkey registration verification failed") from exc
        with self._database.connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            try:
                self._consume_challenge(connection, row, now)
                self._insert_passkey(
                    connection,
                    principal.tenant_id,
                    principal.user_id,
                    verified.credential_id,
                    verified.public_key,
                    verified.sign_count,
                    label.strip(),
                    now,
                )
                connection.execute("COMMIT")
            except Exception:
                if connection.in_transaction:
                    connection.execute("ROLLBACK")
                raise
        return verified.credential_id

    def recover_session(
        self,
        tenant_slug: str,
        email: str,
        recovery_code: str,
        now: datetime,
    ) -> SessionIssue:
        normalized_email = self._normalize_email(email)
        code_hash = self._recovery_hash(recovery_code)
        with self._database.connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            try:
                row = connection.execute(
                    """
                    SELECT u.tenant_id, u.user_id
                    FROM users u JOIN tenants t ON t.tenant_id = u.tenant_id
                    JOIN recovery_codes r
                      ON r.tenant_id = u.tenant_id AND r.user_id = u.user_id
                    WHERE t.slug = ? AND t.status = 'active'
                      AND u.email = ? AND u.status = 'active'
                      AND r.code_hash = ? AND r.used_at IS NULL
                    """,
                    (tenant_slug, normalized_email, code_hash),
                ).fetchone()
                if row is None:
                    raise SessionError("recovery credentials are invalid")
                changed = connection.execute(
                    """
                    UPDATE recovery_codes SET used_at = ?
                    WHERE tenant_id = ? AND user_id = ? AND code_hash = ? AND used_at IS NULL
                    """,
                    (
                        _utc_text(now),
                        row["tenant_id"],
                        row["user_id"],
                        code_hash,
                    ),
                )
                if changed.rowcount != 1:
                    raise SessionError("recovery credentials are invalid")
                issue = self._issue_session(
                    connection,
                    str(row["tenant_id"]),
                    str(row["user_id"]),
                    now,
                )
                connection.execute("COMMIT")
            except Exception:
                if connection.in_transaction:
                    connection.execute("ROLLBACK")
                raise
        return issue

    def authenticate_session(self, token: str, now: datetime) -> SessionPrincipal:
        session_id, separator, secret = token.partition(".")
        if not separator or not session_id or not secret:
            raise SessionError("session is invalid")
        with self._database.connect() as connection:
            row = connection.execute(
                """
                SELECT s.tenant_id, s.session_id, s.user_id, s.secret_hash, s.csrf_hash,
                       s.expires_at, s.revoked_at, u.email, u.display_name, u.role,
                       u.status AS user_status, t.status AS tenant_status
                FROM sessions s
                JOIN users u ON u.tenant_id = s.tenant_id AND u.user_id = s.user_id
                JOIN tenants t ON t.tenant_id = s.tenant_id
                WHERE s.session_id = ?
                """,
                (session_id,),
            ).fetchone()
            if row is None or not hmac.compare_digest(
                str(row["secret_hash"]),
                self._hash(self._session_pepper, "session", token),
            ):
                raise SessionError("session is invalid")
            if (
                row["revoked_at"] is not None
                or row["user_status"] != "active"
                or row["tenant_status"] != "active"
                or self._parse_time(str(row["expires_at"])) <= now.astimezone(timezone.utc)
            ):
                raise SessionError("session is inactive")
            connection.execute(
                """
                UPDATE sessions SET last_seen_at = ?
                WHERE tenant_id = ? AND session_id = ?
                """,
                (_utc_text(now), row["tenant_id"], session_id),
            )
        return self._principal_from_row(row)

    def verify_csrf(self, principal: SessionPrincipal, csrf_token: str) -> None:
        expected = self._hash(self._session_pepper, "csrf", csrf_token)
        if not csrf_token or not hmac.compare_digest(principal.csrf_hash, expected):
            raise HumanAuthorizationError("csrf verification failed")

    def session_csrf(self, principal: SessionPrincipal, now: datetime) -> str:
        """Recover a session-bound token without invalidating another browser tab.

        Legacy random tokens converge once when first read after upgrade. New
        sessions use this purpose-separated PRF from creation; plaintext tokens
        are never stored, and a session ID alone cannot derive its CSRF value.
        """
        csrf_token = self._csrf_token(principal.session_id)
        with self._database.connect() as connection:
            changed = connection.execute(
                """
                UPDATE sessions SET csrf_hash = ?, last_seen_at = ?
                WHERE tenant_id = ? AND session_id = ? AND revoked_at IS NULL
                  AND expires_at > ?
                """,
                (
                    self._hash(self._session_pepper, "csrf", csrf_token),
                    _utc_text(now),
                    principal.tenant_id,
                    principal.session_id,
                    _utc_text(now),
                ),
            )
        if changed.rowcount != 1:
            raise SessionError("session is inactive")
        return csrf_token

    def _csrf_token(self, session_id: str) -> str:
        return self._hash(self._session_pepper, "session-csrf-token-v1", session_id)

    def revoke_session(self, principal: SessionPrincipal, now: datetime) -> None:
        with self._database.connect() as connection:
            connection.execute(
                """
                UPDATE sessions SET revoked_at = ?
                WHERE tenant_id = ? AND session_id = ? AND revoked_at IS NULL
                """,
                (_utc_text(now), principal.tenant_id, principal.session_id),
            )

    def require_capability(
        self,
        principal: SessionPrincipal,
        tenant_id: str,
        capability: Capability,
    ) -> None:
        if principal.tenant_id != tenant_id or capability not in ROLE_CAPABILITIES[principal.role]:
            raise HumanAuthorizationError("principal is not authorized for this operation")

    @staticmethod
    def _active_admin(connection: sqlite3.Connection, tenant_id: str, user_id: str) -> bool:
        row = connection.execute(
            """SELECT m.home_tenant_id FROM users u
               JOIN tenants t ON t.tenant_id=u.tenant_id
               LEFT JOIN owner_memberships m ON m.tenant_id=u.tenant_id AND m.user_id=u.user_id
               WHERE u.tenant_id=? AND u.user_id=? AND u.status='active'
                 AND u.role='admin' AND t.status='active'""",
            (tenant_id, user_id),
        ).fetchone()
        if row is None:
            return False
        if row["home_tenant_id"] is None:
            return True
        return (
            connection.execute(
                """SELECT 1 FROM platform_owners o JOIN users u
                 ON u.tenant_id=o.home_tenant_id AND u.user_id=o.user_id
               JOIN tenants t ON t.tenant_id=u.tenant_id
               WHERE o.home_tenant_id=? AND o.user_id=? AND u.status='active'
                 AND u.role='admin' AND t.status='active'""",
                (row["home_tenant_id"], user_id),
            ).fetchone()
            is not None
        )

    def require_current_capability(
        self,
        connection: sqlite3.Connection,
        principal: SessionPrincipal,
        capability: Capability,
        now: datetime,
    ) -> None:
        """Recheck mutable authority inside the caller's management transaction."""
        self.require_capability(principal, principal.tenant_id, capability)
        row = connection.execute(
            """SELECT s.tenant_id AS home_tenant_id, member.role AS member_role
               FROM sessions s JOIN users home
                 ON home.tenant_id=s.tenant_id AND home.user_id=s.user_id
               JOIN tenants home_network ON home_network.tenant_id=s.tenant_id
               JOIN users member ON member.tenant_id=? AND member.user_id=s.user_id
               JOIN tenants target ON target.tenant_id=member.tenant_id
               WHERE s.session_id=? AND s.user_id=? AND s.revoked_at IS NULL AND s.expires_at>?
                 AND home.status='active' AND home_network.status='active'
                 AND member.status='active' AND target.status='active'""",
            (principal.tenant_id, principal.session_id, principal.user_id, _utc_text(now)),
        ).fetchone()
        if row is None or row["member_role"] != principal.role:
            raise HumanAuthorizationError("administrator authority changed; sign in again")
        if row["home_tenant_id"] != principal.tenant_id:
            membership = connection.execute(
                """SELECT 1 FROM owner_memberships WHERE tenant_id=? AND user_id=?
                     AND home_tenant_id=?""",
                (principal.tenant_id, principal.user_id, row["home_tenant_id"]),
            ).fetchone()
            if membership is None or not self._active_admin(
                connection, principal.tenant_id, principal.user_id
            ):
                raise HumanAuthorizationError("platform owner authority is inactive")

    def _create_challenge(
        self,
        purpose: Literal["bootstrap", "registration", "authentication"],
        tenant_id: Optional[str],
        user_id: Optional[str],
        context: dict[str, object],
        now: datetime,
    ) -> tuple[tuple[str, bytes], datetime]:
        challenge_id = str(uuid.uuid4())
        challenge = secrets.token_bytes(32)
        expires_at = now + timedelta(seconds=self._challenge_ttl_seconds)
        with self._database.connect() as connection:
            connection.execute(
                """
                INSERT INTO auth_challenges(
                    challenge_id, tenant_id, user_id, purpose, challenge_b64,
                    context_json, created_at, expires_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    challenge_id,
                    tenant_id,
                    user_id,
                    purpose,
                    base64.urlsafe_b64encode(challenge).decode("ascii"),
                    json.dumps(context, separators=(",", ":"), sort_keys=True),
                    _utc_text(now),
                    _utc_text(expires_at),
                ),
            )
        return (challenge_id, challenge), expires_at

    def _load_challenge(
        self,
        challenge_id: str,
        purpose: str,
        now: datetime,
    ) -> tuple[sqlite3.Row, dict[str, object], bytes]:
        with self._database.connect() as connection:
            row = connection.execute(
                "SELECT * FROM auth_challenges WHERE challenge_id = ?",
                (challenge_id,),
            ).fetchone()
        if (
            row is None
            or row["purpose"] != purpose
            or row["consumed_at"] is not None
            or self._parse_time(str(row["expires_at"])) <= now.astimezone(timezone.utc)
        ):
            raise ChallengeError("passkey challenge is inactive")
        context = json.loads(str(row["context_json"]))
        if not isinstance(context, dict):
            raise ChallengeError("passkey challenge context is invalid")
        try:
            challenge = base64.urlsafe_b64decode(str(row["challenge_b64"]))
        except ValueError as exc:
            raise ChallengeError("passkey challenge encoding is invalid") from exc
        return row, context, challenge

    @staticmethod
    def _consume_challenge(
        connection: sqlite3.Connection,
        challenge: sqlite3.Row,
        now: datetime,
    ) -> None:
        changed = connection.execute(
            """
            UPDATE auth_challenges SET consumed_at = ?
            WHERE challenge_id = ? AND consumed_at IS NULL AND expires_at > ?
            """,
            (_utc_text(now), challenge["challenge_id"], _utc_text(now)),
        )
        if changed.rowcount != 1:
            raise ChallengeError("passkey challenge was already consumed or expired")

    def _require_bootstrap_token(self, token_hash: str, now: datetime) -> None:
        with self._database.connect() as connection:
            row = connection.execute(
                """
                SELECT 1 FROM bootstrap_tokens
                WHERE token_hash = ? AND used_at IS NULL AND revoked_at IS NULL
                  AND expires_at > ?
                """,
                (token_hash, _utc_text(now)),
            ).fetchone()
        if row is None or self.bootstrap_status().configured:
            raise BootstrapError("bootstrap token is inactive")

    def _issue_session(
        self,
        connection: sqlite3.Connection,
        tenant_id: str,
        user_id: str,
        now: datetime,
    ) -> SessionIssue:
        if (
            connection.execute(
                """SELECT 1 FROM users u JOIN tenants t ON t.tenant_id=u.tenant_id
               WHERE u.tenant_id=? AND u.user_id=? AND u.status='active' AND t.status='active'
                 AND NOT EXISTS (SELECT 1 FROM owner_memberships m
                     WHERE m.tenant_id=u.tenant_id AND m.user_id=u.user_id)""",
                (tenant_id, user_id),
            ).fetchone()
            is None
        ):
            raise SessionError("sign-in identity is inactive")
        session_id = str(uuid.uuid4())
        session_token = f"{session_id}.{secrets.token_urlsafe(32)}"
        csrf_token = self._csrf_token(session_id)
        expires_at = now + timedelta(seconds=self._session_ttl_seconds)
        connection.execute(
            """
            INSERT INTO sessions(
                tenant_id, session_id, user_id, secret_hash, csrf_hash,
                created_at, expires_at, last_seen_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                tenant_id,
                session_id,
                user_id,
                self._hash(self._session_pepper, "session", session_token),
                self._hash(self._session_pepper, "csrf", csrf_token),
                _utc_text(now),
                _utc_text(expires_at),
                _utc_text(now),
            ),
        )
        principal_row = connection.execute(
            """
            SELECT s.tenant_id, s.session_id, s.user_id, s.csrf_hash, s.expires_at,
                   u.email, u.display_name, u.role
            FROM sessions s
            JOIN users u ON u.tenant_id = s.tenant_id AND u.user_id = s.user_id
            WHERE s.tenant_id = ? AND s.session_id = ?
            """,
            (tenant_id, session_id),
        ).fetchone()
        if principal_row is None:
            raise SessionError("new session could not be loaded")
        return SessionIssue(session_token, csrf_token, self._principal_from_row(principal_row))

    @staticmethod
    def _insert_passkey(
        connection: sqlite3.Connection,
        tenant_id: str,
        user_id: str,
        credential_id: str,
        public_key: bytes,
        sign_count: int,
        label: str,
        now: datetime,
    ) -> None:
        connection.execute(
            """
            INSERT INTO passkey_credentials(
                tenant_id, user_id, credential_id, public_key,
                sign_count, label, created_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (
                tenant_id,
                user_id,
                credential_id,
                public_key,
                sign_count,
                label,
                _utc_text(now),
            ),
        )

    def _new_recovery_codes(self) -> list[str]:
        return [secrets.token_urlsafe(16) for _ in range(10)]

    def _recovery_hash(self, value: str) -> str:
        return self._hash(self._recovery_pepper, "recovery", value.strip())

    @staticmethod
    def _hash(key: bytes, purpose: str, value: str) -> str:
        return hmac.new(key, f"{purpose}:{value}".encode(), hashlib.sha256).hexdigest()

    @staticmethod
    def _normalize_email(value: str) -> str:
        normalized = value.strip().casefold()
        if len(normalized) > 320 or normalized.count("@") != 1:
            raise IdentityError("email identity is invalid")
        local, domain = normalized.split("@", maxsplit=1)
        if not local or not domain or "." not in domain:
            raise IdentityError("email identity is invalid")
        return normalized

    @staticmethod
    def _parse_time(value: str) -> datetime:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
        if parsed.tzinfo is None:
            raise IdentityError("stored identity timestamp is invalid")
        return parsed.astimezone(timezone.utc)

    @staticmethod
    def _context_text(context: dict[str, object], key: str) -> str:
        value = context.get(key)
        if not isinstance(value, str) or not value:
            raise ChallengeError("passkey challenge context is incomplete")
        return value

    @staticmethod
    def _required_row_text(row: sqlite3.Row, key: str) -> str:
        value = row[key]
        if not isinstance(value, str) or not value:
            raise ChallengeError("passkey challenge identity is incomplete")
        return value

    @staticmethod
    def _principal_from_row(row: sqlite3.Row) -> SessionPrincipal:
        role_value = str(row["role"])
        if role_value not in ROLE_CAPABILITIES:
            raise SessionError("session role is invalid")
        role = cast(Role, role_value)
        return SessionPrincipal(
            tenant_id=str(row["tenant_id"]),
            user_id=str(row["user_id"]),
            email=str(row["email"]),
            display_name=str(row["display_name"]),
            role=role,
            session_id=str(row["session_id"]),
            expires_at=HumanIdentityService._parse_time(str(row["expires_at"])),
            csrf_hash=str(row["csrf_hash"]),
        )
