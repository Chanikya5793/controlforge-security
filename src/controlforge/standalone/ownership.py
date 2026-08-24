"""Explicit offline designation for appliances created before platform ownership."""

from __future__ import annotations

import os
import stat
from datetime import datetime
from pathlib import Path

from .audit import StandaloneAuditLog
from .backup import ApplianceOperationLock, RestoreOfflineError
from .database import StandaloneDatabase
from .migrations import MIGRATIONS
from .store import _utc_text

OWNER_CONFIRMATION = "DESIGNATE-PLATFORM-OWNER"


class OwnerSetupError(ValueError):
    """The local owner ceremony could not safely complete."""


def require_operator_directory(path: Path) -> None:
    for directory in (path, *path.parents):
        metadata = directory.lstat()
        mode = stat.S_IMODE(metadata.st_mode)
        is_root_owned_sticky_directory = metadata.st_uid == 0 and bool(mode & stat.S_ISVTX)
        if (
            not stat.S_ISDIR(metadata.st_mode)
            or metadata.st_uid not in {0, os.geteuid()}
            or (mode & 0o022 and not is_root_owned_sticky_directory)
        ):
            raise OwnerSetupError("owner setup requires a trusted operator-owned directory")


class PlatformOwnerSetup:
    """Not mounted in HTTP. Filesystem ownership is the local operator boundary."""

    def __init__(self, database: StandaloneDatabase, audit: StandaloneAuditLog) -> None:
        self.database = database
        self.audit = audit

    def _preflight(self) -> None:
        require_operator_directory(self.database.settings.database_path.parent)
        if self.database.settings.database_path.lstat().st_nlink != 1:
            raise OwnerSetupError("owner setup requires a database without hard links")
        if self.database.applied_versions() != tuple(item.version for item in MIGRATIONS):
            raise OwnerSetupError("upgrade the appliance schema before designating its owner")

    def status(self) -> dict[str, object]:
        self._preflight()
        with (
            ApplianceOperationLock(self.database.settings.database_path).shared(),
            self.database.connect() as connection,
        ):
            owner = connection.execute(
                "SELECT home_tenant_id,user_id FROM platform_owners"
            ).fetchone()
            candidates = connection.execute(
                """SELECT u.tenant_id,u.user_id,u.email,u.display_name,t.slug AS network_slug
                       FROM users u JOIN tenants t ON t.tenant_id=u.tenant_id
                       WHERE u.status='active' AND u.role='admin' AND t.status='active'
                         AND EXISTS(SELECT 1 FROM passkey_credentials p
                           WHERE p.tenant_id=u.tenant_id AND p.user_id=u.user_id
                             AND p.revoked_at IS NULL)
                         AND NOT EXISTS(SELECT 1 FROM owner_memberships m
                           WHERE m.tenant_id=u.tenant_id AND m.user_id=u.user_id)
                       ORDER BY t.slug,u.email LIMIT 200"""
            ).fetchall()
        return {
            "owner": dict(owner) if owner else None,
            "candidates": [dict(row) for row in candidates],
            "candidate_limit": 200,
        }

    def designate(
        self,
        tenant_id: str,
        user_id: str,
        confirmation: str,
        now: datetime,
    ) -> dict[str, object]:
        if confirmation != OWNER_CONFIRMATION or now.tzinfo is None:
            raise OwnerSetupError(f"owner designation requires --confirm {OWNER_CONFIRMATION}")
        self._preflight()
        lock = ApplianceOperationLock(self.database.settings.database_path)
        try:
            lock.acquire_exclusive()
        except RestoreOfflineError as exc:
            raise OwnerSetupError(
                "stop the standalone runtime before designating its owner"
            ) from exc
        try:
            return self._designate_locked(tenant_id, user_id, now)
        finally:
            lock.release()

    def _designate_locked(self, tenant_id: str, user_id: str, now: datetime) -> dict[str, object]:
        with self.database.connect() as connection:
            tenants = connection.execute("SELECT tenant_id FROM tenants LIMIT 201").fetchall()
        if len(tenants) > 200:
            raise OwnerSetupError("owner setup supports at most 200 networks")
        for tenant in tenants:
            if not self.audit.verify(str(tenant["tenant_id"])).valid:
                raise OwnerSetupError("verify the appliance audit key and chain before owner setup")
        with self.database.connect() as connection, connection:
            connection.execute("BEGIN IMMEDIATE")
            previous = connection.execute("SELECT * FROM platform_owners").fetchone()
            if previous is not None:
                if previous["home_tenant_id"] == tenant_id and previous["user_id"] == user_id:
                    return {
                        "status": "already_designated",
                        "home_tenant_id": tenant_id,
                        "user_id": user_id,
                    }
                raise OwnerSetupError(
                    "an owner is already designated; this is not an owner-transfer command"
                )
            if connection.execute("SELECT 1 FROM owner_memberships LIMIT 1").fetchone():
                raise OwnerSetupError("existing owner membership data needs explicit recovery")
            candidate = connection.execute(
                """SELECT u.* FROM users u JOIN tenants t ON t.tenant_id=u.tenant_id
                   WHERE u.tenant_id=? AND u.user_id=? AND u.status='active' AND u.role='admin'
                     AND t.status='active' AND EXISTS(SELECT 1 FROM passkey_credentials p
                       WHERE p.tenant_id=u.tenant_id AND p.user_id=u.user_id
                         AND p.revoked_at IS NULL)""",
                (tenant_id, user_id),
            ).fetchone()
            if candidate is None:
                raise OwnerSetupError("select an active administrator with an active passkey")
            for tenant in tenants:
                target = str(tenant["tenant_id"])
                if target == tenant_id:
                    continue
                if connection.execute(
                    "SELECT 1 FROM users WHERE tenant_id=? AND (user_id=? OR email=?)",
                    (target, user_id, candidate["email"]),
                ).fetchone():
                    raise OwnerSetupError(
                        "an existing network identity conflicts; no identities were merged"
                    )
                connection.execute(
                    """INSERT INTO users(
                       tenant_id,user_id,email,display_name,role,status,created_at)
                       VALUES(?,?,?,?,'admin','active',?)""",
                    (
                        target,
                        user_id,
                        candidate["email"],
                        candidate["display_name"],
                        _utc_text(now),
                    ),
                )
                connection.execute(
                    "INSERT INTO owner_memberships VALUES(?,?,?)", (target, user_id, tenant_id)
                )
                self.audit.append(
                    connection,
                    target,
                    "platform_owner.membership_created",
                    "local_operator",
                    str(os.geteuid()),
                    "user",
                    user_id,
                    {"home_tenant_id": tenant_id},
                    now,
                )
            connection.execute(
                "INSERT INTO platform_owners VALUES(1,?,?,?)", (tenant_id, user_id, _utc_text(now))
            )
            connection.execute(
                """UPDATE sessions SET revoked_at=?
                   WHERE tenant_id=? AND user_id=? AND revoked_at IS NULL""",
                (_utc_text(now), tenant_id, user_id),
            )
            connection.execute(
                """UPDATE auth_challenges SET consumed_at=?
                   WHERE tenant_id=? AND user_id=? AND consumed_at IS NULL""",
                (_utc_text(now), tenant_id, user_id),
            )
            self.audit.append(
                connection,
                tenant_id,
                "platform_owner.designated",
                "local_operator",
                str(os.geteuid()),
                "user",
                user_id,
                {"networks": len(tenants)},
                now,
            )
        return {
            "status": "designated",
            "home_tenant_id": tenant_id,
            "user_id": user_id,
            "sign_in_again": True,
            "networks": len(tenants),
        }
