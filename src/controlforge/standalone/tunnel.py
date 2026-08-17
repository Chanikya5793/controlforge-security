"""Read-only, exact-host Cloudflare Tunnel configuration snapshots."""

from __future__ import annotations

import ipaddress
import os
import sqlite3
import stat
from pathlib import Path
from typing import Optional
from uuid import UUID

import yaml

from .migrations import MIGRATIONS
from .network_routing import NetworkRoutingService, eligible_entry_domain
from .networks import normalize_domain
from .ownership import require_operator_directory


def _path_reference(path: Path) -> str:
    value = str(path)
    if not path.is_absolute() or ".." in path.parts or any(ord(char) < 32 for char in value):
        raise ValueError("Tunnel file references must be absolute paths without traversal")
    # This command deliberately never opens the credentials or CA file.
    return value


def render_tunnel_config(
    *,
    database_path: Path,
    admin_origin: str,
    base_domain: str,
    origin_port: int,
    tunnel_id: str,
    credentials_file: Path,
    ca_pool: Optional[Path] = None,
) -> str:
    """Render configuration without migrating state, publishing DNS or reading secrets."""
    routing = NetworkRoutingService(None, admin_origin)
    if routing.port != 443 or routing.host == "localhost":
        raise ValueError("Tunnel entry requires a public canonical HTTPS hostname on port 443")
    try:
        ipaddress.ip_address(routing.host)
    except ValueError:
        pass
    else:
        raise ValueError("Tunnel entry requires a public DNS hostname, not an IP address")
    if not 1 <= origin_port <= 65535:
        raise ValueError("invalid Tunnel origin port")
    domain = normalize_domain(base_domain)
    identifier = str(UUID(tunnel_id))
    if identifier != tunnel_id or UUID(tunnel_id).int == 0:
        raise ValueError("Tunnel ID must be a nonzero canonical UUID")
    credential_reference = _path_reference(credentials_file)
    ca_reference = _path_reference(ca_pool) if ca_pool is not None else None
    path = database_path.absolute()
    require_operator_directory(path.parent)
    metadata = path.lstat()
    if (
        not stat.S_ISREG(metadata.st_mode)
        or metadata.st_uid != os.geteuid()
        or stat.S_IMODE(metadata.st_mode) != 0o600
        or metadata.st_nlink != 1
    ):
        raise ValueError("Tunnel snapshot requires a private operator-owned database")
    try:
        connection = sqlite3.connect(f"{path.as_uri()}?mode=ro", uri=True, timeout=5)
        try:
            connection.execute("PRAGMA query_only = ON")
            connection.execute("BEGIN")
            ledger = connection.execute(
                "SELECT version, name FROM schema_migrations ORDER BY version LIMIT ?",
                (len(MIGRATIONS) + 1,),
            ).fetchall()
            if ledger != [(item.version, item.name) for item in MIGRATIONS]:
                raise ValueError(
                    "upgrade the appliance schema before generating Tunnel configuration"
                )
            tenants = connection.execute("SELECT tenant_id FROM tenants LIMIT 201").fetchall()
            if not 1 <= len(tenants) <= 200:
                raise ValueError("Tunnel snapshot requires between 1 and 200 networks")
            aliases = connection.execute(
                """SELECT n.login_domain FROM network_namespaces n
                   JOIN tenants t ON t.tenant_id=n.tenant_id
                   JOIN network_routes r ON r.tenant_id=n.tenant_id
                   WHERE t.status='active' AND r.enabled=1 ORDER BY n.login_domain LIMIT 201"""
            ).fetchall()
        finally:
            connection.close()
    except sqlite3.Error:
        raise ValueError("could not read the appliance routing snapshot") from None
    hosts = [
        routing.host,
        *sorted(
            {str(row[0]) for row in aliases if eligible_entry_domain(row[0], domain, routing.host)}
        ),
    ]
    origin: dict[str, object] = {
        "originServerName": routing.host,
        "noTLSVerify": False,
        "matchSNItoHost": False,
    }
    if ca_reference is not None:
        origin["caPool"] = ca_reference
    ingress: list[dict[str, str]] = [
        {"hostname": host, "service": f"https://127.0.0.1:{origin_port}"} for host in hosts
    ]
    ingress.append({"service": "http_status:404"})
    return (
        "# ControlForge routing snapshot; NOT a DNS, certificate or deployment verification.\n"
        "# Serve with --host 127.0.0.1 --ingress-mode cloudflare-tunnel and matching origin/port.\n"
        "# Regenerate and validate after enabling additional network web addresses.\n"
        + yaml.safe_dump(
            {
                "tunnel": identifier,
                "credentials-file": credential_reference,
                "originRequest": origin,
                "ingress": ingress,
            },
            sort_keys=False,
        )
    )
