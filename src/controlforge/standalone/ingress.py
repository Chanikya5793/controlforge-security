"""Explicit proxy metadata boundary; addresses are rate-limit hints, not identity."""

from __future__ import annotations

import ipaddress
from typing import Literal, Optional

from fastapi import Request
from fastapi.responses import JSONResponse

IngressMode = Literal["direct", "cloudflare-tunnel"]


def validate_ingress_listener(mode: str, host: str) -> None:
    if mode not in {"direct", "cloudflare-tunnel"}:
        raise ValueError("unsupported standalone ingress mode")
    if mode == "cloudflare-tunnel" and host != "127.0.0.1":
        raise ValueError("Cloudflare Tunnel ingress requires --host 127.0.0.1")


class IngressPolicy:
    def __init__(self, mode: IngressMode) -> None:
        validate_ingress_listener(mode, "127.0.0.1")
        self.mode = mode

    def prepare(self, request: Request) -> Optional[JSONResponse]:
        peer = request.client.host if request.client is not None else "unknown"
        if self.mode == "direct":
            # Never honor user-supplied Forwarded, X-Forwarded-* or CF-* fields.
            request.state.rate_limit_client = peer
            return None
        values = [
            value
            for name, value in request.scope.get("headers", [])
            if name.lower() == b"cf-connecting-ip"
        ]
        if peer == "127.0.0.1" and request.scope.get("scheme") == "https" and len(values) == 1:
            try:
                raw = values[0].decode("ascii")
                if len(raw) > 45 or "%" in raw:
                    raise ValueError("invalid client address")
                address = ipaddress.ip_address(raw)
                if isinstance(address, ipaddress.IPv6Address) and address.ipv4_mapped is not None:
                    address = address.ipv4_mapped
                request.state.rate_limit_client = str(address)
                return None
            except (UnicodeError, ValueError):
                pass
        return JSONResponse(
            {"error": "Request did not arrive through the configured connector."}, status_code=403
        )


def rate_limit_client(request: Request) -> str:
    # Populated by the outer boundary; never read an unvalidated HTTP field here.
    return str(request.state.rate_limit_client)
