"""Separate passkey-admin and password-endpoint HTTP contracts."""

from __future__ import annotations

import hashlib
from collections.abc import Callable
from datetime import datetime, timedelta
from typing import Literal

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel, ConfigDict, Field, SecretStr

from .accounts import EndpointAccountService
from .identity import HumanAuthorizationError, Role, SessionError, SessionPrincipal
from .ingress import rate_limit_client
from .network_lifecycle import NetworkLifecycleService
from .network_routing import NetworkRoutingService
from .networks import NetworkConflictError, NetworkError, NetworkService
from .passwords import PasswordBusyError, PasswordError
from .ratelimit import SlidingWindowRateLimiter


class NetworkInput(BaseModel):
    model_config = ConfigDict(extra="forbid")
    slug: str = Field(min_length=3, max_length=48)
    display_name: str = Field(min_length=1, max_length=120)


class AccountInput(BaseModel):
    model_config = ConfigDict(extra="forbid")
    alias: str = Field(min_length=1, max_length=64)
    display_name: str = Field(min_length=1, max_length=120)


class UsernameInput(BaseModel):
    model_config = ConfigDict(extra="forbid")
    username: str = Field(min_length=1, max_length=254)


class PasswordLoginInput(UsernameInput):
    password: SecretStr = Field(min_length=1, max_length=128)


class PasswordChangeInput(BaseModel):
    model_config = ConfigDict(extra="forbid")
    password: SecretStr = Field(min_length=15, max_length=128)


class AccountEnrollmentInput(BaseModel):
    model_config = ConfigDict(extra="forbid")
    device_id: str = Field(min_length=1, max_length=128, pattern=r"^[A-Za-z0-9._:-]+$")


class ResetApprovalInput(BaseModel):
    model_config = ConfigDict(extra="forbid")
    identity_verified: Literal[True]


class ConfirmedRevisionInput(BaseModel):
    model_config = ConfigDict(extra="forbid")
    revision: int = Field(ge=1)
    confirmed: Literal[True]


class NetworkUpdateInput(ConfirmedRevisionInput):
    display_name: str = Field(min_length=1, max_length=120)
    status: Literal["active", "suspended"]


class NamespaceInput(ConfirmedRevisionInput):
    slug: str = Field(min_length=3, max_length=48)


class RoutingInput(ConfirmedRevisionInput):
    enabled: bool = Field(strict=True)


class AccountUpdateInput(ConfirmedRevisionInput):
    display_name: str = Field(min_length=1, max_length=120)
    status: Literal["active", "disabled"]


class MemberUpdateInput(ConfirmedRevisionInput):
    role: Role
    status: Literal["active", "disabled"]
    expected_role: Role
    expected_status: Literal["active", "disabled", "invited"]


class ConfirmedInput(BaseModel):
    model_config = ConfigDict(extra="forbid")
    confirmed: Literal[True]


class AccountRateLimitError(RuntimeError):
    pass


def install_network_routes(
    app: FastAPI,
    networks: NetworkService,
    accounts: EndpointAccountService,
    limiter: SlidingWindowRateLimiter,
    origin: str,
    clock: Callable[[], datetime],
) -> None:
    lifecycle = NetworkLifecycleService(networks)
    routing = NetworkRoutingService(networks, origin)

    @app.exception_handler(NetworkConflictError)
    async def conflict(_request: Request, error: NetworkConflictError) -> JSONResponse:
        return JSONResponse({"error": str(error)}, status_code=409)

    @app.exception_handler(NetworkError)
    @app.exception_handler(PasswordError)
    async def invalid_input(_request: Request, error: ValueError) -> JSONResponse:
        return JSONResponse({"error": str(error)}, status_code=400)

    @app.exception_handler(PasswordBusyError)
    @app.exception_handler(AccountRateLimitError)
    async def busy(_request: Request, _error: RuntimeError) -> JSONResponse:
        return JSONResponse(
            {"error": "Too many attempts. Please try again later."},
            status_code=429,
            headers={"Retry-After": "900"},
        )

    def admin(request: Request, *, mutation: bool = False, scoped: bool = True) -> SessionPrincipal:
        principal = networks.identity.authenticate_session(
            request.cookies.get("controlforge_session", ""), clock()
        )
        if mutation:
            if request.headers.get("origin", "").rstrip("/") != origin:
                raise HumanAuthorizationError("origin rejected")
            networks.identity.verify_csrf(principal, request.headers.get("x-csrf-token", ""))
        if scoped:
            principal = networks.scope(principal, request.headers.get("x-network-id", ""))
        return principal

    def endpoint_token(request: Request) -> str:
        # Native clients do not send Origin; browser callers must be same-origin.
        if "origin" in request.headers and request.headers["origin"].rstrip("/") != origin:
            raise HumanAuthorizationError("origin rejected")
        bearer = request.headers.get("authorization", "")
        if not bearer.startswith("Bearer ") or len(bearer) > 135:
            raise SessionError("endpoint sign-in required")
        return bearer[7:]

    def public_budget(request: Request, username: str, scope: str) -> None:
        if "origin" in request.headers and request.headers["origin"].rstrip("/") != origin:
            raise HumanAuthorizationError("origin rejected")
        host = rate_limit_client(request)
        identity = hashlib.sha256(username.strip().lower().encode()).hexdigest()
        for key, limit, seconds in [
            ("global", 60, 60),
            (f"ip:{host}", 20, 900),
            (f"account:{identity}", 10, 900),
        ]:
            if not limiter.check(
                scope, key, clock(), limit=limit, window=timedelta(seconds=seconds)
            ).allowed:
                raise AccountRateLimitError()

    @app.get("/v1/networks")
    def networks_list(request: Request) -> dict[str, object]:
        principal = admin(request, scoped=False)
        return {
            "is_platform_owner": networks.is_owner(principal),
            "base_domain": networks.base_domain,
            "canonical_origin": routing.origin,
            "networks": [
                {**row, **routing.describe(row)} for row in networks.list_networks(principal)
            ],
        }

    @app.post("/v1/networks/{tenant_id}/routing")
    def network_routing(tenant_id: str, request: Request, body: RoutingInput) -> dict[str, object]:
        return routing.configure(
            admin(request, mutation=True, scoped=False),
            tenant_id,
            body.enabled,
            body.revision,
            clock(),
        )

    @app.post("/v1/networks", status_code=201)
    def networks_create(request: Request, body: NetworkInput) -> dict[str, object]:
        return networks.create_network(
            admin(request, mutation=True, scoped=False), body.slug, body.display_name, clock()
        )

    @app.get("/v1/network/accounts")
    def accounts_list(request: Request) -> dict[str, object]:
        return {"accounts": accounts.list_accounts(admin(request))}

    @app.post("/v1/networks/{tenant_id}/configure")
    def network_configure(
        tenant_id: str, request: Request, body: NetworkUpdateInput
    ) -> dict[str, object]:
        return lifecycle.update_network(
            admin(request, mutation=True, scoped=False),
            tenant_id,
            body.display_name,
            body.status,
            body.revision,
            clock(),
        )

    @app.post("/v1/networks/{tenant_id}/namespace")
    def network_namespace(
        tenant_id: str, request: Request, body: NamespaceInput
    ) -> dict[str, object]:
        return lifecycle.adopt_namespace(
            admin(request, mutation=True, scoped=False),
            tenant_id,
            body.slug,
            body.revision,
            clock(),
        )

    @app.get("/v1/network/team")
    def team_list(request: Request) -> dict[str, object]:
        return lifecycle.team(admin(request), clock())

    @app.post("/v1/network/team/{user_id}")
    def team_update(user_id: str, request: Request, body: MemberUpdateInput) -> dict[str, object]:
        return lifecycle.update_member(
            admin(request, mutation=True),
            user_id,
            body.role,
            body.status,
            body.expected_role,
            body.expected_status,
            body.revision,
            clock(),
        )

    @app.post("/v1/network/invitations/{invite_id}/revoke")
    def invite_revoke(invite_id: str, request: Request, body: ConfirmedInput) -> dict[str, str]:
        return lifecycle.revoke_invite(admin(request, mutation=True), invite_id, clock())

    @app.post("/v1/network/accounts/{account_id}/configure")
    def account_configure(
        account_id: str, request: Request, body: AccountUpdateInput
    ) -> dict[str, object]:
        return lifecycle.update_account(
            admin(request, mutation=True),
            account_id,
            body.display_name,
            body.status,
            body.revision,
            clock(),
        )

    @app.post("/v1/network/accounts", status_code=201)
    def accounts_create(request: Request, body: AccountInput) -> dict[str, object]:
        return accounts.create_account(
            admin(request, mutation=True), body.alias, body.display_name, clock()
        )

    @app.get("/v1/network/password-resets")
    def resets_list(request: Request) -> dict[str, object]:
        return {"requests": accounts.reset_requests(admin(request))}

    @app.post("/v1/network/password-resets/{request_id}/resolve")
    def resets_resolve(
        request_id: str,
        request: Request,
        body: ResetApprovalInput,
    ) -> dict[str, object]:
        return accounts.reset_password(admin(request, mutation=True), request_id, clock())

    @app.post("/v1/endpoint/login")
    def endpoint_login(request: Request, body: PasswordLoginInput) -> dict[str, object]:
        public_budget(request, body.username, "endpoint-login")
        return accounts.login(body.username, body.password.get_secret_value(), clock())

    @app.get("/v1/endpoint/me")
    def endpoint_me(request: Request) -> dict[str, object]:
        return accounts.me(endpoint_token(request), clock())

    @app.post("/v1/endpoint/password")
    def endpoint_password(request: Request, body: PasswordChangeInput) -> dict[str, object]:
        token = endpoint_token(request)
        principal = accounts.me(token, clock())
        public_budget(request, str(principal["username"]), "endpoint-password")
        return accounts.change_password(token, body.password.get_secret_value(), clock())

    @app.post("/v1/endpoint/logout")
    def endpoint_logout(request: Request) -> dict[str, str]:
        accounts.logout(endpoint_token(request))
        return {"status": "signed_out"}

    @app.post("/v1/endpoint/password-reset", status_code=202)
    def endpoint_reset(request: Request, body: UsernameInput) -> dict[str, str]:
        public_budget(request, body.username, "endpoint-reset")
        accounts.request_reset(body.username, clock())
        return {
            "message": "If this account is active, your admin will see a reset request. "
            "Contact them to verify your identity and receive a new password."
        }

    @app.post("/v1/endpoint/enrollment-grant", status_code=201)
    def endpoint_enroll(request: Request, body: AccountEnrollmentInput) -> dict[str, object]:
        token = endpoint_token(request)
        principal = accounts.me(token, clock())
        public_budget(request, str(principal["username"]), "endpoint-enroll")
        return accounts.enrollment_grant(token, body.device_id, clock())
