"""Minimal authenticated FastAPI boundary for the standalone appliance."""

from __future__ import annotations

import asyncio
import hashlib
import secrets
from collections.abc import AsyncIterator, Awaitable, Callable
from contextlib import asynccontextmanager
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Literal, Optional

from fastapi import FastAPI, Request, Response
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse
from pydantic import BaseModel, ConfigDict, Field

from controlforge import __version__

from .auth import CollectorAuthenticationError, CollectorReplayError, SignedCollectorRequest
from .cases import (
    CaseDetail,
    CaseNotFoundError,
    CaseTransitionError,
    CaseValidationError,
    StandaloneCaseService,
)
from .credential_rotation import DeviceCredentialRotationService
from .dashboard import dashboard_html
from .enrollment import DeviceEnrollmentService, EnrollmentError
from .identity import (
    BootstrapError,
    Capability,
    ChallengeError,
    HumanAuthorizationError,
    HumanIdentityService,
    HumanInviteError,
    IdentityError,
    SessionError,
    SessionIssue,
    SessionPrincipal,
)
from .ingestion import (
    CollectorIngestionError,
    CollectorIngestionService,
    DeviceBindingError,
)
from .operations import StandaloneOperationsRepository
from .presentation import (
    CaseFilterPriority,
    CaseFilterStatus,
    PresentationError,
    StandalonePresentationRepository,
)
from .ratelimit import SlidingWindowRateLimiter
from .replay import DecisionReplayService, ReplayError
from .response import (
    DeviceActionBindingError,
    ResponseAction,
    ResponseConflictError,
    ResponseExpiredError,
    ResponseNotFoundError,
    ResponseValidationError,
    StandaloneResponseService,
)
from .retention import RetentionError, StandaloneRetentionService
from .store import EventIdentityConflict
from .supervisor import StandaloneWorkerSupervisor

SESSION_COOKIE = "controlforge_session"


class BootstrapOptionsInput(BaseModel):
    model_config = ConfigDict(extra="forbid")

    token: str = Field(min_length=32, max_length=256)
    tenant_slug: str = Field(min_length=3, max_length=48)
    tenant_display_name: str = Field(min_length=1, max_length=120)
    email: str = Field(min_length=3, max_length=320)
    display_name: str = Field(min_length=1, max_length=120)


class BootstrapCompleteInput(BaseModel):
    model_config = ConfigDict(extra="forbid")

    token: str = Field(min_length=32, max_length=256)
    challenge_id: str = Field(min_length=1, max_length=128)
    credential: dict[str, object]


class LoginOptionsInput(BaseModel):
    model_config = ConfigDict(extra="forbid")

    tenant_slug: str = Field(min_length=3, max_length=48)
    email: str = Field(min_length=3, max_length=320)


class LoginCompleteInput(BaseModel):
    model_config = ConfigDict(extra="forbid")

    challenge_id: str = Field(min_length=1, max_length=128)
    credential: dict[str, object]


class RecoveryInput(BaseModel):
    model_config = ConfigDict(extra="forbid")

    tenant_slug: str = Field(min_length=3, max_length=48)
    email: str = Field(min_length=3, max_length=320)
    recovery_code: str = Field(min_length=16, max_length=128)


class PasskeyRegistrationCompleteInput(BaseModel):
    model_config = ConfigDict(extra="forbid")

    challenge_id: str = Field(min_length=1, max_length=128)
    credential: dict[str, object]
    label: str = Field(min_length=1, max_length=120)


class EnrollmentGrantInput(BaseModel):
    model_config = ConfigDict(extra="forbid")

    expected_device_id: Optional[str] = Field(
        default=None,
        min_length=1,
        max_length=128,
        pattern=r"^[A-Za-z0-9._:-]+$",
    )
    expires_in_minutes: int = Field(default=15, ge=5, le=1_440)


class EnrollmentClaimInput(BaseModel):
    model_config = ConfigDict(extra="forbid")

    token: str = Field(min_length=32, max_length=128)
    device_id: str = Field(
        min_length=1,
        max_length=128,
        pattern=r"^[A-Za-z0-9._:-]+$",
    )
    display_name: str = Field(min_length=1, max_length=100)
    platform: str = Field(pattern=r"^macos$")


class CredentialRotationInput(BaseModel):
    model_config = ConfigDict(extra="forbid")

    lifetime_days: int = Field(default=90, ge=1, le=365)


class ReplayInput(BaseModel):
    model_config = ConfigDict(extra="forbid")

    mode: Literal["original", "current"] = "original"


class CaseNoteInput(BaseModel):
    model_config = ConfigDict(extra="forbid")

    note: str = Field(min_length=1, max_length=4_000)


class CaseTransitionInput(BaseModel):
    model_config = ConfigDict(extra="forbid")

    status: Literal["open", "investigating", "contained", "closed"]


class CaseDispositionInput(BaseModel):
    model_config = ConfigDict(extra="forbid")

    status: Literal["true_positive", "false_positive", "benign", "inconclusive"]
    rationale: str = Field(min_length=1, max_length=4_000)
    false_positive_reason: Optional[str] = Field(default=None, max_length=1_000)


class CaseAssignmentInput(BaseModel):
    model_config = ConfigDict(extra="forbid")

    assignee_user_id: Optional[str] = Field(default=None, max_length=128)


class HumanInviteCreateInput(BaseModel):
    model_config = ConfigDict(extra="forbid")

    email: str = Field(min_length=3, max_length=320)
    display_name: str = Field(min_length=1, max_length=120)
    role: Literal["responder", "admin"]
    expires_in_minutes: int = Field(default=15, ge=1, le=60)


class HumanInviteOptionsInput(BaseModel):
    model_config = ConfigDict(extra="forbid")

    token: str = Field(min_length=32, max_length=256)


class HumanInviteCompleteInput(HumanInviteOptionsInput):
    challenge_id: str = Field(min_length=1, max_length=128)
    credential: dict[str, object]


class ResponseProposalInput(BaseModel):
    model_config = ConfigDict(extra="forbid")

    action_type: Literal["isolate_endpoint", "release_endpoint"]
    device_id: str = Field(
        min_length=1,
        max_length=128,
        pattern=r"^[A-Za-z0-9._:-]+$",
    )
    rationale: str = Field(min_length=1, max_length=500)
    expires_in_seconds: int = Field(default=300, ge=60, le=900)


class ResponseRejectionInput(BaseModel):
    model_config = ConfigDict(extra="forbid")

    reason: str = Field(min_length=1, max_length=500)


class RetentionPolicyInput(BaseModel):
    model_config = ConfigDict(extra="forbid")

    telemetry_days: int = Field(ge=30, le=3_650)


class AgentResultInput(BaseModel):
    model_config = ConfigDict(extra="forbid")

    status: Literal["succeeded", "failed"]
    summary: str = Field(min_length=1, max_length=500)
    evidence: list[str] = Field(default_factory=list, max_length=20)


@dataclass(frozen=True)
class StandaloneApiServices:
    identity: HumanIdentityService
    ingestion: CollectorIngestionService
    enrollment: DeviceEnrollmentService
    operations: StandaloneOperationsRepository
    replay: DecisionReplayService
    cases: StandaloneCaseService
    worker: Optional[StandaloneWorkerSupervisor] = None
    rate_limiter: SlidingWindowRateLimiter = field(default_factory=SlidingWindowRateLimiter)
    responses: Optional[StandaloneResponseService] = None
    presentation: Optional[StandalonePresentationRepository] = None
    retention: Optional[StandaloneRetentionService] = None
    credential_rotation: Optional[DeviceCredentialRotationService] = None


class PublicRateLimitError(RuntimeError):
    """Raised after a public authentication or enrollment budget is exhausted."""

    def __init__(self, retry_after_seconds: int) -> None:
        super().__init__("public request rate limit exceeded")
        self.retry_after_seconds = retry_after_seconds


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


def create_standalone_app(
    services: StandaloneApiServices,
    admin_origin: str,
    clock: Callable[[], datetime] = _utc_now,
) -> FastAPI:
    """Build the intentionally small standalone authenticated surface."""

    expected_origin = admin_origin.rstrip("/")
    if not expected_origin.startswith("https://"):
        raise ValueError("standalone admin origin must use HTTPS")

    @asynccontextmanager
    async def lifespan(_app: FastAPI) -> AsyncIterator[None]:
        task: Optional[asyncio.Task[None]] = None
        if services.worker is not None:
            task = asyncio.create_task(services.worker.run())
        try:
            yield
        finally:
            if services.worker is not None and task is not None:
                services.worker.stop()
                await task

    app = FastAPI(
        title="ControlForge Standalone API",
        version=__version__,
        description="Authenticated standalone security operations control plane.",
        lifespan=lifespan,
    )

    @app.middleware("http")
    async def security_headers(
        request: Request,
        call_next: Callable[[Request], Awaitable[Response]],
    ) -> Response:
        response = await call_next(request)
        response.headers["x-content-type-options"] = "nosniff"
        response.headers["x-frame-options"] = "DENY"
        response.headers["referrer-policy"] = "no-referrer"
        response.headers["permissions-policy"] = "camera=(), microphone=(), geolocation=()"
        response.headers["strict-transport-security"] = (
            "max-age=63072000; includeSubDomains; preload"
        )
        response.headers["cache-control"] = "no-store"
        if "content-security-policy" not in response.headers:
            response.headers["content-security-policy"] = (
                "default-src 'none'; frame-ancestors 'none'; base-uri 'none'"
            )
        return response

    @app.exception_handler(HumanAuthorizationError)
    async def human_authorization_error(
        _request: Request,
        _error: HumanAuthorizationError,
    ) -> JSONResponse:
        return JSONResponse({"error": "authorization failed"}, status_code=403)

    @app.exception_handler(BootstrapError)
    @app.exception_handler(ChallengeError)
    @app.exception_handler(SessionError)
    @app.exception_handler(HumanInviteError)
    async def human_authentication_error(
        _request: Request,
        _error: IdentityError,
    ) -> JSONResponse:
        return JSONResponse({"error": "authentication failed"}, status_code=401)

    @app.exception_handler(CollectorReplayError)
    async def collector_replay_error(
        _request: Request,
        _error: CollectorReplayError,
    ) -> JSONResponse:
        return JSONResponse({"error": "collector request replayed"}, status_code=409)

    @app.exception_handler(CollectorAuthenticationError)
    async def collector_authentication_error(
        _request: Request,
        _error: CollectorAuthenticationError,
    ) -> JSONResponse:
        return JSONResponse({"error": "collector authentication failed"}, status_code=401)

    @app.exception_handler(DeviceBindingError)
    async def device_binding_error(
        _request: Request,
        _error: DeviceBindingError,
    ) -> JSONResponse:
        return JSONResponse({"error": "collector device binding failed"}, status_code=403)

    @app.exception_handler(CollectorIngestionError)
    async def collector_ingestion_error(
        _request: Request,
        _error: CollectorIngestionError,
    ) -> JSONResponse:
        return JSONResponse({"error": "collector ingestion failed"}, status_code=400)

    @app.exception_handler(EventIdentityConflict)
    async def event_identity_conflict(
        _request: Request,
        _error: EventIdentityConflict,
    ) -> JSONResponse:
        return JSONResponse({"error": "event identity conflict"}, status_code=409)

    @app.exception_handler(EnrollmentError)
    async def enrollment_error(
        _request: Request,
        _error: EnrollmentError,
    ) -> JSONResponse:
        return JSONResponse({"error": "device enrollment failed"}, status_code=409)

    @app.exception_handler(ReplayError)
    async def replay_error(
        _request: Request,
        _error: ReplayError,
    ) -> JSONResponse:
        return JSONResponse({"error": "alert replay failed"}, status_code=404)

    @app.exception_handler(CaseNotFoundError)
    async def case_not_found_error(
        _request: Request,
        _error: CaseNotFoundError,
    ) -> JSONResponse:
        return JSONResponse({"error": "case is unavailable"}, status_code=404)

    @app.exception_handler(CaseTransitionError)
    async def case_transition_error(
        _request: Request,
        _error: CaseTransitionError,
    ) -> JSONResponse:
        return JSONResponse({"error": "case transition rejected"}, status_code=409)

    @app.exception_handler(CaseValidationError)
    async def case_validation_error(
        _request: Request,
        _error: CaseValidationError,
    ) -> JSONResponse:
        return JSONResponse({"error": "case input rejected"}, status_code=400)

    @app.exception_handler(ResponseNotFoundError)
    async def response_not_found_error(
        _request: Request,
        _error: ResponseNotFoundError,
    ) -> JSONResponse:
        return JSONResponse({"error": "response action is unavailable"}, status_code=404)

    @app.exception_handler(ResponseExpiredError)
    @app.exception_handler(ResponseConflictError)
    async def response_conflict_error(
        _request: Request,
        _error: ResponseConflictError,
    ) -> JSONResponse:
        return JSONResponse({"error": "response action transition rejected"}, status_code=409)

    @app.exception_handler(ResponseValidationError)
    async def response_validation_error(
        _request: Request,
        _error: ResponseValidationError,
    ) -> JSONResponse:
        return JSONResponse({"error": "response action input rejected"}, status_code=400)

    @app.exception_handler(PresentationError)
    async def presentation_error(
        _request: Request,
        _error: PresentationError,
    ) -> JSONResponse:
        return JSONResponse({"error": "dashboard projection is unavailable"}, status_code=400)

    @app.exception_handler(RetentionError)
    async def retention_error(
        _request: Request,
        _error: RetentionError,
    ) -> JSONResponse:
        return JSONResponse({"error": "retention operation rejected"}, status_code=409)

    @app.exception_handler(DeviceActionBindingError)
    async def response_device_binding_error(
        _request: Request,
        _error: DeviceActionBindingError,
    ) -> JSONResponse:
        return JSONResponse({"error": "response device binding failed"}, status_code=403)

    @app.exception_handler(PublicRateLimitError)
    async def public_rate_limit_error(
        _request: Request,
        error: PublicRateLimitError,
    ) -> JSONResponse:
        return JSONResponse(
            {"error": "too many requests"},
            status_code=429,
            headers={"retry-after": str(error.retry_after_seconds)},
        )

    def require_origin(request: Request) -> None:
        if request.headers.get("origin", "").rstrip("/") != expected_origin:
            raise HumanAuthorizationError("request origin is not allowed")

    def require_public_budget(
        request: Request,
        scope: str,
        *,
        limit: int,
        window: timedelta,
        identity: str = "",
    ) -> None:
        client_host = request.client.host if request.client is not None else "unknown"
        decision = services.rate_limiter.check(
            scope,
            f"{client_host}|{identity}",
            clock(),
            limit=limit,
            window=window,
        )
        if not decision.allowed:
            raise PublicRateLimitError(decision.retry_after_seconds)

    def require_session(request: Request) -> SessionPrincipal:
        token = request.cookies.get(SESSION_COOKIE, "")
        return services.identity.authenticate_session(token, clock())

    def require_human_mutation(request: Request) -> SessionPrincipal:
        require_origin(request)
        principal = require_session(request)
        services.identity.verify_csrf(principal, request.headers.get("x-csrf-token", ""))
        return principal

    def require_response_service() -> StandaloneResponseService:
        if services.responses is None:
            raise ResponseNotFoundError("active response is unavailable")
        return services.responses

    def require_presentation() -> StandalonePresentationRepository:
        if services.presentation is None:
            raise PresentationError("dashboard presentation is unavailable")
        return services.presentation

    def require_retention_service() -> StandaloneRetentionService:
        if services.retention is None:
            raise RetentionError("retention is unavailable")
        return services.retention

    def require_credential_rotation_service() -> DeviceCredentialRotationService:
        if services.credential_rotation is None:
            raise EnrollmentError("credential rotation is unavailable")
        return services.credential_rotation

    async def signed_collector_request(request: Request) -> SignedCollectorRequest:
        return SignedCollectorRequest(
            method=request.method,
            path=request.url.path,
            body=await request.body(),
            credential_id=request.headers.get("x-controlforge-credential-id", ""),
            timestamp=request.headers.get("x-controlforge-timestamp", ""),
            nonce=request.headers.get("x-controlforge-nonce", ""),
            signature=request.headers.get("x-controlforge-signature", ""),
        )

    def set_session_cookie(response: Response, issue: SessionIssue) -> None:
        max_age = max(0, int((issue.principal.expires_at - clock()).total_seconds()))
        response.set_cookie(
            SESSION_COOKIE,
            issue.token,
            max_age=max_age,
            expires=issue.principal.expires_at,
            path="/",
            secure=True,
            httponly=True,
            samesite="strict",
        )

    def session_payload(issue: SessionIssue) -> dict[str, object]:
        return {
            "csrf_token": issue.csrf_token,
            "expires_at": issue.principal.expires_at.isoformat(),
            "recovery_codes": list(issue.recovery_codes),
        }

    def case_payload(case: CaseDetail) -> dict[str, object]:
        return {
            "case_id": case.case_id,
            "title": case.title,
            "priority": case.priority,
            "status": case.status,
            "assignee_user_id": case.assignee_user_id,
            "version": case.version,
            "opened_at": case.opened_at.isoformat(),
            "updated_at": case.updated_at.isoformat(),
            "closed_at": case.closed_at.isoformat() if case.closed_at is not None else None,
            "alert_ids": list(case.alert_ids),
            "alert_count": case.alert_count,
            "alerts_truncated": case.alerts_truncated,
            "activity": [
                {
                    "activity_id": item.activity_id,
                    "activity_type": item.activity_type,
                    "actor_id": item.actor_id,
                    "body": item.body,
                    "created_at": item.created_at.isoformat(),
                }
                for item in case.activity
            ],
            "activity_count": case.activity_count,
            "activity_truncated": case.activity_truncated,
            "dispositions": [
                {
                    "disposition_id": item.disposition_id,
                    "status": item.status,
                    "rationale": item.rationale,
                    "false_positive_reason": item.false_positive_reason,
                    "rule_version": item.rule_version,
                    "created_by": item.created_by,
                    "created_at": item.created_at.isoformat(),
                }
                for item in case.dispositions
            ],
            "disposition_count": case.disposition_count,
            "dispositions_truncated": case.dispositions_truncated,
        }

    def response_payload(action: ResponseAction) -> dict[str, object]:
        return {
            "action_id": action.action_id,
            "case_id": action.case_id,
            "action_type": action.action_type,
            "target_type": "device",
            "target_id": action.target_id,
            "rationale": action.rationale,
            "risk_level": "active",
            "status": action.status,
            "proposed_by": action.proposed_by,
            "proposed_at": action.proposed_at.isoformat(),
            "approved_by": action.approved_by,
            "approved_at": (
                action.approved_at.isoformat() if action.approved_at is not None else None
            ),
            "rejected_by": action.rejected_by,
            "rejected_at": (
                action.rejected_at.isoformat() if action.rejected_at is not None else None
            ),
            "rejection_reason": action.rejection_reason,
            "dispatch_count": action.dispatch_count,
            "dispatched_at": (
                action.dispatched_at.isoformat() if action.dispatched_at is not None else None
            ),
            "expires_at": action.expires_at.isoformat(),
            "completed_at": (
                action.completed_at.isoformat() if action.completed_at is not None else None
            ),
            "result_summary": action.result_summary,
            "result_evidence": list(action.result_evidence),
        }

    @app.get("/health")
    def health() -> dict[str, object]:
        worker_status = services.worker.status if services.worker is not None else None
        healthy = worker_status is None or worker_status.last_error is None
        return {
            "status": "ok" if healthy else "degraded",
            "service": "controlforge-standalone",
            "version": __version__,
            "worker": {
                "running": worker_status.running,
                "last_cycle_at": (
                    worker_status.last_cycle_at.isoformat()
                    if worker_status.last_cycle_at is not None
                    else None
                ),
                "last_error": worker_status.last_error,
            }
            if worker_status is not None
            else None,
        }

    @app.get("/", include_in_schema=False)
    def root() -> RedirectResponse:
        return RedirectResponse("/admin", status_code=307)

    @app.get("/admin", response_class=HTMLResponse, include_in_schema=False)
    def admin_dashboard() -> HTMLResponse:
        nonce = secrets.token_urlsafe(24)
        csp = (
            "default-src 'none'; "
            f"style-src 'nonce-{nonce}'; script-src 'nonce-{nonce}'; "
            "connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'"
        )
        return HTMLResponse(
            dashboard_html(nonce),
            headers={"content-security-policy": csp},
        )

    @app.get("/v1/bootstrap/status")
    def bootstrap_status() -> dict[str, bool]:
        return {"configured": services.identity.bootstrap_status().configured}

    @app.post("/v1/bootstrap/options")
    def bootstrap_options(request: Request, input_data: BootstrapOptionsInput) -> dict[str, object]:
        require_origin(request)
        require_public_budget(
            request,
            "bootstrap-options",
            limit=5,
            window=timedelta(minutes=10),
        )
        ceremony = services.identity.begin_bootstrap(
            input_data.token,
            input_data.tenant_slug,
            input_data.tenant_display_name,
            input_data.email,
            input_data.display_name,
            clock(),
        )
        return {
            "challenge_id": ceremony.challenge_id,
            "options": ceremony.options,
            "expires_at": ceremony.expires_at.isoformat(),
        }

    @app.post("/v1/bootstrap/complete")
    def bootstrap_complete(
        request: Request,
        response: Response,
        input_data: BootstrapCompleteInput,
    ) -> dict[str, object]:
        require_origin(request)
        require_public_budget(
            request,
            "bootstrap-complete",
            limit=5,
            window=timedelta(minutes=10),
        )
        issue = services.identity.complete_bootstrap(
            input_data.token,
            input_data.challenge_id,
            input_data.credential,
            clock(),
        )
        set_session_cookie(response, issue)
        return session_payload(issue)

    @app.post("/v1/auth/login/options")
    def login_options(request: Request, input_data: LoginOptionsInput) -> dict[str, object]:
        require_origin(request)
        require_public_budget(
            request,
            "login-options",
            limit=10,
            window=timedelta(minutes=10),
            identity=f"{input_data.tenant_slug}|{input_data.email}",
        )
        ceremony = services.identity.begin_authentication(
            input_data.tenant_slug,
            input_data.email,
            clock(),
        )
        return {
            "challenge_id": ceremony.challenge_id,
            "options": ceremony.options,
            "expires_at": ceremony.expires_at.isoformat(),
        }

    @app.post("/v1/team/invites", status_code=201)
    def issue_human_invite(
        request: Request,
        input_data: HumanInviteCreateInput,
    ) -> object:
        principal = require_human_mutation(request)
        try:
            invite = services.identity.issue_human_invite(
                principal,
                input_data.email,
                input_data.display_name,
                input_data.role,
                clock(),
                ttl_seconds=input_data.expires_in_minutes * 60,
            )
        except HumanInviteError:
            return JSONResponse({"error": "human invite could not be issued"}, status_code=409)
        return {
            "invite_id": invite.invite_id,
            "token": invite.token,
            "role": invite.role,
            "expires_at": invite.expires_at.isoformat(),
        }

    @app.post("/v1/auth/invites/options")
    def human_invite_options(
        request: Request,
        input_data: HumanInviteOptionsInput,
    ) -> dict[str, object]:
        require_origin(request)
        token_identity = hashlib.sha256(input_data.token.encode()).hexdigest()
        require_public_budget(
            request,
            "human-invite-options",
            limit=10,
            window=timedelta(minutes=10),
            identity=token_identity,
        )
        ceremony = services.identity.begin_human_invite(input_data.token, clock())
        return {
            "challenge_id": ceremony.challenge_id,
            "options": ceremony.options,
            "expires_at": ceremony.expires_at.isoformat(),
        }

    @app.post("/v1/auth/invites/complete")
    def human_invite_complete(
        request: Request,
        response: Response,
        input_data: HumanInviteCompleteInput,
    ) -> dict[str, object]:
        require_origin(request)
        token_identity = hashlib.sha256(input_data.token.encode()).hexdigest()
        require_public_budget(
            request,
            "human-invite-complete",
            limit=10,
            window=timedelta(minutes=10),
            identity=token_identity,
        )
        issue = services.identity.complete_human_invite(
            input_data.token,
            input_data.challenge_id,
            input_data.credential,
            clock(),
        )
        set_session_cookie(response, issue)
        return session_payload(issue)

    @app.post("/v1/auth/login/complete")
    def login_complete(
        request: Request,
        response: Response,
        input_data: LoginCompleteInput,
    ) -> dict[str, object]:
        require_origin(request)
        require_public_budget(
            request,
            "login-complete",
            limit=20,
            window=timedelta(minutes=10),
        )
        issue = services.identity.complete_authentication(
            input_data.challenge_id,
            input_data.credential,
            clock(),
        )
        set_session_cookie(response, issue)
        return session_payload(issue)

    @app.post("/v1/auth/recovery")
    def recover(
        request: Request,
        response: Response,
        input_data: RecoveryInput,
    ) -> dict[str, object]:
        require_origin(request)
        require_public_budget(
            request,
            "recovery",
            limit=5,
            window=timedelta(minutes=15),
            identity=f"{input_data.tenant_slug}|{input_data.email}",
        )
        issue = services.identity.recover_session(
            input_data.tenant_slug,
            input_data.email,
            input_data.recovery_code,
            clock(),
        )
        set_session_cookie(response, issue)
        return session_payload(issue)

    @app.get("/v1/auth/csrf")
    def csrf(request: Request) -> dict[str, str]:
        principal = require_session(request)
        return {"csrf_token": services.identity.rotate_csrf(principal, clock())}

    @app.post("/v1/auth/logout")
    def logout(request: Request, response: Response) -> dict[str, str]:
        principal = require_human_mutation(request)
        services.identity.revoke_session(principal, clock())
        response.delete_cookie(
            SESSION_COOKIE,
            path="/",
            secure=True,
            httponly=True,
            samesite="strict",
        )
        return {"status": "signed_out"}

    @app.get("/v1/me")
    def me(request: Request) -> dict[str, object]:
        principal = require_session(request)
        return {
            "tenant_id": principal.tenant_id,
            "user_id": principal.user_id,
            "email": principal.email,
            "display_name": principal.display_name,
            "role": principal.role,
        }

    @app.post("/v1/auth/passkeys/register/options")
    def passkey_registration_options(request: Request) -> dict[str, object]:
        principal = require_human_mutation(request)
        ceremony = services.identity.begin_passkey_registration(principal, clock())
        return {
            "challenge_id": ceremony.challenge_id,
            "options": ceremony.options,
            "expires_at": ceremony.expires_at.isoformat(),
        }

    @app.post("/v1/auth/passkeys/register/complete")
    def passkey_registration_complete(
        request: Request,
        input_data: PasskeyRegistrationCompleteInput,
    ) -> dict[str, str]:
        principal = require_human_mutation(request)
        credential_id = services.identity.complete_passkey_registration(
            principal,
            input_data.challenge_id,
            input_data.credential,
            input_data.label,
            clock(),
        )
        return {"credential_id": credential_id}

    @app.get("/v1/devices")
    def devices(request: Request) -> dict[str, object]:
        principal = require_session(request)
        services.identity.require_capability(
            principal,
            principal.tenant_id,
            Capability.VIEW,
        )
        records = services.enrollment.list_devices(principal.tenant_id, clock())
        return {
            "devices": [
                {
                    "device_id": item.device_id,
                    "display_name": item.display_name,
                    "platform": item.platform,
                    "status": item.status,
                    "enrolled_at": (
                        item.enrolled_at.isoformat() if item.enrolled_at is not None else None
                    ),
                    "last_seen_at": (
                        item.last_seen_at.isoformat() if item.last_seen_at is not None else None
                    ),
                    "active_credentials": item.active_credentials,
                }
                for item in records
            ]
        }

    @app.get("/v1/dashboard/summary")
    def dashboard_summary(request: Request) -> dict[str, int]:
        principal = require_session(request)
        services.identity.require_capability(
            principal,
            principal.tenant_id,
            Capability.VIEW,
        )
        result = services.operations.summary(principal.tenant_id, clock())
        return {
            "events_24h": result.events_24h,
            "alerts_24h": result.alerts_24h,
            "critical_open": result.critical_open,
            "open_cases": result.open_cases,
            "active_devices": result.active_devices,
            "pending_jobs": result.pending_jobs,
            "dead_jobs": result.dead_jobs,
        }

    @app.get("/v1/dashboard/posture")
    def dashboard_posture(request: Request) -> dict[str, object]:
        principal = require_session(request)
        services.identity.require_capability(principal, principal.tenant_id, Capability.VIEW)
        payload = require_presentation().posture(principal.tenant_id, clock()).as_dict()
        worker_status = services.worker.status if services.worker is not None else None
        payload["worker"] = (
            {
                "running": worker_status.running,
                "last_cycle_at": (
                    worker_status.last_cycle_at.isoformat()
                    if worker_status.last_cycle_at is not None
                    else None
                ),
                "last_error": worker_status.last_error,
            }
            if worker_status is not None
            else None
        )
        return payload

    @app.get("/v1/dashboard/devices")
    def dashboard_devices(request: Request, limit: int = 200) -> dict[str, object]:
        principal = require_session(request)
        services.identity.require_capability(principal, principal.tenant_id, Capability.VIEW)
        return {
            "devices": require_presentation().device_health(
                principal.tenant_id,
                clock(),
                limit,
            )
        }

    @app.get("/v1/dashboard/cases")
    def dashboard_cases(
        request: Request,
        status: Optional[CaseFilterStatus] = None,
        priority: Optional[CaseFilterPriority] = None,
        query: str = "",
        limit: int = 200,
    ) -> dict[str, object]:
        principal = require_session(request)
        services.identity.require_capability(principal, principal.tenant_id, Capability.VIEW)
        return {
            "cases": require_presentation().case_queue(
                principal.tenant_id,
                status=status,
                priority=priority,
                query=query,
                limit=limit,
            )
        }

    @app.get("/v1/dashboard/responses")
    def dashboard_responses(request: Request, limit: int = 200) -> dict[str, object]:
        principal = require_session(request)
        services.identity.require_capability(principal, principal.tenant_id, Capability.VIEW)
        return {"actions": require_presentation().response_queue(principal.tenant_id, limit)}

    @app.get("/v1/dashboard/case-assignees")
    def dashboard_case_assignees(request: Request) -> dict[str, object]:
        principal = require_session(request)
        services.identity.require_capability(principal, principal.tenant_id, Capability.VIEW)
        return {"assignees": require_presentation().case_assignees(principal.tenant_id)}

    @app.get("/v1/alerts")
    def recent_alerts(request: Request, limit: int = 30) -> list[dict[str, object]]:
        principal = require_session(request)
        services.identity.require_capability(
            principal,
            principal.tenant_id,
            Capability.VIEW,
        )
        return services.operations.recent_alerts(principal.tenant_id, limit)

    @app.get("/v1/cases")
    def recent_cases(request: Request, limit: int = 20) -> list[dict[str, object]]:
        principal = require_session(request)
        services.identity.require_capability(
            principal,
            principal.tenant_id,
            Capability.VIEW,
        )
        return services.operations.recent_cases(principal.tenant_id, limit)

    @app.get("/v1/cases/{case_id}")
    def case_detail(case_id: str, request: Request) -> dict[str, object]:
        principal = require_session(request)
        return case_payload(services.cases.get_case(principal, case_id))

    @app.get("/v1/cases/{case_id}/evidence")
    def case_evidence(case_id: str, request: Request) -> dict[str, object]:
        principal = require_session(request)
        services.identity.require_capability(principal, principal.tenant_id, Capability.VIEW)
        case = services.cases.get_case(principal, case_id)
        evidence = require_presentation().case_evidence(principal.tenant_id, case_id)
        return {
            "evidence": evidence,
            "total": case.alert_count,
            "truncated": case.alert_count > len(evidence),
        }

    @app.post("/v1/cases/{case_id}/notes", status_code=201)
    def add_case_note(
        case_id: str,
        request: Request,
        input_data: CaseNoteInput,
    ) -> dict[str, object]:
        principal = require_human_mutation(request)
        activity = services.cases.add_note(
            principal,
            case_id,
            input_data.note,
            clock(),
        )
        return {
            "activity_id": activity.activity_id,
            "activity_type": activity.activity_type,
            "actor_id": activity.actor_id,
            "body": activity.body,
            "created_at": activity.created_at.isoformat(),
        }

    @app.post("/v1/cases/{case_id}/assignment")
    def assign_case(
        case_id: str,
        request: Request,
        input_data: CaseAssignmentInput,
    ) -> dict[str, object]:
        principal = require_human_mutation(request)
        return case_payload(
            services.cases.assign(
                principal,
                case_id,
                input_data.assignee_user_id,
                clock(),
            )
        )

    @app.post("/v1/cases/{case_id}/transitions")
    def transition_case(
        case_id: str,
        request: Request,
        input_data: CaseTransitionInput,
    ) -> dict[str, object]:
        principal = require_human_mutation(request)
        return case_payload(
            services.cases.transition(
                principal,
                case_id,
                input_data.status,
                clock(),
            )
        )

    @app.post("/v1/cases/{case_id}/dispositions", status_code=201)
    def record_case_disposition(
        case_id: str,
        request: Request,
        input_data: CaseDispositionInput,
    ) -> dict[str, object]:
        principal = require_human_mutation(request)
        disposition = services.cases.record_disposition(
            principal,
            case_id,
            input_data.status,
            input_data.rationale,
            input_data.false_positive_reason,
            clock(),
        )
        return {
            "disposition_id": disposition.disposition_id,
            "status": disposition.status,
            "rationale": disposition.rationale,
            "false_positive_reason": disposition.false_positive_reason,
            "rule_version": disposition.rule_version,
            "created_by": disposition.created_by,
            "created_at": disposition.created_at.isoformat(),
        }

    @app.post("/v1/cases/{case_id}/response-actions", status_code=201)
    def propose_response_action(
        case_id: str,
        request: Request,
        input_data: ResponseProposalInput,
    ) -> dict[str, object]:
        principal = require_human_mutation(request)
        action = require_response_service().propose(
            principal,
            case_id,
            input_data.action_type,
            input_data.device_id,
            input_data.rationale,
            clock(),
            expires_in_seconds=input_data.expires_in_seconds,
        )
        return response_payload(action)

    @app.get("/v1/response-actions")
    def list_response_actions(request: Request, limit: int = 100) -> dict[str, object]:
        principal = require_session(request)
        actions = require_response_service().list_actions(principal, clock(), limit=limit)
        return {"actions": [response_payload(action) for action in actions]}

    @app.post("/v1/response-actions/{action_id}/approve")
    def approve_response_action(action_id: str, request: Request) -> dict[str, object]:
        principal = require_human_mutation(request)
        return response_payload(require_response_service().approve(principal, action_id, clock()))

    @app.post("/v1/response-actions/{action_id}/reject")
    def reject_response_action(
        action_id: str,
        request: Request,
        input_data: ResponseRejectionInput,
    ) -> dict[str, object]:
        principal = require_human_mutation(request)
        return response_payload(
            require_response_service().reject(
                principal,
                action_id,
                input_data.reason,
                clock(),
            )
        )

    @app.get("/v1/retention")
    def retention_status(request: Request) -> dict[str, object]:
        principal = require_session(request)
        service = require_retention_service()
        policy = service.policy(principal)
        preview = service.preview(principal, clock())
        latest_run = service.latest_run(principal)
        return {
            "policy": {
                "telemetry_days": policy.telemetry_days,
                "updated_by": policy.updated_by,
                "updated_at": policy.updated_at.isoformat() if policy.updated_at else None,
            },
            "preview": {
                "cutoff_at": preview.cutoff_at.isoformat(),
                "terminal_jobs": preview.terminal_jobs,
                "unreferenced_events": preview.unreferenced_events,
            },
            "latest_run": (
                {
                    "run_id": latest_run.run_id,
                    "cutoff_at": latest_run.cutoff_at.isoformat(),
                    "terminal_jobs_deleted": latest_run.terminal_jobs_deleted,
                    "unreferenced_events_deleted": latest_run.unreferenced_events_deleted,
                    "executed_by": latest_run.executed_by,
                    "executed_at": latest_run.executed_at.isoformat(),
                }
                if latest_run is not None
                else None
            ),
            "preserved": [
                "alerts",
                "cases",
                "dispositions",
                "response actions",
                "audit chain",
            ],
        }

    @app.put("/v1/retention/policy")
    def update_retention_policy(
        request: Request,
        input_data: RetentionPolicyInput,
    ) -> dict[str, object]:
        principal = require_human_mutation(request)
        policy = require_retention_service().set_policy(
            principal,
            input_data.telemetry_days,
            clock(),
        )
        return {
            "telemetry_days": policy.telemetry_days,
            "updated_by": policy.updated_by,
            "updated_at": policy.updated_at.isoformat() if policy.updated_at else None,
        }

    @app.post("/v1/retention/apply")
    def apply_retention(request: Request) -> dict[str, object]:
        principal = require_human_mutation(request)
        result = require_retention_service().apply(principal, clock())
        return {
            "run_id": result.run_id,
            "cutoff_at": result.cutoff_at.isoformat(),
            "terminal_jobs_deleted": result.terminal_jobs_deleted,
            "unreferenced_events_deleted": result.unreferenced_events_deleted,
            "executed_by": result.executed_by,
            "executed_at": result.executed_at.isoformat(),
        }

    @app.get("/v1/audit/verify")
    def verify_audit(request: Request) -> dict[str, object]:
        principal = require_session(request)
        result = services.cases.verify_audit(principal)
        return {
            "valid": result.valid,
            "entries_checked": result.entries_checked,
            "checkpoints_checked": result.checkpoints_checked,
            "terminal_hmac": result.terminal_hmac,
            "failure_sequence": result.failure_sequence,
            "reason": result.reason,
        }

    @app.post("/v1/alerts/{alert_id}/replay", status_code=201)
    def replay_alert(
        alert_id: str,
        request: Request,
        input_data: ReplayInput,
    ) -> dict[str, object]:
        principal = require_human_mutation(request)
        services.identity.require_capability(
            principal,
            principal.tenant_id,
            Capability.TRIAGE,
        )
        result = services.replay.replay(
            principal.tenant_id,
            alert_id,
            principal.user_id,
            input_data.mode,
            clock(),
        )
        return {
            "replay_id": result.replay_id,
            "alert_id": result.alert_id,
            "mode": result.mode,
            "outcome": result.outcome,
            "matched": result.matched,
            "rule_id": result.rule_id,
            "rule_version": result.rule_version,
            "rule_digest": result.rule_digest,
            "detector_version": result.detector_version,
            "evidence": result.evidence,
        }

    @app.post("/v1/devices/enrollment-grants", status_code=201)
    def create_enrollment_grant(
        request: Request,
        input_data: EnrollmentGrantInput,
    ) -> dict[str, object]:
        principal = require_human_mutation(request)
        services.identity.require_capability(
            principal,
            principal.tenant_id,
            Capability.MANAGE,
        )
        grant = services.enrollment.issue_grant(
            principal.tenant_id,
            principal.user_id,
            clock(),
            expires_in=timedelta(minutes=input_data.expires_in_minutes),
            expected_device_id=input_data.expected_device_id,
        )
        return {
            "token_id": grant.token_id,
            "token": grant.token,
            "expires_at": grant.expires_at.isoformat(),
            "expected_device_id": grant.expected_device_id,
        }

    @app.post("/v1/devices/enroll", status_code=201)
    def claim_enrollment_grant(
        request: Request,
        input_data: EnrollmentClaimInput,
    ) -> dict[str, object]:
        require_public_budget(
            request,
            "device-enrollment",
            limit=10,
            window=timedelta(minutes=15),
            identity=input_data.device_id,
        )
        credential = services.enrollment.claim_grant(
            input_data.token,
            input_data.device_id,
            input_data.display_name,
            input_data.platform,
            clock(),
        )
        return {
            "tenant_id": credential.tenant_id,
            "device_id": credential.device_id,
            "credential_id": credential.credential_id,
            "credential_secret": credential.secret,
            "expires_at": credential.expires_at.isoformat(),
        }

    @app.post("/v1/devices/{device_id}/credentials/rotate", status_code=201)
    def rotate_device_credential(
        device_id: str,
        request: Request,
        input_data: CredentialRotationInput,
    ) -> dict[str, object]:
        principal = require_human_mutation(request)
        services.identity.require_capability(
            principal,
            principal.tenant_id,
            Capability.MANAGE,
        )
        rotation = require_credential_rotation_service().initiate(
            principal.tenant_id,
            device_id,
            principal.user_id,
            clock(),
            credential_lifetime=timedelta(days=input_data.lifetime_days),
        )
        return {
            "rotation_id": rotation.rotation_id,
            "device_id": rotation.device_id,
            "predecessor_credential_id": rotation.predecessor_credential_id,
            "replacement_credential_id": rotation.replacement_credential_id,
            "status": rotation.status,
            "delivery_expires_at": rotation.delivery_expires_at.isoformat(),
        }

    @app.get("/v1/agent/credential-rotation")
    async def poll_credential_rotation(
        request: Request,
        device_id: str,
    ) -> dict[str, object]:
        envelope = require_credential_rotation_service().poll(
            await signed_collector_request(request),
            device_id,
            clock(),
        )
        return {"rotation": envelope.model_dump(mode="json") if envelope is not None else None}

    @app.post("/v1/agent/credential-rotation/ack")
    async def acknowledge_credential_rotation(request: Request) -> dict[str, object]:
        rotation = require_credential_rotation_service().acknowledge(
            await signed_collector_request(request),
            clock(),
        )
        return {
            "rotation_id": rotation.rotation_id if rotation is not None else None,
            "status": rotation.status if rotation is not None else "none",
            "changed": rotation.changed if rotation is not None else False,
        }

    @app.post("/v1/devices/{device_id}/credentials/{credential_id}/revoke")
    def revoke_device_credential(
        device_id: str,
        credential_id: str,
        request: Request,
    ) -> dict[str, object]:
        principal = require_human_mutation(request)
        services.identity.require_capability(
            principal,
            principal.tenant_id,
            Capability.MANAGE,
        )
        changed = services.enrollment.revoke_credential(
            principal.tenant_id,
            device_id,
            credential_id,
            clock(),
        )
        return {"revoked": changed}

    @app.post("/v1/devices/{device_id}/revoke")
    def revoke_device(device_id: str, request: Request) -> dict[str, object]:
        principal = require_human_mutation(request)
        services.identity.require_capability(
            principal,
            principal.tenant_id,
            Capability.MANAGE,
        )
        changed = services.enrollment.revoke_device(
            principal.tenant_id,
            device_id,
            clock(),
        )
        return {"revoked": changed}

    @app.post("/v1/ingest/events", status_code=202)
    async def ingest_events(request: Request) -> dict[str, object]:
        signed = await signed_collector_request(request)
        result = services.ingestion.ingest(signed, clock())
        return {
            "accepted": result.accepted,
            "duplicates": result.duplicates,
            "event_ids": list(result.event_ids),
        }

    @app.get("/v1/agent/actions")
    async def poll_agent_actions(request: Request, device_id: str) -> dict[str, object]:
        actions = require_response_service().poll_device(
            await signed_collector_request(request),
            device_id,
            clock(),
        )
        return {
            "actions": [
                {
                    "action_id": action.action_id,
                    "action_type": action.action_type,
                    "target_type": action.target_type,
                    "target_id": action.target_id,
                    "rationale": action.rationale,
                    "risk_level": action.risk_level,
                    "expires_at": action.expires_at.isoformat(),
                }
                for action in actions
            ]
        }

    @app.post("/v1/agent/actions/{action_id}/result")
    async def submit_agent_action_result(
        action_id: str,
        request: Request,
        input_data: AgentResultInput,
    ) -> dict[str, object]:
        result = require_response_service().submit_device_result(
            await signed_collector_request(request),
            action_id,
            input_data.status,
            input_data.summary,
            input_data.evidence,
            clock(),
        )
        return {
            "action_id": result.action_id,
            "status": result.status,
            "changed": result.changed,
        }

    return app
