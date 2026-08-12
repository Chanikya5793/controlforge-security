from __future__ import annotations

import base64
import hashlib
import hmac
import json
import sqlite3
import threading
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import cast

import pytest
from fastapi.testclient import TestClient

from controlforge.standalone.api import StandaloneApiServices, create_standalone_app
from controlforge.standalone.audit import StandaloneAuditLog
from controlforge.standalone.auth import (
    CollectorReplayError,
    DeviceHmacAuthenticator,
    SignedCollectorRequest,
)
from controlforge.standalone.cases import StandaloneCaseService
from controlforge.standalone.database import StandaloneDatabase
from controlforge.standalone.enrollment import (
    AesGcmDeviceCredentialCipher,
    DeviceEnrollmentService,
)
from controlforge.standalone.identity import (
    HumanAuthorizationError,
    HumanIdentityService,
    HumanInviteError,
    Role,
    SessionIssue,
    SessionPrincipal,
)
from controlforge.standalone.ingestion import CollectorIngestionService
from controlforge.standalone.operations import StandaloneOperationsRepository
from controlforge.standalone.passkeys import (
    AuthenticationVerification,
    PasskeyAdapter,
    RegistrationVerification,
)
from controlforge.standalone.replay import DecisionReplayService
from controlforge.standalone.response import (
    DeviceActionBindingError,
    ResponseConflictError,
    ResponseExpiredError,
    ResponseNotFoundError,
    StandaloneResponseService,
)
from controlforge.standalone.settings import StandaloneSettings
from controlforge.standalone.store import StandaloneStore

NOW = datetime(2026, 8, 22, 23, 0, tzinfo=timezone.utc)
ORIGIN = "https://admin.controlforge.test"
TENANT_ID = "00000000-0000-4000-8000-000000000201"
OTHER_TENANT_ID = "00000000-0000-4000-8000-000000000202"
CASE_ID = "response-case-open"
CLOSED_CASE_ID = "response-case-closed"
CREDENTIAL_ID = "response-credential-mac-1"
OTHER_CREDENTIAL_ID = "response-credential-mac-2"
SECRET = b"response-test-device-secret-material-000001"
OTHER_SECRET = b"response-test-device-secret-material-000002"
SESSION_PEPPER = b"response-session-pepper-material-00001"
RECOVERY_PEPPER = b"response-recovery-pepper-material-001"
AUDIT_KEY = b"response-audit-key-material-0000000001"


class SecretResolver:
    def resolve(
        self,
        credential_id: str,
        secret_ciphertext: str,
        secret_iv: str,
    ) -> bytes:
        assert secret_ciphertext.startswith("encrypted-")
        assert secret_iv.startswith("response-")
        return {
            CREDENTIAL_ID: SECRET,
            OTHER_CREDENTIAL_ID: OTHER_SECRET,
        }[credential_id]


class FakePasskeyAdapter:
    @staticmethod
    def _challenge(value: bytes) -> str:
        return base64.urlsafe_b64encode(value).decode("ascii")

    def registration_options(
        self,
        user_id: str,
        user_name: str,
        display_name: str,
        challenge: bytes,
        exclude_credential_ids: list[str],
    ) -> dict[str, object]:
        return {
            "challenge": self._challenge(challenge),
            "user_id": user_id,
            "user_name": user_name,
            "display_name": display_name,
            "exclude": exclude_credential_ids,
        }

    def verify_registration(
        self,
        response: dict[str, object],
        challenge: bytes,
    ) -> RegistrationVerification:
        if response.get("challenge") != self._challenge(challenge):
            raise ValueError("challenge mismatch")
        credential_id = response.get("id")
        if not isinstance(credential_id, str):
            raise ValueError("credential missing")
        return RegistrationVerification(credential_id, b"response-public-key", 0)

    def authentication_options(
        self,
        challenge: bytes,
        credential_ids: list[str],
    ) -> dict[str, object]:
        return {"challenge": self._challenge(challenge), "allow": credential_ids}

    def response_credential_id(self, response: dict[str, object]) -> str:
        credential_id = response.get("id")
        if not isinstance(credential_id, str):
            raise ValueError("credential missing")
        return credential_id

    def verify_authentication(
        self,
        response: dict[str, object],
        challenge: bytes,
        public_key: bytes,
        current_sign_count: int,
    ) -> AuthenticationVerification:
        if response.get("challenge") != self._challenge(challenge):
            raise ValueError("challenge mismatch")
        assert public_key == b"response-public-key"
        return AuthenticationVerification(
            self.response_credential_id(response),
            current_sign_count + 1,
        )


def principal(user_id: str, role: Role, tenant_id: str = TENANT_ID) -> SessionPrincipal:
    return SessionPrincipal(
        tenant_id=tenant_id,
        user_id=user_id,
        email=f"{user_id}@example.com",
        display_name=user_id,
        role=role,
        session_id=f"session-{user_id}",
        expires_at=NOW + timedelta(hours=1),
        csrf_hash="unused",
    )


def configured_service(
    tmp_path: Path,
) -> tuple[
    StandaloneDatabase,
    StandaloneStore,
    HumanIdentityService,
    StandaloneAuditLog,
    StandaloneResponseService,
]:
    database = StandaloneDatabase(StandaloneSettings(database_path=tmp_path / "response.db"))
    database.initialize()
    store = StandaloneStore(database)
    store.create_tenant(TENANT_ID, "response", "Response tenant", NOW)
    store.create_tenant(OTHER_TENANT_ID, "other", "Other tenant", NOW)
    store.register_device(TENANT_ID, "mac-1", "Primary Mac", "macos", NOW)
    store.register_device(TENANT_ID, "mac-2", "Second Mac", "macos", NOW)
    store.register_device_credential(
        CREDENTIAL_ID,
        TENANT_ID,
        "mac-1",
        "primary",
        "encrypted-response-one",
        "response-iv-one",
        NOW,
        NOW + timedelta(days=30),
    )
    store.register_device_credential(
        OTHER_CREDENTIAL_ID,
        TENANT_ID,
        "mac-2",
        "primary",
        "encrypted-response-two",
        "response-iv-two",
        NOW,
        NOW + timedelta(days=30),
    )
    audit = StandaloneAuditLog(database, AUDIT_KEY)
    identity = HumanIdentityService(
        database,
        cast(PasskeyAdapter, object()),
        SESSION_PEPPER,
        RECOVERY_PEPPER,
        audit=audit,
    )
    with database.connect() as connection:
        for tenant_id, user_id, role in (
            (TENANT_ID, "responder-a", "responder"),
            (TENANT_ID, "responder-b", "responder"),
            (TENANT_ID, "analyst-a", "analyst"),
            (TENANT_ID, "admin-a", "admin"),
            (OTHER_TENANT_ID, "admin-other", "admin"),
        ):
            connection.execute(
                """
                INSERT INTO users(
                    tenant_id, user_id, email, display_name, role, status, created_at
                ) VALUES (?, ?, ?, ?, ?, 'active', ?)
                """,
                (tenant_id, user_id, f"{user_id}@example.com", user_id, role, NOW.isoformat()),
            )
        for case_id, status in ((CASE_ID, "open"), (CLOSED_CASE_ID, "closed")):
            connection.execute(
                """
                INSERT INTO cases(
                    tenant_id, case_id, title, priority, status,
                    opened_at, updated_at, closed_at
                ) VALUES (?, ?, ?, 'critical', ?, ?, ?, ?)
                """,
                (
                    TENANT_ID,
                    case_id,
                    case_id,
                    status,
                    NOW.isoformat(),
                    NOW.isoformat(),
                    NOW.isoformat() if status == "closed" else None,
                ),
            )
    authenticator = DeviceHmacAuthenticator(database, SecretResolver())
    return (
        database,
        store,
        identity,
        audit,
        StandaloneResponseService(database, identity, audit, authenticator),
    )


def signed_request(
    method: str,
    path: str,
    body: bytes = b"",
    *,
    nonce: str,
    credential_id: str = CREDENTIAL_ID,
    secret: bytes = SECRET,
    timestamp: datetime = NOW,
) -> SignedCollectorRequest:
    unsigned = SignedCollectorRequest(
        method=method,
        path=path,
        body=body,
        credential_id=credential_id,
        timestamp=timestamp.isoformat().replace("+00:00", "Z"),
        nonce=nonce,
        signature="0" * 64,
    )
    signature = hmac.new(
        secret,
        DeviceHmacAuthenticator.canonical_request(unsigned),
        hashlib.sha256,
    ).hexdigest()
    return SignedCollectorRequest(
        method=method,
        path=path,
        body=body,
        credential_id=credential_id,
        timestamp=unsigned.timestamp,
        nonce=nonce,
        signature=signature,
    )


def propose_and_approve(
    service: StandaloneResponseService,
    *,
    now: datetime = NOW,
    expires_in_seconds: int = 300,
) -> str:
    action = service.propose(
        principal("responder-a", "responder"),
        CASE_ID,
        "isolate_endpoint",
        "mac-1",
        "Confirmed credential theft requires temporary isolation.",
        now,
        expires_in_seconds=expires_in_seconds,
    )
    service.approve(principal("responder-b", "responder"), action.action_id, now)
    return action.action_id


def close_response_case(database: StandaloneDatabase, disposition_id: str) -> None:
    with database.connect() as connection:
        connection.execute(
            """
            INSERT INTO dispositions(
                tenant_id, disposition_id, case_id, status, rationale,
                rule_version, created_by, created_at
            ) VALUES (?, ?, ?, 'true_positive',
                      'Incident was resolved.', 'test-v1', 'admin-a', ?)
            """,
            (TENANT_ID, disposition_id, CASE_ID, NOW.isoformat()),
        )
        connection.execute(
            """
            UPDATE cases SET status = 'closed', version = version + 1,
                closed_at = ?, updated_at = ?
            WHERE tenant_id = ? AND case_id = ?
            """,
            (NOW.isoformat(), NOW.isoformat(), TENANT_ID, CASE_ID),
        )


def test_response_requires_open_case_active_device_rbac_and_independent_human(
    tmp_path: Path,
) -> None:
    database, _, _, audit, service = configured_service(tmp_path)
    proposer = principal("responder-a", "responder")
    reviewer = principal("responder-b", "responder")

    with pytest.raises(HumanAuthorizationError):
        service.propose(
            principal("analyst-a", "analyst"),
            CASE_ID,
            "isolate_endpoint",
            "mac-1",
            "Analysts cannot propose active response.",
            NOW,
        )
    with pytest.raises(ResponseNotFoundError):
        service.propose(
            proposer,
            CLOSED_CASE_ID,
            "isolate_endpoint",
            "mac-1",
            "Closed cases cannot receive an active response.",
            NOW,
        )
    action = service.propose(
        proposer,
        CASE_ID,
        "isolate_endpoint",
        "mac-1",
        "Confirmed credential theft requires temporary isolation.",
        NOW,
    )
    with pytest.raises(ResponseConflictError):
        service.propose(
            proposer,
            CASE_ID,
            "release_endpoint",
            "mac-1",
            "A device can have only one live action.",
            NOW,
        )
    with pytest.raises(HumanAuthorizationError):
        service.approve(proposer, action.action_id, NOW)
    with pytest.raises(HumanAuthorizationError):
        service.reject(proposer, action.action_id, "Self rejection is forbidden.", NOW)

    approved = service.approve(reviewer, action.action_id, NOW)

    assert approved.status == "approved"
    assert approved.approved_by == reviewer.user_id
    with pytest.raises(ResponseNotFoundError):
        service.get(principal("admin-other", "admin", OTHER_TENANT_ID), action.action_id)
    assert audit.verify(TENANT_ID).valid is True
    with database.connect() as connection:
        with pytest.raises(sqlite3.IntegrityError):
            connection.execute(
                "UPDATE response_actions SET proposed_by = 'forged' WHERE action_id = ?",
                (action.action_id,),
            )
        with pytest.raises(sqlite3.IntegrityError):
            connection.execute(
                "DELETE FROM response_actions WHERE action_id = ?",
                (action.action_id,),
            )


def test_device_poll_is_bound_replay_safe_bounded_and_result_is_idempotent(
    tmp_path: Path,
) -> None:
    database, _, _, audit, service = configured_service(tmp_path)
    action_id = propose_and_approve(service)

    with pytest.raises(DeviceActionBindingError):
        service.poll_device(
            signed_request(
                "GET",
                "/v1/agent/actions",
                nonce="response-wrong-query-0001",
            ),
            "mac-2",
            NOW,
        )
    wrong_device = service.poll_device(
        signed_request(
            "GET",
            "/v1/agent/actions",
            nonce="response-other-device-001",
            credential_id=OTHER_CREDENTIAL_ID,
            secret=OTHER_SECRET,
        ),
        "mac-2",
        NOW,
    )
    assert wrong_device == []

    for attempt in range(5):
        request = signed_request(
            "GET",
            "/v1/agent/actions",
            nonce=f"response-poll-{attempt:012d}",
        )
        dispatched = service.poll_device(request, "mac-1", NOW)
        assert [item.action_id for item in dispatched] == [action_id]
        if attempt == 0:
            with pytest.raises(CollectorReplayError):
                service.poll_device(request, "mac-1", NOW)
    assert (
        service.poll_device(
            signed_request(
                "GET",
                "/v1/agent/actions",
                nonce="response-poll-limit-001",
            ),
            "mac-1",
            NOW,
        )
        == []
    )

    body = json.dumps(
        {"evidence": ["pf anchor installed"], "status": "succeeded", "summary": "Isolated"},
        separators=(",", ":"),
        sort_keys=True,
    ).encode()
    result_path = f"/v1/agent/actions/{action_id}/result"
    with pytest.raises(DeviceActionBindingError):
        service.submit_device_result(
            signed_request(
                "POST",
                result_path,
                body,
                nonce="response-wrong-result-001",
                credential_id=OTHER_CREDENTIAL_ID,
                secret=OTHER_SECRET,
            ),
            action_id,
            "succeeded",
            "Isolated",
            ["pf anchor installed"],
            NOW,
        )
    result_request = signed_request(
        "POST",
        result_path,
        body,
        nonce="response-result-0000001",
    )
    result = service.submit_device_result(
        result_request,
        action_id,
        "succeeded",
        "Isolated",
        ["pf anchor installed"],
        NOW,
    )
    assert result.changed is True
    with pytest.raises(CollectorReplayError):
        service.submit_device_result(
            result_request,
            action_id,
            "succeeded",
            "Isolated",
            ["pf anchor installed"],
            NOW,
        )
    repeated = service.submit_device_result(
        signed_request(
            "POST",
            result_path,
            body,
            nonce="response-result-0000002",
        ),
        action_id,
        "succeeded",
        "Isolated",
        ["pf anchor installed"],
        NOW,
    )
    assert repeated.changed is False
    with pytest.raises(ResponseConflictError):
        service.submit_device_result(
            signed_request(
                "POST",
                result_path,
                b'{"different":true}',
                nonce="response-result-0000003",
            ),
            action_id,
            "failed",
            "Different result",
            [],
            NOW,
        )

    released = service.propose(
        principal("responder-a", "responder"),
        CASE_ID,
        "release_endpoint",
        "mac-1",
        "Release after the incident is resolved.",
        NOW,
    )
    assert released.status == "proposed"
    with database.connect() as connection:
        row = connection.execute(
            "SELECT dispatch_count, result_device_id FROM response_actions WHERE action_id = ?",
            (action_id,),
        ).fetchone()
    assert tuple(row) == (5, "mac-1")
    assert audit.verify(TENANT_ID).valid is True


def test_independent_rejection_is_terminal_and_releases_the_device_slot(tmp_path: Path) -> None:
    _, _, _, audit, service = configured_service(tmp_path)
    proposer = principal("responder-a", "responder")
    reviewer = principal("responder-b", "responder")
    action = service.propose(
        proposer,
        CASE_ID,
        "isolate_endpoint",
        "mac-1",
        "Containment needs independent review.",
        NOW,
    )

    rejected = service.reject(reviewer, action.action_id, "Evidence is not conclusive.", NOW)

    assert rejected.status == "rejected"
    assert rejected.rejected_by == reviewer.user_id
    assert rejected.rejection_reason == "Evidence is not conclusive."
    with pytest.raises(ResponseConflictError):
        service.approve(reviewer, action.action_id, NOW)
    replacement = service.propose(
        proposer,
        CASE_ID,
        "isolate_endpoint",
        "mac-1",
        "New evidence now meets the response threshold.",
        NOW,
    )
    assert replacement.status == "proposed"
    assert audit.verify(TENANT_ID).valid is True


def test_concurrent_approve_and_reject_have_one_winner_and_one_audit_entry(
    tmp_path: Path,
) -> None:
    _, _, _, audit, service = configured_service(tmp_path)
    action = service.propose(
        principal("responder-a", "responder"),
        CASE_ID,
        "isolate_endpoint",
        "mac-1",
        "Race-safe independent review.",
        NOW,
    )
    barrier = threading.Barrier(2)

    def review(decision: str) -> str:
        barrier.wait()
        try:
            if decision == "approve":
                return service.approve(
                    principal("responder-b", "responder"),
                    action.action_id,
                    NOW,
                ).status
            return service.reject(
                principal("admin-a", "admin"),
                action.action_id,
                "Concurrent reviewer rejected it.",
                NOW,
            ).status
        except ResponseConflictError:
            return "conflict"

    with ThreadPoolExecutor(max_workers=2) as executor:
        outcomes = list(executor.map(review, ("approve", "reject")))

    assert sorted(outcomes) in (["approved", "conflict"], ["conflict", "rejected"])
    verification = audit.verify(TENANT_ID)
    assert verification.valid is True
    assert verification.entries_checked == 2


def test_expiry_boundary_prevents_approval_dispatch_and_late_result(tmp_path: Path) -> None:
    _, _, _, audit, service = configured_service(tmp_path)
    proposer = principal("responder-a", "responder")
    reviewer = principal("responder-b", "responder")
    first = service.propose(
        proposer,
        CASE_ID,
        "isolate_endpoint",
        "mac-1",
        "Short approval window.",
        NOW,
        expires_in_seconds=60,
    )
    with pytest.raises(ResponseExpiredError):
        service.approve(reviewer, first.action_id, NOW + timedelta(seconds=60))
    assert service.get(proposer, first.action_id).status == "expired"

    second_id = propose_and_approve(service, now=NOW + timedelta(seconds=61), expires_in_seconds=60)
    dispatched = service.poll_device(
        signed_request(
            "GET",
            "/v1/agent/actions",
            nonce="response-expiry-poll-001",
            timestamp=NOW + timedelta(seconds=61),
        ),
        "mac-1",
        NOW + timedelta(seconds=61),
    )
    assert [item.action_id for item in dispatched] == [second_id]
    result_at_boundary = NOW + timedelta(seconds=121)
    result_path = f"/v1/agent/actions/{second_id}/result"
    result_body = b'{"evidence":[],"status":"failed","summary":"Late"}'
    with pytest.raises(ResponseExpiredError):
        service.submit_device_result(
            signed_request(
                "POST",
                result_path,
                result_body,
                nonce="response-expiry-result-01",
                timestamp=result_at_boundary,
            ),
            second_id,
            "failed",
            "Late",
            [],
            result_at_boundary,
        )
    assert service.get(proposer, second_id).status == "expired"
    assert audit.verify(TENANT_ID).valid is True


def test_case_closed_after_approval_expires_action_before_device_dispatch(
    tmp_path: Path,
) -> None:
    database, _, _, audit, service = configured_service(tmp_path)
    action_id = propose_and_approve(service)
    close_response_case(database, "response-disposition")

    dispatched = service.poll_device(
        signed_request(
            "GET",
            "/v1/agent/actions",
            nonce="response-closed-case-001",
        ),
        "mac-1",
        NOW,
    )

    assert dispatched == []
    assert service.get(principal("responder-a", "responder"), action_id).status == "expired"
    assert audit.verify(TENANT_ID).valid is True


def test_dispatched_action_can_report_result_after_case_closes(tmp_path: Path) -> None:
    database, _, _, audit, service = configured_service(tmp_path)
    action_id = propose_and_approve(service)
    service.poll_device(
        signed_request(
            "GET",
            "/v1/agent/actions",
            nonce="response-dispatched-close-01",
        ),
        "mac-1",
        NOW,
    )
    close_response_case(database, "response-dispatched-disposition")
    result_path = f"/v1/agent/actions/{action_id}/result"
    result_body = b'{"evidence":[],"status":"succeeded","summary":"Isolated"}'

    result = service.submit_device_result(
        signed_request(
            "POST",
            result_path,
            result_body,
            nonce="response-dispatched-result-01",
        ),
        action_id,
        "succeeded",
        "Isolated",
        [],
        NOW,
    )

    assert result.changed is True
    assert service.get(principal("responder-a", "responder"), action_id).status == "succeeded"
    assert audit.verify(TENANT_ID).valid is True


def bootstrap(identity: HumanIdentityService) -> SessionIssue:
    token = identity.issue_bootstrap_token(NOW)
    ceremony = identity.begin_bootstrap(
        token,
        "controlforge",
        "ControlForge",
        "admin@example.com",
        "Admin",
        NOW,
    )
    return identity.complete_bootstrap(
        token,
        ceremony.challenge_id,
        {"id": "admin-passkey", "challenge": ceremony.options["challenge"]},
        NOW,
    )


def test_human_invite_is_hashed_audited_tenant_bound_expiring_and_single_use(
    tmp_path: Path,
) -> None:
    database = StandaloneDatabase(StandaloneSettings(database_path=tmp_path / "invite.db"))
    database.initialize()
    audit = StandaloneAuditLog(database, AUDIT_KEY)
    identity = HumanIdentityService(
        database,
        FakePasskeyAdapter(),
        SESSION_PEPPER,
        RECOVERY_PEPPER,
        challenge_ttl_seconds=60,
        audit=audit,
    )
    admin = bootstrap(identity)
    invite = identity.issue_human_invite(
        admin.principal,
        "responder@example.com",
        "Second Responder",
        "responder",
        NOW,
        ttl_seconds=60,
    )
    with database.connect() as connection:
        stored = connection.execute(
            "SELECT token_hash, tenant_id FROM human_invites WHERE invite_id = ?",
            (invite.invite_id,),
        ).fetchone()
    assert invite.token not in str(stored["token_hash"])
    assert stored["tenant_id"] == admin.principal.tenant_id

    ceremony = identity.begin_human_invite(invite.token, NOW)
    completed = identity.complete_human_invite(
        invite.token,
        ceremony.challenge_id,
        {"id": "responder-passkey", "challenge": ceremony.options["challenge"]},
        NOW,
    )
    assert completed.principal.role == "responder"
    assert completed.principal.tenant_id == admin.principal.tenant_id
    assert len(completed.recovery_codes) == 10
    with pytest.raises(HumanInviteError):
        identity.complete_human_invite(
            invite.token,
            ceremony.challenge_id,
            {"id": "replay", "challenge": ceremony.options["challenge"]},
            NOW,
        )
    with pytest.raises(HumanInviteError):
        identity.begin_human_invite(invite.token, NOW)
    expiring = identity.issue_human_invite(
        admin.principal,
        "expired@example.com",
        "Expired Responder",
        "responder",
        NOW,
        ttl_seconds=60,
    )
    with pytest.raises(HumanInviteError):
        identity.begin_human_invite(expiring.token, NOW + timedelta(seconds=60))
    with database.connect() as connection:
        with pytest.raises(sqlite3.IntegrityError):
            connection.execute(
                "UPDATE human_invites SET role = 'admin' WHERE invite_id = ?",
                (invite.invite_id,),
            )
        with pytest.raises(sqlite3.IntegrityError):
            connection.execute(
                "DELETE FROM human_invite_challenges WHERE challenge_id = ?",
                (ceremony.challenge_id,),
            )
    verification = audit.verify(admin.principal.tenant_id)
    assert verification.valid is True
    assert verification.entries_checked == 3


def test_human_invite_issue_and_consumption_roll_back_if_audit_fails(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    database = StandaloneDatabase(StandaloneSettings(database_path=tmp_path / "invite-audit.db"))
    database.initialize()
    audit = StandaloneAuditLog(database, AUDIT_KEY)
    identity = HumanIdentityService(
        database,
        FakePasskeyAdapter(),
        SESSION_PEPPER,
        RECOVERY_PEPPER,
        audit=audit,
    )
    admin = bootstrap(identity)
    original_append = audit.append

    def fail_append(*_args: object, **_kwargs: object) -> None:
        raise RuntimeError("audit unavailable")

    monkeypatch.setattr(audit, "append", fail_append)
    with pytest.raises(RuntimeError, match="audit unavailable"):
        identity.issue_human_invite(
            admin.principal,
            "rolled-back@example.com",
            "Rolled Back",
            "responder",
            NOW,
        )
    with database.connect() as connection:
        assert connection.execute("SELECT COUNT(*) FROM human_invites").fetchone()[0] == 0

    monkeypatch.setattr(audit, "append", original_append)
    invite = identity.issue_human_invite(
        admin.principal,
        "completion@example.com",
        "Completion Rollback",
        "responder",
        NOW,
    )
    ceremony = identity.begin_human_invite(invite.token, NOW)
    monkeypatch.setattr(audit, "append", fail_append)
    with pytest.raises(RuntimeError, match="audit unavailable"):
        identity.complete_human_invite(
            invite.token,
            ceremony.challenge_id,
            {"id": "rolled-back-passkey", "challenge": ceremony.options["challenge"]},
            NOW,
        )
    with database.connect() as connection:
        invite_row = connection.execute(
            "SELECT consumed_at FROM human_invites WHERE invite_id = ?",
            (invite.invite_id,),
        ).fetchone()
        challenge_row = connection.execute(
            "SELECT consumed_at FROM human_invite_challenges WHERE challenge_id = ?",
            (ceremony.challenge_id,),
        ).fetchone()
        user = connection.execute(
            "SELECT 1 FROM users WHERE email = 'completion@example.com'"
        ).fetchone()
    assert invite_row["consumed_at"] is None
    assert challenge_row["consumed_at"] is None
    assert user is None


def test_api_requires_two_sessions_and_device_hmac_for_complete_response_flow(
    tmp_path: Path,
) -> None:
    database = StandaloneDatabase(StandaloneSettings(database_path=tmp_path / "response-api.db"))
    database.initialize()
    store = StandaloneStore(database)
    audit = StandaloneAuditLog(database, AUDIT_KEY)
    identity = HumanIdentityService(
        database,
        FakePasskeyAdapter(),
        SESSION_PEPPER,
        RECOVERY_PEPPER,
        audit=audit,
    )
    authenticator = DeviceHmacAuthenticator(database, SecretResolver())
    response_service = StandaloneResponseService(database, identity, audit, authenticator)
    app = create_standalone_app(
        StandaloneApiServices(
            identity=identity,
            ingestion=CollectorIngestionService(authenticator, store),
            enrollment=DeviceEnrollmentService(
                database,
                AesGcmDeviceCredentialCipher(b"response-enrollment-cipher-key01"),
            ),
            operations=StandaloneOperationsRepository(database),
            replay=DecisionReplayService(database, [], "response-api-v1"),
            cases=StandaloneCaseService(database, identity, audit),
            responses=response_service,
        ),
        ORIGIN,
        clock=lambda: NOW,
    )
    admin_client = TestClient(app, base_url=ORIGIN)
    invitee_client = TestClient(app, base_url=ORIGIN)
    bootstrap_token = identity.issue_bootstrap_token(NOW)
    options = admin_client.post(
        "/v1/bootstrap/options",
        headers={"origin": ORIGIN},
        json={
            "token": bootstrap_token,
            "tenant_slug": "controlforge",
            "tenant_display_name": "ControlForge",
            "email": "admin@example.com",
            "display_name": "Admin",
        },
    ).json()
    completed = admin_client.post(
        "/v1/bootstrap/complete",
        headers={"origin": ORIGIN},
        json={
            "token": bootstrap_token,
            "challenge_id": options["challenge_id"],
            "credential": {
                "id": "admin-api-passkey",
                "challenge": options["options"]["challenge"],
            },
        },
    )
    admin_csrf = str(completed.json()["csrf_token"])
    tenant_id = str(admin_client.get("/v1/me").json()["tenant_id"])
    store.register_device(tenant_id, "mac-1", "Primary Mac", "macos", NOW)
    store.register_device_credential(
        CREDENTIAL_ID,
        tenant_id,
        "mac-1",
        "primary",
        "encrypted-response-one",
        "response-iv-one",
        NOW,
        NOW + timedelta(days=30),
    )
    with database.connect() as connection:
        connection.execute(
            """
            INSERT INTO cases(
                tenant_id, case_id, title, priority, status, opened_at, updated_at
            ) VALUES (?, ?, 'API response', 'critical', 'open', ?, ?)
            """,
            (tenant_id, CASE_ID, NOW.isoformat(), NOW.isoformat()),
        )

    assert (
        admin_client.post(
            "/v1/team/invites",
            json={
                "email": "responder@example.com",
                "display_name": "Responder",
                "role": "responder",
            },
        ).status_code
        == 403
    )
    issued = admin_client.post(
        "/v1/team/invites",
        headers={"origin": ORIGIN, "x-csrf-token": admin_csrf},
        json={
            "email": "responder@example.com",
            "display_name": "Responder",
            "role": "responder",
            "expires_in_minutes": 15,
        },
    )
    assert issued.status_code == 201
    invite_token = str(issued.json()["token"])
    assert (
        invitee_client.post(
            "/v1/auth/invites/options",
            json={"token": invite_token},
        ).status_code
        == 403
    )
    invite_options = invitee_client.post(
        "/v1/auth/invites/options",
        headers={"origin": ORIGIN},
        json={"token": invite_token},
    ).json()
    invite_complete = invitee_client.post(
        "/v1/auth/invites/complete",
        headers={"origin": ORIGIN},
        json={
            "token": invite_token,
            "challenge_id": invite_options["challenge_id"],
            "credential": {
                "id": "responder-api-passkey",
                "challenge": invite_options["options"]["challenge"],
            },
        },
    )
    assert invite_complete.status_code == 200
    responder_csrf = str(invite_complete.json()["csrf_token"])
    assert (
        invitee_client.post(
            "/v1/auth/invites/complete",
            headers={"origin": ORIGIN},
            json={
                "token": invite_token,
                "challenge_id": invite_options["challenge_id"],
                "credential": {
                    "id": "replay",
                    "challenge": invite_options["options"]["challenge"],
                },
            },
        ).status_code
        == 401
    )
    for _ in range(9):
        assert (
            invitee_client.post(
                "/v1/auth/invites/options",
                headers={"origin": ORIGIN},
                json={"token": invite_token},
            ).status_code
            == 401
        )
    limited = invitee_client.post(
        "/v1/auth/invites/options",
        headers={"origin": ORIGIN},
        json={"token": invite_token},
    )
    assert limited.status_code == 429
    assert int(limited.headers["retry-after"]) > 0

    proposal = admin_client.post(
        f"/v1/cases/{CASE_ID}/response-actions",
        headers={"origin": ORIGIN, "x-csrf-token": admin_csrf},
        json={
            "action_type": "isolate_endpoint",
            "device_id": "mac-1",
            "rationale": "Confirmed API test incident.",
            "expires_in_seconds": 300,
        },
    )
    assert proposal.status_code == 201
    action_id = str(proposal.json()["action_id"])
    assert (
        admin_client.post(
            f"/v1/response-actions/{action_id}/approve",
            headers={"origin": ORIGIN, "x-csrf-token": admin_csrf},
        ).status_code
        == 403
    )
    approved = invitee_client.post(
        f"/v1/response-actions/{action_id}/approve",
        headers={"origin": ORIGIN, "x-csrf-token": responder_csrf},
    )
    assert approved.status_code == 200
    assert approved.json()["approved_by"] == invitee_client.get("/v1/me").json()["user_id"]

    poll = signed_request(
        "GET",
        "/v1/agent/actions",
        nonce="response-api-poll-00001",
    )
    polled = admin_client.get(
        "/v1/agent/actions?device_id=mac-1",
        headers={
            "x-controlforge-credential-id": poll.credential_id,
            "x-controlforge-timestamp": poll.timestamp,
            "x-controlforge-nonce": poll.nonce,
            "x-controlforge-signature": poll.signature,
        },
    )
    assert polled.status_code == 200
    assert polled.json()["actions"][0]["action_id"] == action_id

    result_body = json.dumps(
        {"evidence": ["network filter active"], "status": "succeeded", "summary": "Isolated"},
        separators=(",", ":"),
        sort_keys=True,
    ).encode()
    result = signed_request(
        "POST",
        f"/v1/agent/actions/{action_id}/result",
        result_body,
        nonce="response-api-result-0001",
    )
    accepted = admin_client.post(
        result.path,
        content=result_body,
        headers={
            "content-type": "application/json",
            "x-controlforge-credential-id": result.credential_id,
            "x-controlforge-timestamp": result.timestamp,
            "x-controlforge-nonce": result.nonce,
            "x-controlforge-signature": result.signature,
        },
    )
    assert accepted.status_code == 200
    assert accepted.json() == {"action_id": action_id, "status": "succeeded", "changed": True}
    human_view = invitee_client.get("/v1/response-actions").json()["actions"][0]
    assert human_view["result_summary"] == "Isolated"
    assert human_view["result_evidence"] == ["network filter active"]
    assert audit.verify(tenant_id).valid is True
