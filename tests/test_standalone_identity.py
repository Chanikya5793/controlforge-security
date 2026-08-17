from __future__ import annotations

import base64
import hashlib
import hmac
import json
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from controlforge.credential_rotation import (
    CredentialRotationEnvelope,
    decrypt_rotation_envelope,
)
from controlforge.standalone.api import StandaloneApiServices, create_standalone_app
from controlforge.standalone.audit import StandaloneAuditLog
from controlforge.standalone.auth import DeviceHmacAuthenticator, SignedCollectorRequest
from controlforge.standalone.cases import StandaloneCaseService
from controlforge.standalone.credential_rotation import DeviceCredentialRotationService
from controlforge.standalone.database import StandaloneDatabase
from controlforge.standalone.enrollment import (
    AesGcmDeviceCredentialCipher,
    DeviceEnrollmentService,
)
from controlforge.standalone.identity import (
    BootstrapError,
    Capability,
    ChallengeError,
    HumanAuthorizationError,
    HumanIdentityService,
    SessionError,
    SessionIssue,
    SessionPrincipal,
)
from controlforge.standalone.ingestion import CollectorIngestionService
from controlforge.standalone.operations import StandaloneOperationsRepository
from controlforge.standalone.passkeys import (
    AuthenticationVerification,
    RegistrationVerification,
    WebAuthnPasskeyAdapter,
)
from controlforge.standalone.replay import DecisionReplayService
from controlforge.standalone.settings import StandaloneSettings
from controlforge.standalone.store import StandaloneStore

NOW = datetime(2026, 8, 22, 20, 0, tzinfo=timezone.utc)
ORIGIN = "https://admin.controlforge.test"
SESSION_PEPPER = b"identity-session-pepper-material-0001"
RECOVERY_PEPPER = b"identity-recovery-pepper-material-001"
COLLECTOR_SECRET = b"identity-test-collector-secret-material-0001"


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
        return RegistrationVerification(credential_id, b"test-public-key", 0)

    def authentication_options(
        self,
        challenge: bytes,
        credential_ids: list[str],
    ) -> dict[str, object]:
        return {
            "challenge": self._challenge(challenge),
            "allow": credential_ids,
        }

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
        assert public_key == b"test-public-key"
        return AuthenticationVerification(
            self.response_credential_id(response),
            current_sign_count + 1,
        )


class CollectorSecretResolver:
    def resolve(
        self,
        credential_id: str,
        secret_ciphertext: str,
        secret_iv: str,
    ) -> bytes:
        assert credential_id == "identity-collector"
        assert secret_ciphertext.startswith("encrypted-")
        assert secret_iv.startswith("identity-")
        return COLLECTOR_SECRET


def identity_fixture(
    tmp_path: Path,
) -> tuple[StandaloneDatabase, StandaloneStore, HumanIdentityService]:
    database = StandaloneDatabase(StandaloneSettings(database_path=tmp_path / "identity.db"))
    database.initialize()
    identity = HumanIdentityService(
        database,
        FakePasskeyAdapter(),
        SESSION_PEPPER,
        RECOVERY_PEPPER,
        session_ttl_seconds=300,
        challenge_ttl_seconds=60,
    )
    return database, StandaloneStore(database), identity


def complete_bootstrap(identity: HumanIdentityService) -> tuple[str, SessionIssue]:
    token = identity.issue_bootstrap_token(NOW)
    ceremony = identity.begin_bootstrap(
        token,
        "controlforge",
        "ControlForge",
        "admin@example.com",
        "Initial Admin",
        NOW,
    )
    issue = identity.complete_bootstrap(
        token,
        ceremony.challenge_id,
        {"id": "credential-admin", "challenge": ceremony.options["challenge"]},
        NOW,
    )
    return token, issue


def test_webauthn_adapter_generates_required_uv_options() -> None:
    adapter = WebAuthnPasskeyAdapter(
        "admin.controlforge.test",
        "ControlForge",
        ORIGIN,
    )
    challenge = b"c" * 32

    registration = adapter.registration_options(
        "user-1",
        "admin@example.com",
        "Admin",
        challenge,
        [],
    )
    authentication = adapter.authentication_options(challenge, [])

    assert registration["rp"] == {
        "id": "admin.controlforge.test",
        "name": "ControlForge",
    }
    assert authentication["rpId"] == "admin.controlforge.test"
    assert authentication["userVerification"] == "required"


def test_bootstrap_token_and_challenge_are_single_use(tmp_path: Path) -> None:
    _, _, identity = identity_fixture(tmp_path)
    token = identity.issue_bootstrap_token(NOW)
    ceremony = identity.begin_bootstrap(
        token,
        "controlforge",
        "ControlForge",
        "admin@example.com",
        "Admin",
        NOW,
    )
    response = {"id": "credential-admin", "challenge": ceremony.options["challenge"]}

    issue = identity.complete_bootstrap(token, ceremony.challenge_id, response, NOW)

    assert issue.principal.role == "admin"
    assert len(issue.recovery_codes) == 10
    with pytest.raises(ChallengeError):
        identity.complete_bootstrap(token, ceremony.challenge_id, response, NOW)
    with pytest.raises(BootstrapError):
        identity.begin_bootstrap(
            token,
            "controlforge",
            "ControlForge",
            "admin@example.com",
            "Admin",
            NOW,
        )


def test_expired_registration_challenge_fails_closed(tmp_path: Path) -> None:
    _, _, identity = identity_fixture(tmp_path)
    token = identity.issue_bootstrap_token(NOW)
    ceremony = identity.begin_bootstrap(
        token,
        "controlforge",
        "ControlForge",
        "admin@example.com",
        "Admin",
        NOW,
    )

    with pytest.raises(ChallengeError):
        identity.complete_bootstrap(
            token,
            ceremony.challenge_id,
            {"id": "credential-admin", "challenge": ceremony.options["challenge"]},
            NOW + timedelta(seconds=60),
        )


def test_session_is_hashed_rotated_expiring_and_revocable(tmp_path: Path) -> None:
    database, _, identity = identity_fixture(tmp_path)
    _, bootstrap_issue = complete_bootstrap(identity)
    initial = bootstrap_issue
    principal = identity.authenticate_session(initial.token, NOW)

    with database.connect() as connection:
        row = connection.execute(
            "SELECT secret_hash FROM sessions WHERE session_id = ?",
            (principal.session_id,),
        ).fetchone()
    assert initial.token not in str(row["secret_hash"])
    fixed = f"{principal.session_id}.attacker-selected-secret"
    with pytest.raises(SessionError):
        identity.authenticate_session(fixed, NOW)
    with pytest.raises(SessionError):
        identity.authenticate_session(initial.token, NOW + timedelta(seconds=300))

    login = identity.begin_authentication("controlforge", "admin@example.com", NOW)
    replacement = identity.complete_authentication(
        login.challenge_id,
        {"id": "credential-admin", "challenge": login.options["challenge"]},
        NOW,
    )
    assert replacement.token != initial.token
    replacement_principal = identity.authenticate_session(replacement.token, NOW)
    identity.revoke_session(replacement_principal, NOW)
    with pytest.raises(SessionError):
        identity.authenticate_session(replacement.token, NOW)


def test_authentication_challenge_and_recovery_code_cannot_replay(tmp_path: Path) -> None:
    _, _, identity = identity_fixture(tmp_path)
    _, bootstrap_issue = complete_bootstrap(identity)
    login = identity.begin_authentication("controlforge", "admin@example.com", NOW)
    response = {"id": "credential-admin", "challenge": login.options["challenge"]}

    identity.complete_authentication(login.challenge_id, response, NOW)

    with pytest.raises(ChallengeError):
        identity.complete_authentication(login.challenge_id, response, NOW)
    recovery_code = bootstrap_issue.recovery_codes[0]
    identity.recover_session(
        "controlforge",
        "admin@example.com",
        recovery_code,
        NOW,
    )
    with pytest.raises(SessionError):
        identity.recover_session(
            "controlforge",
            "admin@example.com",
            recovery_code,
            NOW,
        )


def test_capability_matrix_denies_viewer_and_cross_tenant_access(tmp_path: Path) -> None:
    _, _, identity = identity_fixture(tmp_path)
    _, issue = complete_bootstrap(identity)
    admin = issue.principal
    viewer = SessionPrincipal(
        tenant_id=admin.tenant_id,
        user_id="viewer-1",
        email="viewer@example.com",
        display_name="Viewer",
        role="viewer",
        session_id="viewer-session",
        expires_at=NOW + timedelta(minutes=5),
        csrf_hash="hash",
    )

    identity.require_capability(admin, admin.tenant_id, Capability.MANAGE)
    identity.require_capability(viewer, viewer.tenant_id, Capability.VIEW)
    with pytest.raises(HumanAuthorizationError):
        identity.require_capability(viewer, viewer.tenant_id, Capability.TRIAGE)
    with pytest.raises(HumanAuthorizationError):
        identity.require_capability(admin, "another-tenant", Capability.VIEW)


def test_passkey_registration_challenge_is_principal_bound_and_single_use(
    tmp_path: Path,
) -> None:
    _, _, identity = identity_fixture(tmp_path)
    _, issue = complete_bootstrap(identity)
    ceremony = identity.begin_passkey_registration(issue.principal, NOW)
    response = {"id": "credential-second", "challenge": ceremony.options["challenge"]}

    credential_id = identity.complete_passkey_registration(
        issue.principal,
        ceremony.challenge_id,
        response,
        "Backup passkey",
        NOW,
    )

    assert credential_id == "credential-second"
    with pytest.raises(ChallengeError):
        identity.complete_passkey_registration(
            issue.principal,
            ceremony.challenge_id,
            response,
            "Backup passkey",
            NOW,
        )


def api_fixture(
    tmp_path: Path,
) -> tuple[TestClient, HumanIdentityService, StandaloneStore]:
    database, store, identity = identity_fixture(tmp_path)
    authenticator = DeviceHmacAuthenticator(database, CollectorSecretResolver())
    ingestion = CollectorIngestionService(authenticator, store)
    credential_cipher = AesGcmDeviceCredentialCipher(b"identity-enrollment-cipher-key01")
    enrollment = DeviceEnrollmentService(database, credential_cipher)
    app = create_standalone_app(
        StandaloneApiServices(
            identity=identity,
            ingestion=ingestion,
            enrollment=enrollment,
            operations=StandaloneOperationsRepository(database),
            replay=DecisionReplayService(database, [], "identity-test-v1"),
            cases=StandaloneCaseService(
                database,
                identity,
                StandaloneAuditLog(database, b"identity-test-audit-key-material001"),
            ),
            credential_rotation=DeviceCredentialRotationService(
                database,
                credential_cipher,
                DeviceHmacAuthenticator(database, credential_cipher),
            ),
        ),
        ORIGIN,
        clock=lambda: NOW,
    )
    return TestClient(app, base_url=ORIGIN), identity, store


def api_bootstrap(client: TestClient, identity: HumanIdentityService) -> tuple[str, str]:
    token = identity.issue_bootstrap_token(NOW)
    options = client.post(
        "/v1/bootstrap/options",
        headers={"origin": ORIGIN},
        json={
            "token": token,
            "tenant_slug": "controlforge",
            "tenant_display_name": "ControlForge",
            "email": "admin@example.com",
            "display_name": "Admin",
        },
    )
    assert options.status_code == 200
    ceremony = options.json()
    completed = client.post(
        "/v1/bootstrap/complete",
        headers={"origin": ORIGIN},
        json={
            "token": token,
            "challenge_id": ceremony["challenge_id"],
            "credential": {
                "id": "credential-admin",
                "challenge": ceremony["options"]["challenge"],
            },
        },
    )
    assert completed.status_code == 200
    return completed.json()["csrf_token"], completed.headers["set-cookie"]


def test_public_recovery_endpoint_is_rate_limited(tmp_path: Path) -> None:
    client, _, _ = api_fixture(tmp_path)
    payload = {
        "tenant_slug": "controlforge",
        "email": "unknown@example.com",
        "recovery_code": "invalid-recovery-code-value",
    }
    for _ in range(5):
        assert (
            client.post(
                "/v1/auth/recovery",
                headers={"origin": ORIGIN},
                json=payload,
            ).status_code
            == 401
        )

    limited = client.post(
        "/v1/auth/recovery",
        headers={"origin": ORIGIN},
        json=payload,
    )
    assert limited.status_code == 429
    assert int(limited.headers["retry-after"]) > 0
    assert limited.json()["error"].startswith("Too many attempts. Try again in ")


def test_bootstrap_api_explains_invalid_or_expired_code_without_echo(tmp_path: Path) -> None:
    client, _, _ = api_fixture(tmp_path)
    rejected = client.post(
        "/v1/bootstrap/options",
        headers={"origin": ORIGIN},
        json={
            "token": "invalid-one-time-code-that-is-long-enough-value",
            "tenant_slug": "controlforge",
            "tenant_display_name": "ControlForge",
            "email": "admin@example.com",
            "display_name": "Admin",
        },
    )
    assert rejected.status_code == 401
    message = rejected.json()["error"]
    assert message == (
        "The one-time setup code is invalid or expired. Generate a fresh code and try again."
    )
    assert "invalid-one-time-code" not in message


def test_api_cookie_origin_csrf_and_logout_enforcement(tmp_path: Path) -> None:
    client, identity, _ = api_fixture(tmp_path)
    denied = client.post(
        "/v1/bootstrap/options",
        json={
            "token": identity.issue_bootstrap_token(NOW),
            "tenant_slug": "controlforge",
            "tenant_display_name": "ControlForge",
            "email": "admin@example.com",
            "display_name": "Admin",
        },
    )
    assert denied.status_code == 403
    csrf_token, cookie = api_bootstrap(client, identity)

    assert "Secure" in cookie
    assert "HttpOnly" in cookie
    assert "SameSite=strict" in cookie
    assert client.get("/v1/me").status_code == 200
    assert client.post("/v1/auth/logout").status_code == 403
    assert (
        client.post(
            "/v1/auth/logout",
            headers={"origin": ORIGIN, "x-csrf-token": "wrong"},
        ).status_code
        == 403
    )
    signed_out = client.post(
        "/v1/auth/logout",
        headers={"origin": ORIGIN, "x-csrf-token": csrf_token},
    )
    assert signed_out.status_code == 200
    assert client.get("/v1/me").status_code == 401


def test_standalone_admin_page_is_csp_bound_and_uses_real_same_origin_apis(
    tmp_path: Path,
) -> None:
    client, _, _ = api_fixture(tmp_path)

    response = client.get("/admin")

    assert response.status_code == 200
    csp = response.headers["content-security-policy"]
    assert "default-src 'none'" in csp
    assert "script-src 'nonce-" in csp
    assert "connect-src 'self'" in csp
    assert "__CSP_NONCE__" not in response.text
    assert "ControlForge Standalone Admin" in response.text
    assert "navigator.credentials.create" in response.text
    assert "/v1/devices/enrollment-grants" in response.text
    assert "/v1/cases/" in response.text
    assert "/v1/audit/verify" in response.text
    assert "/v1/team/invites" in response.text
    assert "/v1/auth/invites/options" in response.text
    assert "/response-actions" in response.text
    assert "a different human must review it" in response.text
    assert "action.proposed_by===me.user_id" in response.text
    assert "case-workbench" in response.text
    assert "textContent" in response.text
    assert "innerHTML" not in response.text
    assert "localStorage" not in response.text


def test_api_exposes_only_device_authenticated_ingestion(tmp_path: Path) -> None:
    client, identity, store = api_fixture(tmp_path)
    _, issue = complete_bootstrap(identity)
    store.register_device(issue.principal.tenant_id, "mac-1", "Mac", "macos", NOW)
    store.register_device_credential(
        "identity-collector",
        issue.principal.tenant_id,
        "mac-1",
        "primary",
        "encrypted-identity-secret",
        "identity-iv",
        NOW,
        NOW + timedelta(days=30),
    )
    body = json.dumps(
        {
            "events": [
                {
                    "event_id": "api-event-1",
                    "event_type": "endpoint_control_status",
                    "timestamp": NOW.isoformat(),
                    "actor": "device:mac-1",
                    "device_id": "mac-1",
                    "attributes": {"status": "healthy"},
                }
            ]
        },
        separators=(",", ":"),
        sort_keys=True,
    ).encode()
    unsigned = SignedCollectorRequest(
        method="POST",
        path="/v1/ingest/events",
        body=body,
        credential_id="identity-collector",
        timestamp=NOW.isoformat().replace("+00:00", "Z"),
        nonce="identity-nonce-00000001",
        signature="0" * 64,
    )
    signature = hmac.new(
        COLLECTOR_SECRET,
        DeviceHmacAuthenticator.canonical_request(unsigned),
        hashlib.sha256,
    ).hexdigest()

    response = client.post(
        "/v1/ingest/events",
        content=body,
        headers={
            "x-controlforge-credential-id": unsigned.credential_id,
            "x-controlforge-timestamp": unsigned.timestamp,
            "x-controlforge-nonce": unsigned.nonce,
            "x-controlforge-signature": signature,
            "content-type": "application/json",
        },
    )

    assert response.status_code == 202
    assert response.json() == {
        "accepted": 1,
        "duplicates": 0,
        "event_ids": ["api-event-1"],
    }
    assert client.post("/v1/ingest/events", content=body).status_code == 401


def test_admin_api_enrolls_rotates_lists_and_revokes_device(tmp_path: Path) -> None:
    client, identity, _ = api_fixture(tmp_path)
    csrf_token, _ = api_bootstrap(client, identity)
    mutation_headers = {"origin": ORIGIN, "x-csrf-token": csrf_token}

    refreshed_csrf = client.get("/v1/auth/csrf")
    assert refreshed_csrf.status_code == 200
    csrf_token = refreshed_csrf.json()["csrf_token"]
    mutation_headers["x-csrf-token"] = csrf_token
    summary = client.get("/v1/dashboard/summary")
    assert summary.status_code == 200
    assert summary.json() == {
        "events_24h": 0,
        "alerts_24h": 0,
        "critical_open": 0,
        "open_cases": 0,
        "active_devices": 0,
        "pending_jobs": 0,
        "dead_jobs": 0,
    }

    assert client.post("/v1/devices/enrollment-grants", json={}).status_code == 403
    grant_response = client.post(
        "/v1/devices/enrollment-grants",
        headers=mutation_headers,
        json={"expected_device_id": "mac-admin-api", "expires_in_minutes": 10},
    )
    assert grant_response.status_code == 201
    grant = grant_response.json()

    enrolled_response = client.post(
        "/v1/devices/enroll",
        json={
            "token": grant["token"],
            "device_id": "mac-admin-api",
            "display_name": "Admin API Mac",
            "platform": "macos",
        },
    )
    assert enrolled_response.status_code == 201
    enrolled = enrolled_response.json()
    assert len(enrolled["credential_secret"]) >= 32
    assert (
        client.post(
            "/v1/devices/enroll",
            json={
                "token": grant["token"],
                "device_id": "mac-admin-api-2",
                "display_name": "Replay Mac",
                "platform": "macos",
            },
        ).status_code
        == 409
    )

    inventory = client.get("/v1/devices")
    assert inventory.status_code == 200
    assert inventory.json()["devices"] == [
        {
            "device_id": "mac-admin-api",
            "display_name": "Admin API Mac",
            "platform": "macos",
            "status": "active",
            "enrolled_at": NOW.isoformat(),
            "last_seen_at": None,
            "active_credentials": 1,
        }
    ]

    rotated_response = client.post(
        "/v1/devices/mac-admin-api/credentials/rotate",
        headers=mutation_headers,
        json={"lifetime_days": 30},
    )
    assert rotated_response.status_code == 201
    rotated = rotated_response.json()
    assert rotated["predecessor_credential_id"] == enrolled["credential_id"]
    assert rotated["replacement_credential_id"] != enrolled["credential_id"]
    assert rotated["status"] == "pending"
    assert "credential_secret" not in rotated
    retire_before_ack = client.post(
        f"/v1/devices/mac-admin-api/credentials/{enrolled['credential_id']}/revoke",
        headers=mutation_headers,
    )
    assert retire_before_ack.status_code == 409

    def collector_headers(
        credential_id: str,
        secret: str,
        method: str,
        path: str,
        body: bytes,
        nonce: str,
    ) -> dict[str, str]:
        unsigned = SignedCollectorRequest(
            method=method,
            path=path,
            body=body,
            credential_id=credential_id,
            timestamp=NOW.isoformat().replace("+00:00", "Z"),
            nonce=nonce,
            signature="0" * 64,
        )
        return {
            "x-controlforge-credential-id": credential_id,
            "x-controlforge-timestamp": unsigned.timestamp,
            "x-controlforge-nonce": nonce,
            "x-controlforge-signature": hmac.new(
                secret.encode(),
                DeviceHmacAuthenticator.canonical_request(unsigned),
                hashlib.sha256,
            ).hexdigest(),
        }

    poll = client.get(
        "/v1/agent/credential-rotation?device_id=mac-admin-api",
        headers=collector_headers(
            enrolled["credential_id"],
            enrolled["credential_secret"],
            "GET",
            "/v1/agent/credential-rotation",
            b"",
            "identity-rotation-poll-01",
        ),
    )
    assert poll.status_code == 200
    envelope = CredentialRotationEnvelope.model_validate(poll.json()["rotation"])
    material = decrypt_rotation_envelope(
        envelope,
        enrolled["credential_secret"].encode(),
        expected_device_id="mac-admin-api",
        expected_credential_id=enrolled["credential_id"],
        now=NOW,
    )
    ack_body = b"{}"
    acknowledged = client.post(
        "/v1/agent/credential-rotation/ack",
        content=ack_body,
        headers={
            **collector_headers(
                material.replacement_credential_id,
                material.replacement_secret,
                "POST",
                "/v1/agent/credential-rotation/ack",
                ack_body,
                "identity-rotation-ack-001",
            ),
            "content-type": "application/json",
        },
    )
    assert acknowledged.status_code == 200
    assert acknowledged.json()["status"] == "acknowledged"

    revoked = client.post(
        "/v1/devices/mac-admin-api/revoke",
        headers=mutation_headers,
    )
    assert revoked.status_code == 200
    assert revoked.json() == {"revoked": True}
