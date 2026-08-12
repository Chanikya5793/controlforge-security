from __future__ import annotations

import hashlib
import hmac
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from controlforge.collector_agent import CollectorDefinition, SignedControlForgeClient
from controlforge.credential_rotation import decrypt_rotation_envelope
from controlforge.standalone.auth import (
    CollectorAuthenticationError,
    DeviceHmacAuthenticator,
    SignedCollectorRequest,
)
from controlforge.standalone.credential_rotation import DeviceCredentialRotationService
from controlforge.standalone.database import StandaloneDatabase
from controlforge.standalone.enrollment import (
    AesGcmDeviceCredentialCipher,
    DeviceEnrollmentService,
    EnrollmentError,
)
from controlforge.standalone.settings import StandaloneSettings
from controlforge.standalone.store import StandaloneStore

NOW = datetime(2026, 8, 22, 19, 0, tzinfo=timezone.utc)
TENANT_ID = "00000000-0000-4000-8000-000000000020"
KEY = b"standalone-enrollment-test-key-1"


def enrollment_fixture(
    tmp_path: Path,
) -> tuple[StandaloneDatabase, DeviceEnrollmentService, AesGcmDeviceCredentialCipher]:
    database = StandaloneDatabase(StandaloneSettings(database_path=tmp_path / "enrollment.db"))
    database.initialize()
    StandaloneStore(database).create_tenant(
        TENANT_ID,
        "enrollment-test",
        "Enrollment test",
        NOW,
    )
    cipher = AesGcmDeviceCredentialCipher(KEY)
    return database, DeviceEnrollmentService(database, cipher), cipher


def signed_request(credential_id: str, secret: str, nonce: str) -> SignedCollectorRequest:
    body = b'{"events":[]}'
    unsigned = SignedCollectorRequest(
        method="POST",
        path="/v1/ingest/events",
        body=body,
        credential_id=credential_id,
        timestamp=NOW.isoformat().replace("+00:00", "Z"),
        nonce=nonce,
        signature="0" * 64,
    )
    signature = hmac.new(
        secret.encode(),
        DeviceHmacAuthenticator.canonical_request(unsigned),
        hashlib.sha256,
    ).hexdigest()
    return SignedCollectorRequest(
        method=unsigned.method,
        path=unsigned.path,
        body=body,
        credential_id=credential_id,
        timestamp=unsigned.timestamp,
        nonce=nonce,
        signature=signature,
    )


def signed_rotation_request(
    credential_id: str,
    secret: str,
    nonce: str,
    method: str,
    path: str,
) -> SignedCollectorRequest:
    body = b"" if method == "GET" else b"{}"
    unsigned = SignedCollectorRequest(
        method=method,
        path=path,
        body=body,
        credential_id=credential_id,
        timestamp=NOW.isoformat().replace("+00:00", "Z"),
        nonce=nonce,
        signature="0" * 64,
    )
    return SignedCollectorRequest(
        method=method,
        path=path,
        body=body,
        credential_id=credential_id,
        timestamp=unsigned.timestamp,
        nonce=nonce,
        signature=hmac.new(
            secret.encode(),
            DeviceHmacAuthenticator.canonical_request(unsigned),
            hashlib.sha256,
        ).hexdigest(),
    )


def test_one_time_grant_resumes_only_until_first_authenticated_use(tmp_path: Path) -> None:
    database, service, cipher = enrollment_fixture(tmp_path)
    grant = service.issue_grant(
        TENANT_ID,
        "admin-1",
        NOW,
        expected_device_id="mac-primary",
    )

    enrolled = service.claim_grant(
        grant.token,
        "mac-primary",
        "Primary Mac",
        "macos",
        NOW + timedelta(seconds=1),
    )

    assert enrolled.tenant_id == TENANT_ID
    assert enrolled.device_id == "mac-primary"
    assert len(enrolled.secret) >= 32
    # A server-side enrollment result must satisfy the installed collector's
    # credential contract, not merely the standalone authenticator.
    SignedControlForgeClient(
        CollectorDefinition(api_host="standalone.example.com", device_id="mac-primary"),
        enrolled.credential_id,
        enrolled.secret,
    )
    with database.connect() as connection:
        token_row = connection.execute(
            """
            SELECT token_hash, used_at, claimed_device_id
            FROM enrollment_tokens WHERE token_id = ?
            """,
            (grant.token_id,),
        ).fetchone()
        credential_row = connection.execute(
            """
            SELECT secret_ciphertext, secret_iv
            FROM device_credentials WHERE credential_id = ?
            """,
            (enrolled.credential_id,),
        ).fetchone()
        device = connection.execute(
            "SELECT status, last_seen_at FROM devices WHERE tenant_id = ? AND device_id = ?",
            (TENANT_ID, "mac-primary"),
        ).fetchone()
    assert token_row["token_hash"] == hashlib.sha256(grant.token.encode()).hexdigest()
    assert token_row["token_hash"] != grant.token
    assert token_row["used_at"] is not None
    assert token_row["claimed_device_id"] == "mac-primary"
    assert credential_row["secret_ciphertext"] != enrolled.secret
    assert (
        cipher.resolve(
            enrolled.credential_id,
            credential_row["secret_ciphertext"],
            credential_row["secret_iv"],
        )
        == enrolled.secret.encode()
    )
    assert dict(device) == {"status": "active", "last_seen_at": None}

    resumed = service.claim_grant(
        grant.token,
        "mac-primary",
        "Primary Mac",
        "macos",
        NOW + timedelta(seconds=2),
    )
    assert resumed == enrolled

    with pytest.raises(EnrollmentError):
        service.claim_grant(
            grant.token,
            "mac-second",
            "Second Mac",
            "macos",
            NOW + timedelta(seconds=3),
        )
    DeviceHmacAuthenticator(database, cipher).authenticate(
        signed_request(
            enrolled.credential_id,
            enrolled.secret,
            "nonce-completed-enrollment-1",
        ),
        NOW + timedelta(seconds=4),
    )
    with pytest.raises(EnrollmentError):
        service.claim_grant(
            grant.token,
            "mac-primary",
            "Primary Mac",
            "macos",
            NOW + timedelta(seconds=5),
        )
    with database.connect() as connection:
        assert connection.execute("SELECT COUNT(*) FROM devices").fetchone()[0] == 1
        assert connection.execute("SELECT COUNT(*) FROM device_credentials").fetchone()[0] == 1


def test_bound_expired_and_revoked_grants_fail_closed(tmp_path: Path) -> None:
    database, service, _ = enrollment_fixture(tmp_path)
    bound = service.issue_grant(
        TENANT_ID,
        "admin-1",
        NOW,
        expected_device_id="expected-mac",
    )
    with pytest.raises(EnrollmentError):
        service.claim_grant(
            bound.token,
            "substituted-mac",
            "Substituted Mac",
            "macos",
            NOW + timedelta(seconds=1),
        )
    assert service.revoke_grant(TENANT_ID, bound.token_id, NOW + timedelta(seconds=2)) is True
    assert service.revoke_grant(TENANT_ID, bound.token_id, NOW + timedelta(seconds=3)) is False
    with pytest.raises(EnrollmentError):
        service.claim_grant(
            bound.token,
            "expected-mac",
            "Expected Mac",
            "macos",
            NOW + timedelta(seconds=4),
        )

    expired = service.issue_grant(TENANT_ID, "admin-1", NOW, expires_in=timedelta(minutes=5))
    with pytest.raises(EnrollmentError):
        service.claim_grant(
            expired.token,
            "late-mac",
            "Late Mac",
            "macos",
            NOW + timedelta(minutes=5),
        )
    with database.connect() as connection:
        assert connection.execute("SELECT COUNT(*) FROM devices").fetchone()[0] == 0


def test_concurrent_claim_allows_exactly_one_device(tmp_path: Path) -> None:
    database, service, _ = enrollment_fixture(tmp_path)
    grant = service.issue_grant(TENANT_ID, "admin-1", NOW)

    def claim(index: int) -> bool:
        try:
            service.claim_grant(
                grant.token,
                f"mac-{index}",
                f"Mac {index}",
                "macos",
                NOW + timedelta(seconds=1),
            )
        except EnrollmentError:
            return False
        return True

    with ThreadPoolExecutor(max_workers=2) as executor:
        results = list(executor.map(claim, range(2)))

    assert sorted(results) == [False, True]
    with database.connect() as connection:
        assert connection.execute("SELECT COUNT(*) FROM devices").fetchone()[0] == 1
        assert connection.execute("SELECT COUNT(*) FROM device_credentials").fetchone()[0] == 1


def test_device_revocation_invalidates_all_credentials(tmp_path: Path) -> None:
    database, service, cipher = enrollment_fixture(tmp_path)
    grant = service.issue_grant(TENANT_ID, "admin-1", NOW)
    enrolled = service.claim_grant(
        grant.token,
        "mac-revoked",
        "Revoked Mac",
        "macos",
        NOW + timedelta(seconds=1),
    )
    authenticator = DeviceHmacAuthenticator(database, cipher)
    request = signed_request(
        enrolled.credential_id,
        enrolled.secret,
        "nonce-before-revoke-0001",
    )
    assert (
        authenticator.authenticate(request, NOW + timedelta(seconds=2)).device_id == "mac-revoked"
    )

    assert (
        service.revoke_device(
            TENANT_ID,
            "mac-revoked",
            NOW + timedelta(seconds=3),
        )
        is True
    )
    assert (
        service.revoke_device(
            TENANT_ID,
            "mac-revoked",
            NOW + timedelta(seconds=4),
        )
        is False
    )
    with pytest.raises(CollectorAuthenticationError):
        authenticator.authenticate(
            signed_request(
                enrolled.credential_id,
                enrolled.secret,
                "nonce-after-revoke-00002",
            ),
            NOW + timedelta(seconds=5),
        )
    with database.connect() as connection:
        credential = connection.execute(
            "SELECT revoked_at FROM device_credentials WHERE credential_id = ?",
            (enrolled.credential_id,),
        ).fetchone()
    assert credential["revoked_at"] is not None


def test_credential_rotation_overlaps_then_retires_old_secret(tmp_path: Path) -> None:
    database, service, cipher = enrollment_fixture(tmp_path)
    grant = service.issue_grant(TENANT_ID, "admin-1", NOW)
    original = service.claim_grant(
        grant.token,
        "mac-rotate",
        "Rotation Mac",
        "macos",
        NOW + timedelta(seconds=1),
    )
    authenticator = DeviceHmacAuthenticator(database, cipher)
    rotation_service = DeviceCredentialRotationService(database, cipher, authenticator)
    rotation = rotation_service.initiate(
        TENANT_ID,
        "mac-rotate",
        "admin-1",
        NOW + timedelta(seconds=2),
    )

    assert (
        authenticator.authenticate(
            signed_request(original.credential_id, original.secret, "nonce-original-credential-1"),
            NOW + timedelta(seconds=3),
        ).device_id
        == "mac-rotate"
    )
    with pytest.raises(EnrollmentError):
        rotation_service.initiate(
            TENANT_ID,
            "mac-rotate",
            "admin-1",
            NOW + timedelta(seconds=4),
        )

    envelope = rotation_service.poll(
        signed_rotation_request(
            original.credential_id,
            original.secret,
            "nonce-rotation-poll-0001",
            "GET",
            "/v1/agent/credential-rotation",
        ),
        "mac-rotate",
        NOW + timedelta(seconds=3),
    )
    assert envelope is not None
    material = decrypt_rotation_envelope(
        envelope,
        original.secret.encode(),
        expected_device_id="mac-rotate",
        expected_credential_id=original.credential_id,
        now=NOW + timedelta(seconds=3),
    )
    assert material.rotation_id == rotation.rotation_id
    acknowledged = rotation_service.acknowledge(
        signed_rotation_request(
            material.replacement_credential_id,
            material.replacement_secret,
            "nonce-rotation-ack-00001",
            "POST",
            "/v1/agent/credential-rotation/ack",
        ),
        NOW + timedelta(seconds=4),
    )
    assert acknowledged is not None
    assert acknowledged.status == "acknowledged"

    with pytest.raises(CollectorAuthenticationError):
        authenticator.authenticate(
            signed_request(
                original.credential_id,
                original.secret,
                "nonce-retired-credential-01",
            ),
            NOW + timedelta(seconds=5),
        )
    assert (
        authenticator.authenticate(
            signed_request(
                material.replacement_credential_id,
                material.replacement_secret,
                "nonce-replacement-cred-1",
            ),
            NOW + timedelta(seconds=5),
        ).device_id
        == "mac-rotate"
    )
    with pytest.raises(EnrollmentError):
        service.revoke_credential(
            TENANT_ID,
            "mac-rotate",
            material.replacement_credential_id,
            NOW + timedelta(seconds=7),
        )


def test_cipher_and_input_validation_reject_tampering(tmp_path: Path) -> None:
    _, service, cipher = enrollment_fixture(tmp_path)
    encrypted = cipher.encrypt("credential-1", b"a" * 32)
    with pytest.raises(EnrollmentError):
        cipher.resolve("credential-2", encrypted.ciphertext, encrypted.iv)
    with pytest.raises(ValueError):
        AesGcmDeviceCredentialCipher(b"short")
    with pytest.raises(ValueError):
        service.issue_grant(TENANT_ID, "admin-1", NOW, expires_in=timedelta(minutes=1))
    grant = service.issue_grant(TENANT_ID, "admin-1", NOW)
    with pytest.raises(ValueError):
        service.claim_grant(grant.token, "mac-1", "Mac", "windows", NOW)
