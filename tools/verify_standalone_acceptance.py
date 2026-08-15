#!/usr/bin/env python3
"""Run a non-destructive Standalone 1.0 acceptance exercise in a temporary directory."""

from __future__ import annotations

import argparse
import base64
import hashlib
import hmac
import json
import os
import sqlite3
import stat
import subprocess
import sys
import tempfile
from collections.abc import Sequence
from dataclasses import asdict, dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Optional

PROJECT_ROOT = Path(__file__).resolve().parents[1]
SOURCE_ROOT = PROJECT_ROOT / "src"
if str(SOURCE_ROOT) not in sys.path:
    sys.path.insert(0, str(SOURCE_ROOT))

from fastapi.testclient import TestClient  # noqa: E402

from controlforge.credential_rotation import (  # noqa: E402
    CredentialRotationEnvelope,
    decrypt_rotation_envelope,
)
from controlforge.detections import (  # noqa: E402
    DetectionPipeline,
    SigmaRule,
    canonical_sigma_rule,
    load_rules,
    sigma_rule_digest,
)
from controlforge.macos_response import (  # noqa: E402
    CONTROLFORGE_ANCHOR,
    PFCTL,
    MacOSPfResponseAdapter,
    MacOSResponseAction,
)
from controlforge.models import DetectionAlert, SecurityEvent  # noqa: E402
from controlforge.standalone.api import (  # noqa: E402
    StandaloneApiServices,
    create_standalone_app,
)
from controlforge.standalone.audit import StandaloneAuditLog  # noqa: E402
from controlforge.standalone.auth import (  # noqa: E402
    DeviceHmacAuthenticator,
    SignedCollectorRequest,
)
from controlforge.standalone.backup import BackupError, StandaloneBackupService  # noqa: E402
from controlforge.standalone.cases import StandaloneCaseService  # noqa: E402
from controlforge.standalone.credential_rotation import (  # noqa: E402
    DeviceCredentialRotationService,
)
from controlforge.standalone.database import StandaloneDatabase  # noqa: E402
from controlforge.standalone.enrollment import (  # noqa: E402
    AesGcmDeviceCredentialCipher,
    DeviceEnrollmentService,
)
from controlforge.standalone.identity import HumanIdentityService  # noqa: E402
from controlforge.standalone.ingestion import CollectorIngestionService  # noqa: E402
from controlforge.standalone.operations import StandaloneOperationsRepository  # noqa: E402
from controlforge.standalone.passkeys import (  # noqa: E402
    AuthenticationVerification,
    RegistrationVerification,
)
from controlforge.standalone.presentation import (  # noqa: E402
    StandalonePresentationRepository,
)
from controlforge.standalone.replay import DecisionReplayService  # noqa: E402
from controlforge.standalone.response import StandaloneResponseService  # noqa: E402
from controlforge.standalone.retention import StandaloneRetentionService  # noqa: E402
from controlforge.standalone.secrets import StandaloneSecretBundle  # noqa: E402
from controlforge.standalone.settings import StandaloneSettings  # noqa: E402
from controlforge.standalone.store import StandaloneStore  # noqa: E402
from controlforge.standalone.worker import StandaloneDetectionWorker  # noqa: E402

NOW = datetime(2026, 8, 22, 22, 0, tzinfo=timezone.utc)
ORIGIN = "https://admin.controlforge.test"
DEVICE_ID = "acceptance-mac-1"
_EXPECTED_PACKAGED_RULES = {
    "credential_dumping.yml",
    "edge_sensitive_path_scan.yml",
    "encoded_powershell.yml",
    "phishing_email.yml",
    "privilege_grant.yml",
    "run_key_persistence.yml",
    "santa_denied_execution.yml",
    "santa_gatekeeper_override.yml",
    "santa_xprotect.yml",
    "suspicious_process_tree.yml",
}


class _AcceptancePfRunner:
    """Record fixed PF calls without executing a host command."""

    def __init__(self) -> None:
        self.calls: list[tuple[tuple[str, ...], Optional[str]]] = []

    def run(self, arguments: Sequence[str], rules: Optional[str] = None) -> str:
        fixed = tuple(arguments)
        self.calls.append((fixed, rules))
        if fixed == (PFCTL, "-E"):
            return "pf enabled\nToken : 42\n"
        return ""


class _AcceptanceManagementResolver:
    """Return documentation-only addresses without performing DNS."""

    def resolve(self, host: str, port: int) -> tuple[str, ...]:
        _require(host == "standalone.example.com", "adapter host changed")
        _require(port == 8443, "adapter port changed")
        return ("192.0.2.10", "2001:db8::10")


class _AcceptanceFailingDetector:
    """Force bounded retry/dead-letter transitions without external dependencies."""

    def evaluate(self, event: SecurityEvent) -> list[DetectionAlert]:
        raise RuntimeError(f"injected detector failure for {event.event_id}")


@dataclass(frozen=True)
class CheckResult:
    name: str
    status: str
    evidence: str


class DeterministicPasskeyAdapter:
    """Test-only ceremony adapter; it is not evidence of hardware WebAuthn verification."""

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
            raise ValueError("test registration challenge mismatch")
        credential_id = response.get("id")
        if not isinstance(credential_id, str):
            raise ValueError("test registration credential is missing")
        return RegistrationVerification(credential_id, b"acceptance-public-key", 0)

    def authentication_options(
        self,
        challenge: bytes,
        credential_ids: list[str],
    ) -> dict[str, object]:
        return {"challenge": self._challenge(challenge), "allow": credential_ids}

    @staticmethod
    def response_credential_id(response: dict[str, object]) -> str:
        credential_id = response.get("id")
        if not isinstance(credential_id, str):
            raise ValueError("test authentication credential is missing")
        return credential_id

    def verify_authentication(
        self,
        response: dict[str, object],
        challenge: bytes,
        public_key: bytes,
        current_sign_count: int,
    ) -> AuthenticationVerification:
        if response.get("challenge") != self._challenge(challenge):
            raise ValueError("test authentication challenge mismatch")
        if public_key != b"acceptance-public-key":
            raise ValueError("test authentication public key mismatch")
        return AuthenticationVerification(
            self.response_credential_id(response),
            current_sign_count + 1,
        )


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise RuntimeError(message)


def _decision_metadata(
    rules: list[SigmaRule],
) -> tuple[dict[str, str], dict[str, str], dict[str, str]]:
    versions: dict[str, str] = {}
    digests: dict[str, str] = {}
    snapshots: dict[str, str] = {}
    for rule in rules:
        rule_id = rule.id
        versions[rule_id] = str(rule.rule_version)
        digests[rule_id] = sigma_rule_digest(rule)
        snapshots[rule_id] = json.dumps(
            canonical_sigma_rule(rule),
            ensure_ascii=False,
            separators=(",", ":"),
            sort_keys=True,
        )
    return versions, digests, snapshots


def _signed_headers(
    body: bytes,
    credential_id: str,
    secret: str,
    nonce: str,
    *,
    method: str = "POST",
    path: str = "/v1/ingest/events",
    timestamp: datetime = NOW,
) -> dict[str, str]:
    timestamp_text = timestamp.isoformat().replace("+00:00", "Z")
    unsigned = SignedCollectorRequest(
        method=method,
        path=path,
        body=body,
        credential_id=credential_id,
        timestamp=timestamp_text,
        nonce=nonce,
        signature="0" * 64,
    )
    signature = hmac.new(
        secret.encode("utf-8"),
        DeviceHmacAuthenticator.canonical_request(unsigned),
        hashlib.sha256,
    ).hexdigest()
    return {
        "content-type": "application/json",
        "x-controlforge-credential-id": credential_id,
        "x-controlforge-timestamp": timestamp_text,
        "x-controlforge-nonce": nonce,
        "x-controlforge-signature": signature,
    }


def _run_contract_gates(project_root: Path) -> CheckResult:
    commands = [
        ([sys.executable, "tools/compile_detection_rules.py", "--check"], project_root),
        (
            [
                sys.executable,
                "-m",
                "pytest",
                "-q",
                "tests/test_detection_conformance.py",
                "--no-cov",
            ],
            project_root,
        ),
        (
            [
                "npx",
                "vitest",
                "run",
                "test/detection-conformance.test.ts",
                "--coverage=false",
            ],
            project_root / "cloud",
        ),
    ]
    for command, cwd in commands:
        completed = subprocess.run(  # noqa: S603 - fixed repository-local verification commands
            command,
            cwd=cwd,
            capture_output=True,
            text=True,
            check=False,
        )
        if completed.returncode != 0:
            summary = (completed.stderr or completed.stdout).strip().splitlines()[-1:]
            return CheckResult(
                "cloud_local_stateless_contract",
                "fail",
                f"command failed with exit {completed.returncode}: {' '.join(summary)}",
            )
    return CheckResult(
        "cloud_local_stateless_contract",
        "pass",
        "compiler freshness plus shared Python and Cloud stateless vectors passed",
    )


def _verify_signed_package(package_path: Path, expected_sha256: str) -> CheckResult:
    if not package_path.is_file():
        return CheckResult(
            "signed_notarized_standalone_package",
            "fail",
            f"package does not exist: {package_path}",
        )
    actual_sha256 = hashlib.sha256(package_path.read_bytes()).hexdigest()
    if not hmac.compare_digest(actual_sha256, expected_sha256.casefold()):
        return CheckResult(
            "signed_notarized_standalone_package",
            "fail",
            f"SHA-256 mismatch: expected {expected_sha256}, got {actual_sha256}",
        )
    commands = [
        (["pkgutil", "--check-signature", str(package_path)], "Notarization: trusted"),
        (["xcrun", "stapler", "validate", str(package_path)], "validate action worked"),
        (
            ["spctl", "--assess", "--type", "install", "-vv", str(package_path)],
            "source=Notarized Developer ID",
        ),
    ]
    for command, required_text in commands:
        try:
            completed = subprocess.run(  # noqa: S603 - fixed macOS verification tools
                command,
                capture_output=True,
                text=True,
                check=False,
            )
        except FileNotFoundError as exc:
            return CheckResult(
                "signed_notarized_standalone_package",
                "fail",
                f"required verification tool is unavailable: {exc.filename}",
            )
        output = f"{completed.stdout}\n{completed.stderr}"
        if completed.returncode != 0 or required_text not in output:
            return CheckResult(
                "signed_notarized_standalone_package",
                "fail",
                f"package verification failed: {command[0]} exit {completed.returncode}",
            )
    with tempfile.TemporaryDirectory(prefix="controlforge-package-verify-") as temporary:
        expanded = Path(temporary) / "expanded"
        unpacked = subprocess.run(  # noqa: S603 - fixed macOS package inspection tool
            ["/usr/sbin/pkgutil", "--expand-full", str(package_path), str(expanded)],
            capture_output=True,
            text=True,
            check=False,
        )
        if unpacked.returncode != 0:
            return CheckResult(
                "signed_notarized_standalone_package",
                "fail",
                f"package expansion failed with exit {unpacked.returncode}",
            )
        rule_directories = list(expanded.glob("*.pkg/Payload/Library/ControlForge/rules"))
        if len(rule_directories) != 1:
            return CheckResult(
                "signed_notarized_standalone_package",
                "fail",
                "package does not contain one fixed standalone rule directory",
            )
        rules_directory = rule_directories[0]
        rule_files = {path.name: path for path in rules_directory.glob("*.yml")}
        trusted_rules = rule_files.keys() == _EXPECTED_PACKAGED_RULES and all(
            path.is_file() and not path.is_symlink() and stat.S_IMODE(path.stat().st_mode) == 0o644
            for path in rule_files.values()
        )
        payload = rules_directory.parents[2]
        wrapper = payload / "Library/ControlForge/bin/controlforge"
        runtime = payload / "Library/ControlForge/bin/controlforge-runtime"
        user_app = payload / "Applications/ControlForge.app"
        default_config = payload / "Library/Application Support/ControlForge/collector.default.yml"
        live_config = payload / "Library/Application Support/ControlForge/collector.yml"
        if not trusted_rules or not default_config.is_file() or live_config.exists():
            return CheckResult(
                "signed_notarized_standalone_package",
                "fail",
                "package rule/configuration payload boundary is invalid",
            )
        payload_commands = [
            ["/usr/bin/codesign", "--verify", "--strict", str(wrapper)],
            ["/usr/bin/codesign", "--verify", "--strict", str(runtime)],
            ["/usr/bin/codesign", "--verify", "--deep", "--strict", str(user_app)],
            [str(runtime), "standalone-appliance", "--help"],
        ]
        for command in payload_commands:
            inspected = subprocess.run(  # noqa: S603 - fixed expanded-payload boundary
                command,
                stdin=subprocess.DEVNULL,
                capture_output=True,
                text=True,
                check=False,
            )
            if inspected.returncode != 0:
                return CheckResult(
                    "signed_notarized_standalone_package",
                    "fail",
                    f"expanded package verification failed: {command[0]} exit "
                    f"{inspected.returncode}",
                )
        runtime_help = subprocess.run(  # noqa: S603 - fixed expanded-payload boundary
            [str(runtime), "--help"],
            stdin=subprocess.DEVNULL,
            capture_output=True,
            text=True,
            check=False,
        )
        if runtime_help.returncode != 0 or not {
            "agent-containment-status",
            "agent-containment-release",
        }.issubset(runtime_help.stdout.split()):
            return CheckResult(
                "signed_notarized_standalone_package",
                "fail",
                "expanded runtime does not expose local containment recovery commands",
            )
    return CheckResult(
        "signed_notarized_standalone_package",
        "pass",
        f"SHA-256 {actual_sha256}; Developer ID signature, Apple notarization, and stapled "
        "ticket, strict payload code signatures, bundled appliance launcher, canonical rules, "
        "local containment recovery, and default-only collector configuration verified locally",
    )


def _sqlite_snapshot_smoke(database_path: Path, restored_path: Path) -> tuple[int, int, str]:
    with sqlite3.connect(database_path) as source, sqlite3.connect(restored_path) as destination:
        source.backup(destination)
    restored_path.chmod(0o600)
    with sqlite3.connect(restored_path) as restored:
        integrity = str(restored.execute("PRAGMA integrity_check").fetchone()[0])
        events = int(restored.execute("SELECT COUNT(*) FROM events").fetchone()[0])
        alerts = int(restored.execute("SELECT COUNT(*) FROM alerts").fetchone()[0])
    return events, alerts, integrity


def run_acceptance(
    project_root: Path,
    run_contract_gates: bool,
    signed_package: Optional[Path] = None,
    signed_package_sha256: Optional[str] = None,
) -> dict[str, object]:
    checks: list[CheckResult] = []
    with tempfile.TemporaryDirectory(prefix="controlforge-acceptance-") as temporary:
        root = Path(temporary)
        settings = StandaloneSettings(
            database_path=root / "standalone.db",
            worker_lease_seconds=5,
            worker_max_attempts=3,
        )
        database = StandaloneDatabase(settings)
        database.initialize()
        store = StandaloneStore(database)
        cipher = AesGcmDeviceCredentialCipher(hashlib.sha256(b"acceptance-device-key").digest())
        audit_log = StandaloneAuditLog(
            database,
            hashlib.sha256(b"acceptance-audit-key").digest(),
        )
        identity = HumanIdentityService(
            database,
            DeterministicPasskeyAdapter(),
            b"acceptance-session-pepper-material-01",
            b"acceptance-recovery-pepper-material1",
            audit=audit_log,
        )
        enrollment = DeviceEnrollmentService(database, cipher)
        cases_service = StandaloneCaseService(
            database,
            identity,
            audit_log,
        )
        device_authenticator = DeviceHmacAuthenticator(database, cipher)
        credential_rotation = DeviceCredentialRotationService(
            database,
            cipher,
            device_authenticator,
        )
        response_service = StandaloneResponseService(
            database,
            identity,
            audit_log,
            device_authenticator,
        )
        rules = load_rules(project_root / "rules")
        versions, digests, snapshots = _decision_metadata(rules)
        app = create_standalone_app(
            StandaloneApiServices(
                identity=identity,
                ingestion=CollectorIngestionService(
                    device_authenticator,
                    store,
                ),
                enrollment=enrollment,
                operations=StandaloneOperationsRepository(database),
                replay=DecisionReplayService(database, rules, "acceptance-detector-v1"),
                cases=cases_service,
                responses=response_service,
                presentation=StandalonePresentationRepository(database),
                retention=StandaloneRetentionService(database, identity, audit_log),
                credential_rotation=credential_rotation,
            ),
            ORIGIN,
            clock=lambda: NOW,
        )
        client = TestClient(app, base_url=ORIGIN)
        responder_client = TestClient(app, base_url=ORIGIN)

        health = client.get("/health")
        admin = client.get("/admin")
        _require(health.status_code == 200 and health.json()["status"] == "ok", "health failed")
        _require(admin.status_code == 200, "admin page failed")
        _require("default-src 'none'" in admin.headers["content-security-policy"], "CSP missing")
        checks.append(
            CheckResult(
                "runtime_and_admin_surface",
                "pass",
                "temporary migrated SQLite runtime served health and CSP-bound admin HTML",
            )
        )

        token = identity.issue_bootstrap_token(NOW)
        options = client.post(
            "/v1/bootstrap/options",
            headers={"origin": ORIGIN},
            json={
                "token": token,
                "tenant_slug": "acceptance",
                "tenant_display_name": "Acceptance Tenant",
                "email": "admin@example.com",
                "display_name": "Acceptance Admin",
            },
        )
        _require(options.status_code == 200, "bootstrap options failed")
        ceremony = options.json()
        completed = client.post(
            "/v1/bootstrap/complete",
            headers={"origin": ORIGIN},
            json={
                "token": token,
                "challenge_id": ceremony["challenge_id"],
                "credential": {
                    "id": "acceptance-admin-credential",
                    "challenge": ceremony["options"]["challenge"],
                },
            },
        )
        _require(completed.status_code == 200, "bootstrap completion failed")
        _require(
            client.get("/v1/bootstrap/status").json() == {"configured": True},
            "bootstrap active",
        )
        csrf = str(completed.json()["csrf_token"])
        mutation_headers = {"origin": ORIGIN, "x-csrf-token": csrf}
        principal = client.get("/v1/me").json()
        tenant_id = str(principal["tenant_id"])
        checks.append(
            CheckResult(
                "first_admin_bootstrap_api",
                "pass",
                "single-use console token completed through HTTPS-origin and passkey service APIs",
            )
        )

        invite_response = client.post(
            "/v1/team/invites",
            headers=mutation_headers,
            json={
                "email": "responder@example.com",
                "display_name": "Acceptance Responder",
                "role": "responder",
                "expires_in_minutes": 15,
            },
        )
        _require(invite_response.status_code == 201, "second-responder invite failed")
        invite = invite_response.json()
        invite_options = responder_client.post(
            "/v1/auth/invites/options",
            headers={"origin": ORIGIN},
            json={"token": invite["token"]},
        )
        _require(invite_options.status_code == 200, "second-responder options failed")
        invite_ceremony = invite_options.json()
        invite_completed = responder_client.post(
            "/v1/auth/invites/complete",
            headers={"origin": ORIGIN},
            json={
                "token": invite["token"],
                "challenge_id": invite_ceremony["challenge_id"],
                "credential": {
                    "id": "acceptance-responder-credential",
                    "challenge": invite_ceremony["options"]["challenge"],
                },
            },
        )
        _require(invite_completed.status_code == 200, "second-responder enrollment failed")
        responder_csrf = str(invite_completed.json()["csrf_token"])
        responder_mutation_headers = {
            "origin": ORIGIN,
            "x-csrf-token": responder_csrf,
        }
        responder_principal = responder_client.get("/v1/me").json()
        _require(
            responder_principal["user_id"] != principal["user_id"]
            and responder_principal["role"] == "responder",
            "second responder is not an independent principal",
        )

        grant_response = client.post(
            "/v1/devices/enrollment-grants",
            headers=mutation_headers,
            json={"expected_device_id": DEVICE_ID, "expires_in_minutes": 15},
        )
        _require(grant_response.status_code == 201, "enrollment grant failed")
        grant = grant_response.json()
        enrollment_response = client.post(
            "/v1/devices/enroll",
            json={
                "token": grant["token"],
                "device_id": DEVICE_ID,
                "display_name": "Acceptance Mac",
                "platform": "macos",
            },
        )
        _require(enrollment_response.status_code == 201, "device enrollment failed")
        enrolled = enrollment_response.json()
        reused = client.post(
            "/v1/devices/enroll",
            json={
                "token": grant["token"],
                "device_id": "replacement-mac",
                "display_name": "Replacement Mac",
                "platform": "macos",
            },
        )
        _require(reused.status_code == 409, "enrollment token replay did not fail closed")
        checks.append(
            CheckResult(
                "device_enrollment_api",
                "pass",
                "bound one-time grant created one encrypted device credential; replay returned 409",
            )
        )

        event = {
            "event_id": "acceptance-powershell-1",
            "event_type": "process_start",
            "timestamp": NOW.isoformat(),
            "actor": f"device:{DEVICE_ID}",
            "device_id": DEVICE_ID,
            "attributes": {
                "process_name": "powershell.exe",
                "command_line": "powershell.exe -enc SQBFAFgA",
            },
        }
        body = json.dumps({"events": [event]}, separators=(",", ":"), sort_keys=True).encode()
        ingested = client.post(
            "/v1/ingest/events",
            content=body,
            headers=_signed_headers(
                body,
                str(enrolled["credential_id"]),
                str(enrolled["credential_secret"]),
                "acceptance-nonce-00000001",
            ),
        )
        _require(ingested.status_code == 202 and ingested.json()["accepted"] == 1, "ingest failed")
        checks.append(
            CheckResult(
                "signed_synthetic_signal",
                "pass",
                "device-bound HMAC API accepted one synthetic encoded-PowerShell event and job",
            )
        )

        abandoned = store.lease_jobs(tenant_id, "abandoned-worker", 1, NOW, 5)
        _require(len(abandoned) == 1, "failed to create abandoned lease")
        reopened_database = StandaloneDatabase(settings)
        reopened_store = StandaloneStore(reopened_database)
        restarted_worker = StandaloneDetectionWorker(
            reopened_store,
            DetectionPipeline(rules),
            settings,
            versions,
            "acceptance-detector-v1",
            rule_digests=digests,
            rule_snapshots=snapshots,
        )
        worker_result = restarted_worker.run_once(
            tenant_id,
            "replacement-worker",
            NOW + timedelta(seconds=5),
        )
        _require(worker_result.alerts_inserted == 1, "restart did not persist one alert")
        _require(
            restarted_worker.run_once(
                tenant_id,
                "replacement-worker",
                NOW + timedelta(minutes=1),
            ).leased
            == 0,
            "completed job was leased twice",
        )
        checks.append(
            CheckResult(
                "worker_restart_recovery",
                "pass",
                "reconstructed worker reclaimed an expired lease and converged to one "
                "alert and case",
            )
        )

        duplicate = client.post(
            "/v1/ingest/events",
            content=body,
            headers=_signed_headers(
                body,
                str(enrolled["credential_id"]),
                str(enrolled["credential_secret"]),
                "acceptance-nonce-00000002",
            ),
        )
        _require(
            duplicate.status_code == 202 and duplicate.json()["duplicates"] == 1,
            "retry failed",
        )
        alerts = client.get("/v1/alerts").json()
        cases = client.get("/v1/cases").json()
        summary = client.get("/v1/dashboard/summary").json()
        _require(len(alerts) == 1 and alerts[0]["rule_id"] == "CF-ENDPOINT-001", "alert missing")
        _require(len(cases) == 1 and cases[0]["alert_count"] == 1, "case missing")
        _require(summary["pending_jobs"] == 0 and summary["dead_jobs"] == 0, "backlog unhealthy")
        checks.append(
            CheckResult(
                "investigation_and_diagnostics_api",
                "pass",
                "authenticated alert, case, dashboard, and health projections showed one "
                "idempotent decision",
            )
        )

        recurring_event = {
            **event,
            "event_id": "acceptance-powershell-2",
            "timestamp": (NOW + timedelta(seconds=1)).isoformat(),
        }
        recurring_body = json.dumps(
            {"events": [recurring_event]},
            separators=(",", ":"),
            sort_keys=True,
        ).encode()
        recurring_ingest = client.post(
            "/v1/ingest/events",
            content=recurring_body,
            headers=_signed_headers(
                recurring_body,
                str(enrolled["credential_id"]),
                str(enrolled["credential_secret"]),
                "acceptance-nonce-00000003",
                timestamp=NOW + timedelta(seconds=1),
            ),
        )
        recurring_worker = restarted_worker.run_once(
            tenant_id,
            "replacement-worker",
            NOW + timedelta(seconds=2),
        )
        recurring_queue_response = client.get("/v1/dashboard/cases")
        _require(
            recurring_queue_response.status_code == 200,
            "recurring case queue was unavailable: "
            f"HTTP {recurring_queue_response.status_code} "
            f"{recurring_queue_response.text[:200]}",
        )
        recurring_queue = recurring_queue_response.json()["cases"]
        _require(
            recurring_ingest.status_code == 202
            and recurring_ingest.json()["accepted"] == 1
            and recurring_worker.alerts_inserted == 1,
            "recurring detection was not persisted",
        )
        _require(
            len(recurring_queue) == 1
            and recurring_queue[0]["case_id"] == cases[0]["case_id"]
            and recurring_queue[0]["alert_count"] == 2
            and recurring_queue[0]["recurrence_count"] == 1,
            "recurring detection created case-queue noise",
        )
        checks.append(
            CheckResult(
                "semantic_case_aggregation",
                "pass",
                "two same-rule detections from one device linked to one active case with "
                "an exact recurrence count",
            )
        )

        case_id = str(cases[0]["case_id"])
        assignment = client.post(
            f"/v1/cases/{case_id}/assignment",
            headers=mutation_headers,
            json={"assignee_user_id": responder_principal["user_id"]},
        )
        note = client.post(
            f"/v1/cases/{case_id}/notes",
            headers=mutation_headers,
            json={"note": "Reviewed deterministic evidence and source digest."},
        )
        investigating = client.post(
            f"/v1/cases/{case_id}/transitions",
            headers=mutation_headers,
            json={"status": "investigating"},
        )
        disposition = client.post(
            f"/v1/cases/{case_id}/dispositions",
            headers=mutation_headers,
            json={
                "status": "true_positive",
                "rationale": "Synthetic test signal matched the expected canonical rule.",
            },
        )
        closed = client.post(
            f"/v1/cases/{case_id}/transitions",
            headers=mutation_headers,
            json={"status": "closed"},
        )
        reopened = client.post(
            f"/v1/cases/{case_id}/transitions",
            headers=mutation_headers,
            json={"status": "open"},
        )
        stale_reclose = client.post(
            f"/v1/cases/{case_id}/transitions",
            headers=mutation_headers,
            json={"status": "closed"},
        )
        fresh_disposition = client.post(
            f"/v1/cases/{case_id}/dispositions",
            headers=mutation_headers,
            json={
                "status": "true_positive",
                "rationale": "Reopened evidence was reviewed in a new investigation cycle.",
            },
        )
        reclosed = client.post(
            f"/v1/cases/{case_id}/transitions",
            headers=mutation_headers,
            json={"status": "closed"},
        )
        reopened_again = client.post(
            f"/v1/cases/{case_id}/transitions",
            headers=mutation_headers,
            json={"status": "open"},
        )
        audit = client.get("/v1/audit/verify")
        _require(
            assignment.status_code == 200
            and assignment.json()["assignee_user_id"] == responder_principal["user_id"],
            "case assignment failed",
        )
        _require(note.status_code == 201, "case note failed")
        _require(investigating.status_code == 200, "case investigation transition failed")
        _require(disposition.status_code == 201, "case disposition failed")
        _require(closed.status_code == 200 and closed.json()["status"] == "closed", "close failed")
        _require(
            reopened.status_code == 200 and reopened.json()["status"] == "open",
            "reopen failed",
        )
        _require(stale_reclose.status_code == 409, "stale disposition closed reopened case")
        _require(fresh_disposition.status_code == 201, "fresh-cycle disposition failed")
        _require(
            reclosed.status_code == 200 and reclosed.json()["status"] == "closed",
            "fresh-cycle close failed",
        )
        _require(
            reopened_again.status_code == 200 and reopened_again.json()["status"] == "open",
            "second reopen failed",
        )
        _require(audit.status_code == 200 and audit.json()["valid"] is True, "audit failed")
        checks.append(
            CheckResult(
                "analyst_disposition_api",
                "pass",
                "same-tenant assignment, note, investigate, disposition, close, reopen, "
                "fresh-cycle disposition enforcement, and HMAC-chain verification passed",
            )
        )

        old_event = {
            "event_id": "acceptance-old-unreferenced",
            "event_type": "process_start",
            "timestamp": (NOW - timedelta(days=120)).isoformat(),
            "actor": f"device:{DEVICE_ID}",
            "device_id": DEVICE_ID,
            "attributes": {"process_name": "true", "command_line": "/usr/bin/true"},
        }
        store.ingest_event(
            tenant_id,
            SecurityEvent.model_validate(old_event),
            NOW - timedelta(days=120),
        )
        with database.connect() as connection:
            connection.execute(
                """
                UPDATE detection_jobs
                SET status = 'succeeded', updated_at = ?
                WHERE tenant_id = ? AND event_id = 'acceptance-old-unreferenced'
                """,
                ((NOW - timedelta(days=120)).isoformat(), tenant_id),
            )
        retention_policy = client.put(
            "/v1/retention/policy",
            headers=mutation_headers,
            json={"telemetry_days": 30},
        )
        retention_preview = client.get("/v1/retention")
        retention_apply = client.post(
            "/v1/retention/apply",
            headers=mutation_headers,
            json={},
        )
        _require(retention_policy.status_code == 200, "retention policy update failed")
        _require(
            retention_preview.status_code == 200
            and retention_preview.json()["preview"]["terminal_jobs"] == 1
            and retention_preview.json()["preview"]["unreferenced_events"] == 1,
            "retention preview was not exact",
        )
        _require(
            retention_apply.status_code == 200
            and retention_apply.json()["terminal_jobs_deleted"] == 1
            and retention_apply.json()["unreferenced_events_deleted"] == 1,
            "retention apply counts were not exact",
        )
        with database.connect() as connection:
            preserved_alerts = int(
                connection.execute(
                    "SELECT COUNT(*) FROM alerts WHERE tenant_id = ?",
                    (tenant_id,),
                ).fetchone()[0]
            )
            old_events = int(
                connection.execute(
                    """
                    SELECT COUNT(*) FROM events
                    WHERE tenant_id = ? AND event_id = 'acceptance-old-unreferenced'
                    """,
                    (tenant_id,),
                ).fetchone()[0]
            )
        _require(preserved_alerts == 2 and old_events == 0, "retention weakened evidence")
        checks.append(
            CheckResult(
                "audited_telemetry_retention",
                "pass",
                "administrator policy, exact preview/apply counts, unreferenced deletion, "
                "and preservation of linked alert evidence passed",
            )
        )

        replay = client.post(
            f"/v1/alerts/{alerts[0]['alert_id']}/replay",
            headers=mutation_headers,
            json={"mode": "original"},
        )
        _require(
            replay.status_code == 201
            and replay.json()["outcome"] == "same"
            and replay.json()["matched"] is True,
            "original decision replay failed",
        )
        checks.append(
            CheckResult(
                "original_decision_replay_api",
                "pass",
                "stored rule snapshot and evidence replayed to the same deterministic decision",
            )
        )

        proposal = client.post(
            f"/v1/cases/{case_id}/response-actions",
            headers=mutation_headers,
            json={
                "action_type": "isolate_endpoint",
                "device_id": DEVICE_ID,
                "rationale": "Acceptance exercise for fail-closed response governance.",
                "expires_in_seconds": 300,
            },
        )
        _require(proposal.status_code == 201, "response proposal failed")
        response_action_id = str(proposal.json()["action_id"])
        self_approval = client.post(
            f"/v1/response-actions/{response_action_id}/approve",
            headers=mutation_headers,
        )
        _require(self_approval.status_code == 403, "self-approval did not fail closed")
        approved = responder_client.post(
            f"/v1/response-actions/{response_action_id}/approve",
            headers=responder_mutation_headers,
        )
        _require(
            approved.status_code == 200
            and approved.json()["status"] == "approved"
            and approved.json()["approved_by"] == responder_principal["user_id"],
            "independent response approval failed",
        )

        wrong_poll_headers = _signed_headers(
            b"",
            str(enrolled["credential_id"]),
            str(enrolled["credential_secret"]),
            "acceptance-action-wrong-device-01",
            method="GET",
            path="/v1/agent/actions",
        )
        wrong_poll = client.get(
            "/v1/agent/actions?device_id=another-device",
            headers=wrong_poll_headers,
        )
        _require(wrong_poll.status_code == 403, "cross-device action poll did not fail closed")

        poll_headers = _signed_headers(
            b"",
            str(enrolled["credential_id"]),
            str(enrolled["credential_secret"]),
            "acceptance-action-poll-00000001",
            method="GET",
            path="/v1/agent/actions",
        )
        polled = client.get(
            f"/v1/agent/actions?device_id={DEVICE_ID}",
            headers=poll_headers,
        )
        _require(
            polled.status_code == 200
            and polled.json()["actions"][0]["action_id"] == response_action_id,
            "signed action dispatch failed",
        )
        replayed_poll = client.get(
            f"/v1/agent/actions?device_id={DEVICE_ID}",
            headers=poll_headers,
        )
        _require(replayed_poll.status_code == 409, "action poll nonce replay was accepted")
        retried_poll = client.get(
            f"/v1/agent/actions?device_id={DEVICE_ID}",
            headers=_signed_headers(
                b"",
                str(enrolled["credential_id"]),
                str(enrolled["credential_secret"]),
                "acceptance-action-poll-00000002",
                method="GET",
                path="/v1/agent/actions",
            ),
        )
        _require(
            retried_poll.status_code == 200
            and retried_poll.json()["actions"][0]["action_id"] == response_action_id,
            "idempotent action redispatch failed",
        )

        result_path = f"/v1/agent/actions/{response_action_id}/result"
        result_body = json.dumps(
            {
                "evidence": ["acceptance:no-host-mutation"],
                "status": "failed",
                "summary": "Acceptance harness intentionally did not execute host PF commands.",
            },
            separators=(",", ":"),
            sort_keys=True,
        ).encode()
        accepted_result = client.post(
            result_path,
            content=result_body,
            headers=_signed_headers(
                result_body,
                str(enrolled["credential_id"]),
                str(enrolled["credential_secret"]),
                "acceptance-action-result-000001",
                path=result_path,
            ),
        )
        _require(
            accepted_result.status_code == 200
            and accepted_result.json()["status"] == "failed"
            and accepted_result.json()["changed"] is True,
            "signed action result failed",
        )
        repeated_result = client.post(
            result_path,
            content=result_body,
            headers=_signed_headers(
                result_body,
                str(enrolled["credential_id"]),
                str(enrolled["credential_secret"]),
                "acceptance-action-result-000002",
                path=result_path,
            ),
        )
        listed_responses = client.get("/v1/response-actions")
        _require(
            repeated_result.status_code == 200 and repeated_result.json()["changed"] is False,
            "identical action result was not idempotent",
        )
        listed_action = listed_responses.json()["actions"][0]
        _require(
            listed_responses.status_code == 200
            and listed_action["status"] == "failed"
            and listed_action["dispatch_count"] == 2
            and listed_action["result_evidence"] == ["acceptance:no-host-mutation"],
            "response outcome was not visible to the operator",
        )
        response_audit = client.get("/v1/audit/verify")
        _require(
            response_audit.status_code == 200 and response_audit.json()["valid"] is True,
            "response audit lineage failed",
        )
        checks.append(
            CheckResult(
                "active_response_governance_api",
                "pass",
                "two distinct passkey principals, self-approval denial, exact-device HMAC "
                "dispatch, nonce replay rejection, redispatch, idempotent result, and audit "
                "lineage passed without changing the host",
            )
        )

        rotation_started = client.post(
            f"/v1/devices/{DEVICE_ID}/credentials/rotate",
            headers=mutation_headers,
            json={"lifetime_days": 30},
        )
        _require(rotation_started.status_code == 201, "credential rotation did not start")
        rotation_record = rotation_started.json()
        _require(
            "credential_secret" not in rotation_record and rotation_record["status"] == "pending",
            "credential rotation exposed plaintext material",
        )
        rotation_path = "/v1/agent/credential-rotation"
        rotation_poll = client.get(
            f"{rotation_path}?device_id={DEVICE_ID}",
            headers=_signed_headers(
                b"",
                str(enrolled["credential_id"]),
                str(enrolled["credential_secret"]),
                "acceptance-rotation-poll-0001",
                method="GET",
                path=rotation_path,
            ),
        )
        _require(rotation_poll.status_code == 200, "credential rotation delivery failed")
        envelope = CredentialRotationEnvelope.model_validate(rotation_poll.json()["rotation"])
        replacement = decrypt_rotation_envelope(
            envelope,
            str(enrolled["credential_secret"]).encode(),
            expected_device_id=DEVICE_ID,
            expected_credential_id=str(enrolled["credential_id"]),
            now=NOW,
        )
        ack_path = "/v1/agent/credential-rotation/ack"
        ack_body = b"{}"
        rotation_ack = client.post(
            ack_path,
            content=ack_body,
            headers=_signed_headers(
                ack_body,
                replacement.replacement_credential_id,
                replacement.replacement_secret,
                "acceptance-rotation-ack-00001",
                path=ack_path,
            ),
        )
        _require(
            rotation_ack.status_code == 200 and rotation_ack.json()["status"] == "acknowledged",
            "credential rotation acknowledgment failed",
        )
        old_credential = client.get(
            f"{rotation_path}?device_id={DEVICE_ID}",
            headers=_signed_headers(
                b"",
                str(enrolled["credential_id"]),
                str(enrolled["credential_secret"]),
                "acceptance-rotation-old-0001",
                method="GET",
                path=rotation_path,
            ),
        )
        _require(old_credential.status_code == 401, "rotation predecessor remained active")
        replacement_retry = client.post(
            "/v1/ingest/events",
            content=body,
            headers=_signed_headers(
                body,
                replacement.replacement_credential_id,
                replacement.replacement_secret,
                "acceptance-rotation-new-0001",
            ),
        )
        _require(
            replacement_retry.status_code == 202 and replacement_retry.json()["duplicates"] == 1,
            "activated replacement could not authenticate idempotent ingestion",
        )
        checks.append(
            CheckResult(
                "endpoint_bound_credential_rotation",
                "pass",
                "admin received no secret; predecessor-delivered encrypted material was "
                "acknowledged only by the replacement, predecessor authentication failed, "
                "and replacement ingestion succeeded",
            )
        )

        pf_clock = [NOW]
        pf_runner = _AcceptancePfRunner()
        pf_state_path = root / "pf-contract" / "pf-state.json"
        pf_adapter = MacOSPfResponseAdapter(
            enabled=True,
            device_id=DEVICE_ID,
            api_host="standalone.example.com",
            api_port=8443,
            state_path=pf_state_path,
            runner=pf_runner,
            resolver=_AcceptanceManagementResolver(),
            clock=lambda: pf_clock[0],
            system=lambda: "Darwin",
            euid=lambda: 0,
            state_expected_uid=os.geteuid(),
        )
        isolate = MacOSResponseAction(
            action_id="00000000-0000-4000-8000-000000000001",
            action_type="isolate_endpoint",
            target_type="device",
            target_id=DEVICE_ID,
            rationale="Exercise the non-executing acceptance adapter seam.",
            risk_level="active",
            expires_at=NOW + timedelta(minutes=30),
        )
        first_isolate = pf_adapter.execute(isolate)
        repeated_isolate = pf_adapter.execute(isolate)
        release = MacOSResponseAction(
            action_id="00000000-0000-4000-8000-000000000002",
            action_type="release_endpoint",
            target_type="device",
            target_id=DEVICE_ID,
            rationale="Exercise explicit release through the adapter contract.",
            risk_level="active",
            expires_at=NOW + timedelta(minutes=30),
        )
        explicit_release = pf_adapter.execute(release)
        second_isolate = pf_adapter.execute(isolate)
        pf_clock[0] = NOW + timedelta(minutes=15)
        automatic_release = pf_adapter.reconcile()

        enable_call = (PFCTL, "-E")
        load_call = (PFCTL, "-a", CONTROLFORGE_ANCHOR, "-f", "-")
        flush_call = (PFCTL, "-a", CONTROLFORGE_ANCHOR, "-F", "all")
        release_call = (PFCTL, "-X", "42")
        call_arguments = [arguments for arguments, _rules in pf_runner.calls]
        loaded_rules = [
            rules
            for arguments, rules in pf_runner.calls
            if arguments == load_call and rules is not None
        ]
        _require(first_isolate.state == "isolated", "adapter isolate contract failed")
        _require(
            repeated_isolate.state == "unchanged",
            "repeated isolate was not idempotent",
        )
        _require(explicit_release.state == "released", "explicit release contract failed")
        _require(second_isolate.state == "isolated", "second isolate contract failed")
        _require(
            automatic_release is not None
            and automatic_release.state == "released"
            and automatic_release.reason == "containment_expired",
            "automatic release did not occur at the containment bound",
        )
        _require(
            set(call_arguments) == {enable_call, load_call, flush_call, release_call},
            "adapter used an unexpected PF command contract",
        )
        _require(
            bool(loaded_rules)
            and all(
                "192.0.2.10 port 8443" in rules
                and "2001:db8::10 port 8443" in rules
                and "/etc/pf.conf" not in rules
                for rules in loaded_rules
            ),
            "management allowlist rules were incomplete",
        )
        _require(not pf_state_path.exists(), "automatic release retained PF ownership state")
        checks.append(
            CheckResult(
                "macos_pf_adapter_contract",
                "pass",
                "an injected non-executing PF runner proved fixed argv, dedicated-anchor "
                "rules, management allowlisting, 15-minute capping, isolate idempotency, "
                "explicit release, and automatic release without running a host command",
            )
        )

        restored_path = root / "restored.db"
        restored_events, restored_alerts, integrity = _sqlite_snapshot_smoke(
            settings.database_path,
            restored_path,
        )
        _require(
            (restored_events, restored_alerts, integrity) == (2, 2, "ok"),
            "SQLite snapshot smoke failed",
        )
        restored_database = StandaloneDatabase(StandaloneSettings(database_path=restored_path))
        _require(
            restored_database.applied_versions() == database.applied_versions(),
            "schema mismatch",
        )
        checks.append(
            CheckResult(
                "sqlite_online_snapshot_smoke",
                "pass",
                "temporary SQLite online snapshot reopened with matching schema, two events, "
                "two alerts, and integrity ok",
            )
        )

        backup_secrets = StandaloneSecretBundle(
            session_pepper=hashlib.sha256(b"acceptance-backup-session").digest(),
            recovery_pepper=hashlib.sha256(b"acceptance-backup-recovery").digest(),
            credential_key=hashlib.sha256(b"acceptance-device-key").digest(),
            audit_key=hashlib.sha256(b"acceptance-audit-key").digest(),
        )
        backups = StandaloneBackupService(database, backup_secrets, root / "backups")
        created_backup = backups.create_backup(tenant_id=tenant_id, now=NOW + timedelta(minutes=2))
        artifact = backups.backup_directory / created_backup.filename
        verified_backup = backups.verify_backup(artifact)
        with database.connect() as connection:
            connection.execute(
                """
                INSERT INTO appliance_state(state_key, value_json, updated_at)
                VALUES ('acceptance-post-backup-marker', '{"present":true}', ?)
                """,
                ((NOW + timedelta(minutes=3)).isoformat(),),
            )
        restored_backup = backups.restore_backup(artifact, NOW + timedelta(minutes=4))
        with database.connect() as connection:
            post_backup_marker = connection.execute(
                """
                SELECT 1 FROM appliance_state
                WHERE state_key = 'acceptance-post-backup-marker'
                """
            ).fetchone()
        restored_audit = StandaloneAuditLog(database, backup_secrets.audit_key).verify(tenant_id)
        _require(created_backup.verified, "operational backup was not marked verified")
        _require(
            verified_backup.artifact_sha256 == created_backup.artifact_sha256,
            "operational backup verification changed the artifact identity",
        )
        _require(
            restored_backup.backup_id == created_backup.backup_id and post_backup_marker is None,
            "operational backup did not atomically restore the captured state",
        )
        _require(restored_audit.valid, "restored case audit chain failed verification")
        checks.append(
            CheckResult(
                "operational_backup_restore",
                "pass",
                "temporary encrypted backup was authenticated and atomically restored; "
                "restored audit lineage verified",
            )
        )

        stale_ingestion = client.post(
            "/v1/ingest/events",
            content=body,
            headers=_signed_headers(
                body,
                replacement.replacement_credential_id,
                replacement.replacement_secret,
                "acceptance-clock-skew-0001",
                timestamp=NOW - timedelta(minutes=10),
            ),
        )
        _require(stale_ingestion.status_code == 401, "stale signed request was accepted")

        tampered_artifact = root / "tampered-backup.cfbackup"
        tampered_bytes = bytearray(artifact.read_bytes())
        tampered_bytes[-1] ^= 0x01
        tampered_artifact.write_bytes(tampered_bytes)
        tampered_artifact.chmod(0o600)
        tamper_rejected = False
        try:
            backups.verify_backup(tampered_artifact)
        except BackupError:
            tamper_rejected = True
        _require(tamper_rejected, "tampered encrypted backup passed authentication")

        lock_database = StandaloneDatabase(
            StandaloneSettings(
                database_path=root / "fault-lock.db",
                busy_timeout_ms=100,
            )
        )
        lock_database.initialize()
        lock_holder = sqlite3.connect(
            lock_database.settings.database_path,
            isolation_level=None,
        )
        lock_rejected = False
        try:
            lock_holder.execute("BEGIN IMMEDIATE")
            try:
                with lock_database.connect() as contender:
                    contender.execute("BEGIN IMMEDIATE")
            except sqlite3.OperationalError as exc:
                lock_rejected = "locked" in str(exc).casefold()
        finally:
            if lock_holder.in_transaction:
                lock_holder.execute("ROLLBACK")
            lock_holder.close()
        _require(lock_rejected, "database lock contention did not fail closed")
        with lock_database.connect() as recovered:
            recovered.execute("BEGIN IMMEDIATE")
            recovered.execute("UPDATE schema_migrations SET name = name WHERE version = 1")
            recovered.execute("COMMIT")

        full_database = StandaloneDatabase(
            StandaloneSettings(database_path=root / "fault-disk-full.db")
        )
        full_database.initialize()
        disk_full_rejected = False
        with full_database.connect() as constrained:
            constrained.execute("CREATE TABLE fault_payload(payload BLOB NOT NULL)")
            constrained.execute("PRAGMA wal_checkpoint(TRUNCATE)")
            page_count = int(constrained.execute("PRAGMA page_count").fetchone()[0])
            constrained.execute(f"PRAGMA max_page_count = {page_count:d}")
            try:
                constrained.execute(
                    "INSERT INTO fault_payload(payload) VALUES (?)",
                    (b"x" * 100_000,),
                )
            except sqlite3.OperationalError as exc:
                disk_full_rejected = "full" in str(exc).casefold()
                if constrained.in_transaction:
                    constrained.execute("ROLLBACK")
            remaining_fault_rows = int(
                constrained.execute("SELECT COUNT(*) FROM fault_payload").fetchone()[0]
            )
        _require(
            disk_full_rejected and remaining_fault_rows == 0,
            "simulated disk exhaustion did not reject the write atomically",
        )

        fault_event = SecurityEvent(
            event_id="acceptance-forced-detector-failure",
            event_type="endpoint_control_status",
            timestamp=NOW,
            actor=f"device:{DEVICE_ID}",
            device_id=DEVICE_ID,
            attributes={"status": "healthy"},
        )
        store.ingest_event(tenant_id, fault_event, NOW + timedelta(minutes=10))
        failing_worker = StandaloneDetectionWorker(
            store,
            _AcceptanceFailingDetector(),
            settings,
            {},
            detector_version="acceptance-fault-detector-v1",
            retry_delay_seconds=1,
        )
        first_failure = failing_worker.run_once(
            tenant_id,
            "acceptance-fault-worker",
            NOW + timedelta(minutes=10),
        )
        second_failure = failing_worker.run_once(
            tenant_id,
            "acceptance-fault-worker",
            NOW + timedelta(minutes=10, seconds=1),
        )
        terminal_failure = failing_worker.run_once(
            tenant_id,
            "acceptance-fault-worker",
            NOW + timedelta(minutes=10, seconds=3),
        )
        _require(
            first_failure.retried == 1
            and second_failure.retried == 1
            and terminal_failure.dead == 1
            and store.job_counts(tenant_id)["dead"] == 1,
            "detector failures did not converge to the bounded dead-letter state",
        )
        checks.append(
            CheckResult(
                "temporary_fault_injection_matrix",
                "pass",
                "stale HMAC time, authenticated-backup tampering, SQLite writer contention, "
                "post-lock recovery, simulated disk exhaustion, and bounded detector "
                "retry-to-dead-letter transitions failed closed in temporary state",
            )
        )

    if run_contract_gates:
        checks.append(_run_contract_gates(project_root))
    else:
        checks.append(
            CheckResult(
                "cloud_local_stateless_contract",
                "not_run",
                "rerun with --run-contract-gates to execute compiler and both runtime "
                "vector suites",
            )
        )

    if signed_package is not None and signed_package_sha256 is not None:
        checks.append(_verify_signed_package(signed_package, signed_package_sha256))
    else:
        checks.append(
            CheckResult(
                "signed_notarized_standalone_package",
                "not_run",
                "pass --signed-package and --signed-package-sha256 to verify a release artifact",
            )
        )

    checks.extend(
        [
            CheckResult(
                "one_command_appliance_install",
                "unverified",
                "the harness composes an in-process temporary runtime; it does not install "
                "an appliance",
            ),
            CheckResult(
                "real_endpoint_and_local_app",
                "unverified",
                "no clean-Mac enrollment, Keychain transfer, offline app, or real signal "
                "was exercised",
            ),
            CheckResult(
                "trusted_tls_and_hardware_passkey",
                "unverified",
                "the harness uses TestClient HTTPS semantics and a deterministic passkey adapter",
            ),
            CheckResult(
                "clean_install_upgrade_removal",
                "unverified",
                "the release artifact was not installed, upgraded, rolled back, or removed "
                "on a separate clean Mac",
            ),
            CheckResult(
                "physical_active_response",
                "unverified",
                "governance and non-executing adapter contract checks passed, but no installed "
                "Mac was isolated, kept manageable, automatically released, or recovered "
                "out-of-band",
            ),
        ]
    )
    failed = [check for check in checks if check.status == "fail"]
    release_blockers = [check for check in checks if check.status != "pass"]
    return {
        "schema_version": "standalone-acceptance-evidence.v1",
        "generated_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        "scope": "temporary local API and SQLite exercise; no external network or host mutation",
        "current_scope_passed": not failed,
        "release_ready": not release_blockers,
        "checks": [asdict(check) for check in checks],
    }


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--project-root", type=Path, default=PROJECT_ROOT)
    parser.add_argument("--run-contract-gates", action="store_true")
    parser.add_argument("--signed-package", type=Path)
    parser.add_argument("--signed-package-sha256")
    parser.add_argument("--require-release-ready", action="store_true")
    parser.add_argument("--output", type=Path)
    parser.add_argument("--json", action="store_true", help="emit compact JSON")
    return parser


def main(arguments: Optional[list[str]] = None) -> int:
    args = build_parser().parse_args(arguments)
    try:
        if (args.signed_package is None) != (args.signed_package_sha256 is None):
            raise ValueError(
                "--signed-package and --signed-package-sha256 must be supplied together"
            )
        evidence = run_acceptance(
            args.project_root.resolve(),
            args.run_contract_gates,
            args.signed_package.resolve() if args.signed_package is not None else None,
            args.signed_package_sha256,
        )
    except Exception as exc:
        evidence = {
            "schema_version": "standalone-acceptance-evidence.v1",
            "generated_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
            "scope": (
                "temporary local API and SQLite exercise; no external network or host mutation"
            ),
            "current_scope_passed": False,
            "release_ready": False,
            "checks": [
                asdict(CheckResult("harness_execution", "fail", f"{type(exc).__name__}: {exc}"))
            ],
        }
    rendered = json.dumps(evidence, indent=None if args.json else 2, sort_keys=True)
    if args.output is not None:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(f"{rendered}\n", encoding="utf-8")
    print(rendered)
    if not bool(evidence["current_scope_passed"]):
        return 1
    if args.require_release_ready and not bool(evidence["release_ready"]):
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
