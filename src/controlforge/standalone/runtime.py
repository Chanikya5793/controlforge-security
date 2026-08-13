"""Production composition root for a cloud-independent ControlForge appliance."""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path

from fastapi import FastAPI

from controlforge import __version__
from controlforge.detections import (
    DetectionPipeline,
    canonical_non_sigma_provenance,
    canonical_sigma_rule,
    load_rules,
    sigma_rule_digest,
)

from .api import StandaloneApiServices, create_standalone_app
from .audit import StandaloneAuditLog
from .auth import DeviceHmacAuthenticator
from .backup import ApplianceOperationLock
from .cases import StandaloneCaseService
from .credential_rotation import DeviceCredentialRotationService
from .database import StandaloneDatabase
from .enrollment import AesGcmDeviceCredentialCipher, DeviceEnrollmentService
from .identity import HumanIdentityService
from .ingestion import CollectorIngestionService
from .operations import StandaloneOperationsRepository
from .passkeys import WebAuthnPasskeyAdapter
from .presentation import StandalonePresentationRepository
from .replay import DecisionReplayService
from .response import StandaloneResponseService
from .retention import StandaloneRetentionService
from .secrets import StandaloneSecretBundle
from .settings import StandaloneSettings
from .store import StandaloneStore
from .supervisor import StandaloneWorkerSupervisor
from .worker import StandaloneDetectionWorker


@dataclass(frozen=True)
class StandaloneRuntimeConfig:
    settings: StandaloneSettings
    rules_directory: Path
    secret_directory: Path
    admin_origin: str
    rp_id: str
    rp_name: str = "ControlForge Standalone"
    worker_interval_seconds: float = 2.0


@dataclass(frozen=True)
class StandaloneRuntime:
    app: FastAPI
    database: StandaloneDatabase
    identity: HumanIdentityService
    enrollment: DeviceEnrollmentService
    supervisor: StandaloneWorkerSupervisor
    operation_lock: ApplianceOperationLock

    def close(self) -> None:
        """Release the appliance lifetime lock after API and worker shutdown."""

        self.operation_lock.release()


def build_standalone_runtime(config: StandaloneRuntimeConfig) -> StandaloneRuntime:
    """Initialize durable state and compose every standalone trust boundary."""

    operation_lock = ApplianceOperationLock(config.settings.database_path)
    operation_lock.acquire_shared()
    try:
        return _build_locked_runtime(config, operation_lock)
    except Exception:
        operation_lock.release()
        raise


def _build_locked_runtime(
    config: StandaloneRuntimeConfig,
    operation_lock: ApplianceOperationLock,
) -> StandaloneRuntime:
    database = StandaloneDatabase(config.settings)
    database.initialize()
    secret_bundle = StandaloneSecretBundle.load_or_create(config.secret_directory)
    rules = load_rules(config.rules_directory)
    rule_versions = {rule.id: str(rule.rule_version) for rule in rules}
    rule_digests = {rule.id: sigma_rule_digest(rule) for rule in rules}
    rule_snapshots = {
        rule.id: json.dumps(
            canonical_sigma_rule(rule),
            ensure_ascii=False,
            separators=(",", ":"),
            sort_keys=True,
        )
        for rule in rules
    }
    for rule_id, (version, digest, snapshot) in canonical_non_sigma_provenance().items():
        rule_versions[rule_id] = version
        rule_digests[rule_id] = digest
        rule_snapshots[rule_id] = snapshot
    detector_version = f"controlforge-{__version__}"
    store = StandaloneStore(database)
    credential_cipher = AesGcmDeviceCredentialCipher(secret_bundle.credential_key)
    audit = StandaloneAuditLog(database, secret_bundle.audit_key)
    identity = HumanIdentityService(
        database,
        WebAuthnPasskeyAdapter(config.rp_id, config.rp_name, config.admin_origin),
        secret_bundle.session_pepper,
        secret_bundle.recovery_pepper,
        audit=audit,
    )
    enrollment = DeviceEnrollmentService(database, credential_cipher)
    cases = StandaloneCaseService(database, identity, audit)
    device_authenticator = DeviceHmacAuthenticator(database, credential_cipher)
    credential_rotation = DeviceCredentialRotationService(
        database,
        credential_cipher,
        device_authenticator,
    )
    responses = StandaloneResponseService(
        database,
        identity,
        audit,
        device_authenticator,
    )
    worker = StandaloneDetectionWorker(
        store,
        DetectionPipeline(rules),
        config.settings,
        rule_versions,
        detector_version,
        rule_digests=rule_digests,
        rule_snapshots=rule_snapshots,
    )
    supervisor = StandaloneWorkerSupervisor(
        store,
        worker,
        interval_seconds=config.worker_interval_seconds,
    )
    app = create_standalone_app(
        StandaloneApiServices(
            identity=identity,
            ingestion=CollectorIngestionService(
                device_authenticator,
                store,
            ),
            enrollment=enrollment,
            operations=StandaloneOperationsRepository(database),
            replay=DecisionReplayService(database, rules, detector_version),
            cases=cases,
            worker=supervisor,
            responses=responses,
            presentation=StandalonePresentationRepository(database),
            retention=StandaloneRetentionService(database, identity, audit),
            credential_rotation=credential_rotation,
        ),
        config.admin_origin,
    )
    return StandaloneRuntime(app, database, identity, enrollment, supervisor, operation_lock)


__all__ = ["StandaloneRuntime", "StandaloneRuntimeConfig", "build_standalone_runtime"]
