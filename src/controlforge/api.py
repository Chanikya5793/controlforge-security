"""FastAPI surface for control checks, event ingestion, and alert review."""

from __future__ import annotations

import os
from pathlib import Path
from typing import Optional

from fastapi import FastAPI, HTTPException, Query
from pydantic import BaseModel

from .config import load_control_config
from .controls import EndpointAssuranceEngine
from .detections import DetectionPipeline, load_rules
from .models import ControlReport, DetectionAlert, ScanResult, SecurityEvent
from .probes import LocalSystemProbe
from .service import DetectionService
from .store import AuditStore


class EventBatch(BaseModel):
    events: list[SecurityEvent]


class HealthResponse(BaseModel):
    status: str
    version: str


def create_app(
    rules_directory: Optional[Path] = None,
    control_config_path: Optional[Path] = None,
    database_path: Optional[Path] = None,
) -> FastAPI:
    """Application factory with injectable paths for tests and deployments."""

    package_root = Path(__file__).resolve().parents[2]
    package_data = Path(__file__).resolve().parent / "data"
    default_rules = package_root / "rules"
    default_config = package_root / "config" / "agents.yml"
    if not default_rules.exists():
        default_rules = package_data / "rules"
    if not default_config.exists():
        default_config = package_data / "config" / "agents.yml"
    rules_path = rules_directory or Path(os.environ.get("CONTROLFORGE_RULES", default_rules))
    config_path = control_config_path or Path(
        os.environ.get("CONTROLFORGE_CONTROLS", default_config)
    )
    db_path = database_path or Path(os.environ.get("CONTROLFORGE_DATABASE", "controlforge.db"))

    pipeline = DetectionPipeline(load_rules(rules_path))
    store = AuditStore(db_path)
    service = DetectionService(pipeline, store)

    app = FastAPI(
        title="ControlForge Security API",
        version="0.1.0",
        description="Endpoint control assurance and detection automation.",
    )

    @app.get("/health", response_model=HealthResponse)
    def health() -> HealthResponse:
        return HealthResponse(status="ok", version="0.1.0")

    @app.get("/v1/controls/check", response_model=ControlReport)
    def check_controls() -> ControlReport:
        try:
            config = load_control_config(config_path)
            return EndpointAssuranceEngine(config.agents, LocalSystemProbe()).run()
        except (OSError, ValueError) as exc:
            raise HTTPException(status_code=503, detail="control check unavailable") from exc

    @app.post("/v1/events/scan", response_model=ScanResult)
    def scan_events(batch: EventBatch) -> ScanResult:
        if len(batch.events) > 10_000:
            raise HTTPException(status_code=413, detail="batch exceeds 10,000 events")
        return service.process(batch.events)

    @app.get("/v1/alerts", response_model=list[DetectionAlert])
    def recent_alerts(limit: int = Query(default=100, ge=1, le=1000)) -> list[DetectionAlert]:
        return store.recent_alerts(limit)

    return app


app = create_app()
