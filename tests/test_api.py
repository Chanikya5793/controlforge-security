from fastapi.testclient import TestClient

from controlforge.api import create_app


def test_health_endpoint(project_root, tmp_path) -> None:  # type: ignore[no-untyped-def]
    app = create_app(
        rules_directory=project_root / "rules",
        control_config_path=project_root / "config" / "agents.yml",
        database_path=tmp_path / "api.db",
    )
    response = TestClient(app).get("/health")
    assert response.status_code == 200
    assert response.json() == {"status": "ok", "version": "0.2.0"}


def test_event_scan_and_alert_query(project_root, tmp_path) -> None:  # type: ignore[no-untyped-def]
    app = create_app(
        rules_directory=project_root / "rules",
        control_config_path=project_root / "config" / "agents.yml",
        database_path=tmp_path / "api.db",
    )
    client = TestClient(app)
    payload = {
        "events": [
            {
                "event_id": "api-1",
                "event_type": "privileged_role_grant",
                "timestamp": "2026-08-11T14:00:00Z",
                "actor": "contractor@example.com",
                "target": "finance-db",
                "attributes": {"role": "database-owner", "change_ticket": "none"},
            }
        ]
    }

    scan = client.post("/v1/events/scan", json=payload)
    alerts = client.get("/v1/alerts?limit=10")

    assert scan.status_code == 200
    assert scan.json()["alerts"][0]["rule_id"] == "CF-IDENTITY-002"
    assert alerts.status_code == 200
    assert len(alerts.json()) == 1


def test_invalid_alert_limit_is_rejected(project_root, tmp_path) -> None:  # type: ignore[no-untyped-def]
    app = create_app(
        rules_directory=project_root / "rules",
        control_config_path=project_root / "config" / "agents.yml",
        database_path=tmp_path / "api.db",
    )
    response = TestClient(app).get("/v1/alerts?limit=0")
    assert response.status_code == 422


def test_exposure_scan_persists_privacy_safe_alert(project_root, tmp_path) -> None:  # type: ignore[no-untyped-def]
    app = create_app(
        rules_directory=project_root / "rules",
        control_config_path=project_root / "config" / "agents.yml",
        database_path=tmp_path / "api.db",
    )
    client = TestClient(app)
    payload = {
        "exposures": [
            {
                "exposure_id": "e" * 24,
                "identity_sha256": "a" * 64,
                "monitored_domain": "example.com",
                "source_name": "ExampleBreach",
                "kind": "breach",
                "observed_at": "2026-08-12T15:00:00Z",
            }
        ]
    }

    scan = client.post("/v1/exposures/scan", json=payload)
    alerts = client.get("/v1/alerts?limit=10")

    assert scan.status_code == 200
    assert scan.json()["alerts"][0]["rule_id"] == "CF-EXPOSURE-001"
    assert alerts.json()[0]["actor"] == "identity:aaaaaaaaaaaa"
