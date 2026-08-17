from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path

import pytest
from test_network_accounts import NOW, build_network_setup

from controlforge.detections import (
    DetectionPipeline,
    canonical_sigma_rule,
    load_rules,
    sigma_rule_digest,
)
from controlforge.models import SecurityEvent
from controlforge.standalone.dashboard import dashboard_html
from controlforge.standalone.finding_guidance import finding_guidance
from controlforge.standalone.investigation_ui import INVESTIGATION_SCRIPT
from controlforge.standalone.presentation import StandalonePresentationRepository
from controlforge.standalone.store import StandaloneStore
from controlforge.standalone.worker import StandaloneDetectionWorker


@pytest.fixture
def network_setup(tmp_path):
    return build_network_setup(tmp_path)


def seed_findings(database, tenant_id, device_name="Reception Mac"):
    """Use the real deterministic worker; no provider or production account is involved."""
    store = StandaloneStore(database)
    rules = load_rules(Path("rules"))
    for device_id, name in [("shared-mac", device_name), ("other-mac", "Other Mac")]:
        store.register_device(tenant_id, device_id, name, "macos", NOW)
    for event_id, device_id, event_type, attributes in [
        ("launch-1", "shared-mac", "santa_execution", {"decision": "DECISION_DENY"}),
        ("launch-2", "shared-mac", "santa_execution", {"decision": "DECISION_DENY"}),
        ("xprotect-1", "shared-mac", "santa_xprotect", {}),
        ("launch-other", "other-mac", "santa_execution", {"decision": "DECISION_DENY"}),
        ("unbound", None, "santa_execution", {"decision": "DECISION_DENY"}),
    ]:
        store.ingest_event(
            tenant_id,
            SecurityEvent(
                event_id=event_id,
                event_type=event_type,
                timestamp=NOW,
                actor="device:shared-mac",
                device_id=device_id,
                attributes={**attributes, "private_unused": "raw-payload-not-for-dashboard"},
            ),
            NOW,
        )
    worker = StandaloneDetectionWorker(
        store,
        DetectionPipeline(rules),
        database.settings,
        {rule.id: str(rule.rule_version) for rule in rules},
        "guidance-test",
        rule_digests={rule.id: sigma_rule_digest(rule) for rule in rules},
        rule_snapshots={rule.id: json.dumps(canonical_sigma_rule(rule)) for rule in rules},
    )
    assert worker.run_once(tenant_id, "guidance-worker", NOW).alerts_inserted == 5


@pytest.mark.parametrize(
    ("event_type", "label"),
    [
        ("santa_execution", "application launch"),
        ("santa_gatekeeper_override", "Gatekeeper override"),
        ("santa_xprotect", "XProtect record"),
        ("endpoint_control_status", "security-component check"),
        ("process_start", "program-start"),
        ("registry_value_set", "Windows settings-change"),
        ("privileged_role_grant", "access-permission change"),
        ("sensitive_data_access", "sensitive-data access"),
        ("authentication_success", "successful sign-in"),
        ("edge_auth_failure", "failed sign-in"),
        ("edge_session_use", "application-session"),
        ("edge_http_request", "web-request"),
        ("email_received", "email record"),
        ("<script>unknown</script>", "received activity"),
    ],
)
def test_guidance_is_category_context_not_a_security_verdict(event_type, label):
    guidance = finding_guidance(event_type, device_bound=False)
    assert label in guidance["summary"]
    assert "<script>" not in json.dumps(guidance)
    assert len(guidance["steps"]) == 4
    assert "Do not infer a device" in guidance["steps"][2]
    assert "not a probability of compromise" in guidance["limits"]
    assert "not an AI verdict" in guidance["limits"]


def test_exact_device_filter_preserves_aggregation_without_actor_inference(network_setup):
    database, _, _, _, _, alpha, _, _, client = network_setup
    tenant_id = str(alpha["tenant_id"])
    seed_findings(database, tenant_id)
    all_cases = client.get("/v1/dashboard/cases").json()["cases"]
    assert len(all_cases) == 4
    result = client.get("/v1/dashboard/cases", params={"device_id": "shared-mac"})
    assert result.status_code == 200
    cases = result.json()["cases"]
    assert len(cases) == 2
    assert sorted(case["alert_count"] for case in cases) == [1, 2]
    assert sum(case["recurrence_count"] for case in cases) == 1
    assert (
        client.get(
            "/v1/dashboard/cases", params={"device_id": "shared-mac", "priority": "critical"}
        ).json()["cases"][0]["priority"]
        == "critical"
    )
    for device in ["shared", "%", "_", "' OR 1=1--", "missing-mac"]:
        assert client.get("/v1/dashboard/cases", params={"device_id": device}).json() == {
            "cases": []
        }
    for device in ["", "x" * 129]:
        assert client.get("/v1/dashboard/cases", params={"device_id": device}).status_code == 400


def test_finding_details_and_shared_device_ids_remain_network_scoped(network_setup):
    database, _, accounts, _, admin, alpha, beta, _, client = network_setup
    for network, name in [(alpha, "Alpha Mac"), (beta, "Beta private Mac")]:
        seed_findings(database, str(network["tenant_id"]), name)
    repository = StandalonePresentationRepository(database)
    alpha_cases = repository.case_queue(str(alpha["tenant_id"]), device_id="shared-mac")
    case_id = alpha_cases[0]["case_id"]
    path = f"/v1/cases/{case_id}/evidence"
    response = client.get(path)
    assert response.status_code == 200
    assert "Beta private Mac" not in response.text
    assert "raw-payload-not-for-dashboard" not in response.text
    for item in response.json()["evidence"]:
        assert item["device"] == {
            "device_id": "shared-mac",
            "display_name": "Alpha Mac",
            "status": "active",
        }
        assert "linked device" in item["guidance"]["steps"][2]
    unbound = next(
        item
        for case in repository.case_queue(str(alpha["tenant_id"]))
        for item in repository.case_evidence(str(alpha["tenant_id"]), str(case["case_id"]))
        if item["event"]["device_id"] is None
    )
    assert unbound["device"] is None
    assert "No device is linked" in unbound["guidance"]["steps"][2]
    client.headers["x-network-id"] = str(beta["tenant_id"])
    beta_cases = client.get("/v1/dashboard/cases", params={"device_id": "shared-mac"}).json()
    assert len(beta_cases["cases"]) == 2
    beta_case = beta_cases["cases"][0]["case_id"]
    assert "Beta private Mac" in client.get(f"/v1/cases/{beta_case}/evidence").text
    client.cookies.set("controlforge_session", admin.token)
    assert client.get("/v1/dashboard/cases?device_id=shared-mac").status_code == 403
    assert client.get(f"/v1/cases/{beta_case}/evidence").status_code == 403
    client.headers["x-network-id"] = str(alpha["tenant_id"])
    assert client.get(path).status_code == 200
    created = accounts.create_account(admin.principal, "review", "Endpoint only", NOW)
    login = accounts.login(str(created["username"]), str(created["initial_password"]), NOW)
    client.cookies.clear()
    for route in [path, "/v1/dashboard/cases?device_id=shared-mac"]:
        assert (
            client.get(route, headers={"authorization": "Bearer " + login["token"]}).status_code
            == 401
        )


def test_investigation_javascript_scope_and_out_of_order_contract(tmp_path):
    node = shutil.which("node")
    if node is None:
        pytest.skip("Node is required for native JavaScript contract validation")
    html = dashboard_html("test", network_support=True)
    script = html.split('<script type="module" nonce="test">')[1].split("</script>")[0]
    script_path = tmp_path / "dashboard.mjs"
    script_path.write_text(script)
    subprocess.run(  # noqa: S603 - trusted executable and repository source
        [node, "--check", str(script_path)], check=True, capture_output=True
    )
    load_case = script.split("const loadCase=", 1)[1].split("const renderResponses", 1)[0]
    request_api = script.split("const api=", 1)[1].split(";const mutationHeaders=", 1)[0]
    show_operations = script.split("const showOperations=", 1)[1].split(";const saveRecovery=", 1)[
        0
    ]
    contract = Path("tests/fixtures/investigation_contract.js").read_text()
    contract = (
        contract.replace("__HELPERS__", INVESTIGATION_SCRIPT)
        .replace("__LOAD_CASE__", "const loadCase=" + load_case)
        .replace("__REQUEST_API__", "const requestApi=" + request_api)
        .replace("__SHOW_OPERATIONS__", "const showOperations=" + show_operations)
    )
    contract_path = tmp_path / "contract.mjs"
    contract_path.write_text(contract)
    result = subprocess.run(  # noqa: S603 - trusted executable and repository fixture
        [node, str(contract_path)], capture_output=True, text=True, timeout=20
    )
    assert result.returncode == 0, result.stderr
    assert "investigation contracts passed" in result.stdout
