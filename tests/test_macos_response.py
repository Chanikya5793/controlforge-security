from __future__ import annotations

import json
import os
import stat
import subprocess
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Callable, Optional

import pytest
from pydantic import ValidationError

from controlforge.collector_agent import (
    ActionBatch,
    AgentSpool,
    CollectorDefinition,
    EndpointCollectorAgent,
    SignedControlForgeClient,
    load_collector_definition,
)
from controlforge.macos_response import (
    CONTROLFORGE_ANCHOR,
    PFCTL,
    FixedPfctlRunner,
    MacOSContainmentStatus,
    MacOSPfResponseAdapter,
    MacOSPfState,
    MacOSReconciliationEvent,
    MacOSResponseAction,
    MacOSResponseError,
    MacOSResponseResult,
    PfctlCommandError,
    PfStateStore,
    RootOwnedPfStateStore,
)

NOW = datetime(2026, 8, 22, 12, 0, tzinfo=timezone.utc)
DEVICE_ID = "device-test-1"
ACTION_ID = "2cda0154-59b1-4a66-8955-b8068fb0c33c"
ENABLE = (PFCTL, "-E")
LOAD = (PFCTL, "-a", CONTROLFORGE_ANCHOR, "-f", "-")
FLUSH = (PFCTL, "-a", CONTROLFORGE_ANCHOR, "-F", "all")
RELEASE = (PFCTL, "-X", "42")


class FakeRunner:
    def __init__(self) -> None:
        self.calls: list[tuple[tuple[str, ...], Optional[str]]] = []
        self.fail: set[tuple[str, ...]] = set()

    def run(self, arguments, rules=None):  # type: ignore[no-untyped-def]
        fixed = tuple(arguments)
        self.calls.append((fixed, rules))
        if fixed in self.fail:
            raise PfctlCommandError("fake failure")
        return "pf enabled\nToken : 42\n" if fixed == ENABLE else ""


class FakeResolver:
    def __init__(self, addresses: tuple[str, ...] = ("192.0.2.10", "2001:db8::10")) -> None:
        self.addresses = addresses
        self.calls: list[tuple[str, int]] = []

    def resolve(self, host: str, port: int) -> tuple[str, ...]:
        self.calls.append((host, port))
        if not self.addresses:
            raise MacOSResponseError("management_resolution_failed")
        return self.addresses


class DeleteFailingStore:
    def __init__(self, delegate: RootOwnedPfStateStore) -> None:
        self.delegate = delegate

    def read(self) -> Optional[MacOSPfState]:
        return self.delegate.read()

    def write(self, state: MacOSPfState) -> None:
        self.delegate.write(state)

    def delete(self) -> None:
        raise MacOSResponseError("state_release_failed")


class WriteFailingStore(DeleteFailingStore):
    def write(self, state: MacOSPfState) -> None:
        raise MacOSResponseError("state_persistence_failed")


class PostWriteFailingStore(DeleteFailingStore):
    def write(self, state: MacOSPfState) -> None:
        self.delegate.write(state)
        raise MacOSResponseError("state_persistence_failed")

    def delete(self) -> None:
        self.delegate.delete()


def active_action(
    action_type: str = "isolate_endpoint",
    *,
    target_id: str = DEVICE_ID,
    expires_at: datetime = NOW + timedelta(hours=1),
) -> MacOSResponseAction:
    return MacOSResponseAction.model_validate(
        {
            "action_id": ACTION_ID,
            "action_type": action_type,
            "target_type": "device",
            "target_id": target_id,
            "rationale": "Two responders approved bounded endpoint containment.",
            "risk_level": "active",
            "expires_at": expires_at,
        }
    )


def adapter(
    tmp_path: Path,
    runner: FakeRunner,
    *,
    enabled: bool = True,
    clock: Callable[[], datetime] = lambda: NOW,
    system: Callable[[], str] = lambda: "Darwin",
    euid: Callable[[], int] = lambda: 0,
    resolver: Optional[FakeResolver] = None,
    state_store: Optional[PfStateStore] = None,
) -> MacOSPfResponseAdapter:
    return MacOSPfResponseAdapter(
        enabled=enabled,
        device_id=DEVICE_ID,
        api_host="standalone.example.com",
        api_port=8443,
        state_path=tmp_path / "response" / "pf-state.json",
        runner=runner,
        resolver=resolver or FakeResolver(),
        clock=clock,
        system=system,
        euid=euid,
        state_expected_uid=os.geteuid(),
        state_store=state_store,
    )


def test_isolate_and_release_use_only_fixed_pf_anchor_and_token(tmp_path: Path) -> None:
    runner = FakeRunner()
    response = adapter(tmp_path, runner)
    assert response.containment_status() == MacOSContainmentStatus("released")

    isolated = response.execute(active_action())

    assert isolated.succeeded is True
    assert isolated.state == "isolated"
    assert [call[0] for call in runner.calls] == [ENABLE, LOAD]
    rules = runner.calls[1][1]
    assert rules is not None
    assert "block drop all" in rules
    assert "pass quick on lo0 all" in rules
    assert "proto udp to any port 53" in rules
    assert "to 192.0.2.10 port 8443" in rules
    assert "to 2001:db8::10 port 8443" in rules
    assert "/etc/pf.conf" not in rules
    state_path = tmp_path / "response" / "pf-state.json"
    state = json.loads(state_path.read_text(encoding="utf-8"))
    assert set(state) == {"pf_token", "expires_at", "management_ips"}
    assert state["pf_token"] == "42"  # noqa: S105 - PF reference, not a password
    assert datetime.fromisoformat(state["expires_at"].replace("Z", "+00:00")) == NOW + timedelta(
        minutes=15
    )
    assert stat.S_IMODE(state_path.stat().st_mode) == 0o600
    assert response.containment_status() == MacOSContainmentStatus(
        "isolated",
        NOW + timedelta(minutes=15),
    )

    calls_after_first_isolate = list(runner.calls)
    repeated = response.execute(active_action())
    assert repeated.state == "unchanged"
    assert runner.calls == calls_after_first_isolate

    released = response.execute(active_action("release_endpoint"))
    assert released.state == "released"
    assert [call[0] for call in runner.calls[-2:]] == [FLUSH, RELEASE]
    assert not state_path.exists()
    assert response.containment_status() == MacOSContainmentStatus("released")
    calls_after_release = list(runner.calls)
    assert response.execute(active_action("release_endpoint")).state == "unchanged"
    assert runner.calls == calls_after_release


def test_uninstall_release_works_while_new_containment_is_disabled(tmp_path: Path) -> None:
    runner = FakeRunner()
    assert adapter(tmp_path, runner, enabled=False).containment_status() == MacOSContainmentStatus(
        "not_configured"
    )
    enabled = adapter(tmp_path, runner)
    enabled.execute(active_action())
    disabled = adapter(tmp_path, runner, enabled=False)

    result = disabled.release_owned_state_for_uninstall()

    assert result.succeeded is True
    assert result.state == "released"
    assert [call[0] for call in runner.calls[-2:]] == [FLUSH, RELEASE]
    assert not (tmp_path / "response" / "pf-state.json").exists()


@pytest.mark.parametrize(
    ("enabled", "system", "euid", "code"),
    [
        (False, lambda: "Darwin", lambda: 0, "adapter_disabled"),
        (True, lambda: "Linux", lambda: 0, "unsupported_platform"),
        (True, lambda: "Darwin", lambda: 501, "root_required"),
    ],
)
def test_environment_gates_fail_before_any_pf_command(
    tmp_path: Path,
    enabled: bool,
    system: Callable[[], str],
    euid: Callable[[], int],
    code: str,
) -> None:
    runner = FakeRunner()
    response = adapter(tmp_path, runner, enabled=enabled, system=system, euid=euid)

    with pytest.raises(MacOSResponseError) as error:
        response.execute(active_action())

    assert error.value.code == code
    assert runner.calls == []


@pytest.mark.parametrize(
    ("host", "port"),
    [
        ("https://standalone.example.com", 443),
        ("standalone.example.com\nblock all", 443),
        ("standalone.example.com", 0),
        ("standalone.example.com", 65_536),
        ("standalone.example.com", True),
    ],
)
def test_adapter_rejects_untrusted_management_host_or_port(
    tmp_path: Path,
    host: str,
    port: object,
) -> None:
    with pytest.raises(ValueError, match="API"):
        MacOSPfResponseAdapter(
            enabled=True,
            device_id=DEVICE_ID,
            api_host=host,
            api_port=port,  # type: ignore[arg-type]
            state_path=tmp_path / "state.json",
        )


def test_wrong_device_expired_and_malformed_actions_never_run_pf(tmp_path: Path) -> None:
    runner = FakeRunner()
    response = adapter(tmp_path, runner)

    with pytest.raises(MacOSResponseError) as wrong_device:
        response.execute(active_action(target_id="another-device"))
    assert wrong_device.value.code == "target_mismatch"
    with pytest.raises(MacOSResponseError) as expired:
        response.execute(active_action(expires_at=NOW))
    assert expired.value.code == "action_expired"
    assert runner.calls == []

    base = active_action().model_dump(mode="json")
    for update in (
        {"action_type": "run_shell"},
        {"risk_level": "read_only"},
        {"target_type": "user"},
        {"expires_at": "2026-08-22T12:00:00"},
        {"provider_payload": "must-be-rejected"},
    ):
        with pytest.raises(ValidationError):
            MacOSResponseAction.model_validate({**base, **update})


def test_dns_failure_and_rule_load_failure_never_leave_unowned_state(tmp_path: Path) -> None:
    runner = FakeRunner()
    no_dns = adapter(tmp_path, runner, resolver=FakeResolver(()))
    with pytest.raises(MacOSResponseError) as resolution_error:
        no_dns.execute(active_action())
    assert resolution_error.value.code == "management_resolution_failed"
    assert runner.calls == []

    runner.fail.add(LOAD)
    response = adapter(tmp_path, runner)
    with pytest.raises(MacOSResponseError) as load_error:
        response.execute(active_action())
    assert load_error.value.code == "pf_command_failed"
    assert [call[0] for call in runner.calls] == [ENABLE, LOAD, FLUSH, RELEASE]
    assert not (tmp_path / "response" / "pf-state.json").exists()

    injection_runner = FakeRunner()
    injected = adapter(
        tmp_path / "injected",
        injection_runner,
        resolver=FakeResolver(("192.0.2.10\npass all",)),
    )
    with pytest.raises(MacOSResponseError) as injection_error:
        injected.execute(active_action())
    assert injection_error.value.code == "management_resolution_failed"
    assert injection_runner.calls == []


def test_failed_partial_rollback_preserves_pf_token_for_recovery(tmp_path: Path) -> None:
    runner = FakeRunner()
    runner.fail.update({LOAD, RELEASE})
    response = adapter(tmp_path, runner)

    with pytest.raises(MacOSResponseError) as error:
        response.execute(active_action())

    assert error.value.code == "pf_command_failed"
    retained = RootOwnedPfStateStore(
        tmp_path / "response" / "pf-state.json",
        expected_uid=os.geteuid(),
    ).read()
    assert retained is not None
    assert retained.pf_token == "42"  # noqa: S105 - PF reference, not a password


def test_state_persistence_failure_rolls_back_loaded_anchor(tmp_path: Path) -> None:
    runner = FakeRunner()
    delegate = RootOwnedPfStateStore(
        tmp_path / "response" / "pf-state.json",
        expected_uid=os.geteuid(),
    )
    response = adapter(
        tmp_path,
        runner,
        state_store=WriteFailingStore(delegate),
    )

    with pytest.raises(MacOSResponseError) as error:
        response.execute(active_action())

    assert error.value.code == "state_persistence_failed"
    assert [call[0] for call in runner.calls] == [ENABLE, LOAD, FLUSH, RELEASE]


def test_post_replace_state_fsync_failure_rolls_back_and_removes_only_new_state(
    tmp_path: Path,
) -> None:
    runner = FakeRunner()
    state_path = tmp_path / "response" / "pf-state.json"
    delegate = RootOwnedPfStateStore(state_path, expected_uid=os.geteuid())
    response = adapter(
        tmp_path,
        runner,
        state_store=PostWriteFailingStore(delegate),
    )

    with pytest.raises(MacOSResponseError) as error:
        response.execute(active_action())

    assert error.value.code == "state_persistence_failed"
    assert [call[0] for call in runner.calls] == [ENABLE, LOAD, FLUSH, RELEASE]
    assert not state_path.exists()


def test_state_store_removes_replaced_state_when_parent_fsync_fails(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    state_path = tmp_path / "response" / "pf-state.json"
    store = RootOwnedPfStateStore(state_path, expected_uid=os.geteuid())
    monkeypatch.setattr(
        store,
        "_fsync_parent",
        lambda: (_ for _ in ()).throw(OSError("fake fsync failure")),
    )

    with pytest.raises(MacOSResponseError) as error:
        store.write(
            MacOSPfState(
                pf_token="42",  # noqa: S106 - PF reference, not a password
                expires_at=NOW + timedelta(minutes=1),
                management_ips=["192.0.2.10"],
            )
        )

    assert error.value.code == "state_persistence_failed"
    assert not state_path.exists()


def test_release_state_deletion_failure_reports_failure_and_keeps_recovery_state(
    tmp_path: Path,
) -> None:
    runner = FakeRunner()
    delegate = RootOwnedPfStateStore(
        tmp_path / "response" / "pf-state.json",
        expected_uid=os.geteuid(),
    )
    response = adapter(
        tmp_path,
        runner,
        state_store=DeleteFailingStore(delegate),
    )
    response.execute(active_action())

    with pytest.raises(MacOSResponseError) as error:
        response.execute(active_action("release_endpoint"))

    assert error.value.code == "release_failed"
    assert [call[0] for call in runner.calls[-2:]] == [FLUSH, RELEASE]
    retained = delegate.read()
    assert retained is not None
    assert retained.pf_token == "42"  # noqa: S105 - PF reference, not a password

    runner.fail.add(RELEASE)
    with pytest.raises(MacOSResponseError) as retry_error:
        response.execute(active_action("release_endpoint"))
    assert retry_error.value.code == "release_failed"
    assert delegate.read() is not None


def test_failed_release_keeps_state_for_expiry_reconciliation(tmp_path: Path) -> None:
    current_time = [NOW]
    runner = FakeRunner()
    response = adapter(tmp_path, runner, clock=lambda: current_time[0])
    response.execute(active_action(expires_at=NOW + timedelta(minutes=1)))
    current_time[0] = NOW + timedelta(minutes=2)
    runner.fail.add(RELEASE)

    failed = response.reconcile()

    assert failed is not None
    assert failed.state == "release_failed"
    assert (tmp_path / "response" / "pf-state.json").exists()

    runner.fail.clear()
    released = response.reconcile()
    assert released is not None
    assert released.state == "released"
    assert released.reason == "containment_expired"
    assert not (tmp_path / "response" / "pf-state.json").exists()


def test_disabling_adapter_cannot_abandon_owned_expired_containment(tmp_path: Path) -> None:
    current_time = [NOW]
    runner = FakeRunner()
    enabled = adapter(tmp_path, runner, clock=lambda: current_time[0])
    enabled.execute(active_action(expires_at=NOW + timedelta(minutes=1)))
    current_time[0] = NOW + timedelta(minutes=2)
    disabled = adapter(
        tmp_path,
        runner,
        enabled=False,
        clock=lambda: current_time[0],
    )

    transition = disabled.reconcile()

    assert transition is not None
    assert transition.state == "released"
    assert [call[0] for call in runner.calls[-2:]] == [FLUSH, RELEASE]
    assert not (tmp_path / "response" / "pf-state.json").exists()
    with pytest.raises(MacOSResponseError) as isolate_error:
        disabled.execute(active_action(expires_at=current_time[0] + timedelta(minutes=1)))
    assert isolate_error.value.code == "adapter_disabled"


def test_state_store_rejects_symlink_weak_mode_and_extra_material(tmp_path: Path) -> None:
    state_path = tmp_path / "response" / "pf-state.json"
    store = RootOwnedPfStateStore(state_path, expected_uid=os.geteuid())
    state = MacOSPfState(
        pf_token="42",  # noqa: S106 - PF reference, not a password
        expires_at=NOW + timedelta(minutes=1),
        management_ips=["192.0.2.10"],
    )
    store.write(state)
    state_path.chmod(0o644)
    with pytest.raises(MacOSResponseError) as weak:
        store.read()
    assert weak.value.code == "state_unsafe"

    state_path.unlink()
    target = tmp_path / "other-state"
    target.write_text(state.model_dump_json(), encoding="utf-8")
    target.chmod(0o600)
    state_path.symlink_to(target)
    with pytest.raises(MacOSResponseError) as symlink:
        store.read()
    assert symlink.value.code == "state_unsafe"

    state_path.unlink()
    state_path.write_text(
        json.dumps({**state.model_dump(mode="json"), "device_id": DEVICE_ID}, default=str),
        encoding="utf-8",
    )
    state_path.chmod(0o600)
    with pytest.raises(MacOSResponseError) as malformed:
        store.read()
    assert malformed.value.code == "state_malformed"

    runner = FakeRunner()
    response = adapter(tmp_path, runner)
    transition = response.reconcile()
    assert transition is not None
    assert transition.state == "state_invalid"
    assert response.containment_status() == MacOSContainmentStatus("needs_attention")
    assert runner.calls == []


def test_fixed_runner_never_uses_a_shell_and_rejects_other_argv(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    calls: list[tuple[tuple[str, ...], dict[str, object]]] = []

    def fake_run(arguments, **kwargs):  # type: ignore[no-untyped-def]
        calls.append((arguments, kwargs))
        return subprocess.CompletedProcess(arguments, 0, stdout="Token : 42\n", stderr="")

    monkeypatch.setattr("controlforge.macos_response.subprocess.run", fake_run)
    runner = FixedPfctlRunner()
    assert runner.run(ENABLE) == "Token : 42\n"
    assert calls[0][0] == ENABLE
    assert "shell" not in calls[0][1]

    for arguments in (
        (PFCTL, "-f", "/etc/pf.conf"),
        (PFCTL, "-a", "other/anchor", "-F", "all"),
        ("/bin/sh", "-c", "pfctl -d"),
        (PFCTL, "-X", "42; pfctl -d"),
    ):
        with pytest.raises(ValueError, match="allowlisted"):
            runner.run(arguments)


class CollectorTransport:
    def __init__(self, actions: list[dict[str, object]]) -> None:
        self.actions = actions
        self.requests: list[tuple[str, str, bytes]] = []

    def request(self, method, path, headers, body, timeout_seconds):  # type: ignore[no-untyped-def]
        self.requests.append((method, path, body))
        if method == "GET":
            return 200, json.dumps({"actions": self.actions}).encode()
        return 200, b'{"ok":true}'


class CollectorResponseAdapter:
    def __init__(self, transition: Optional[MacOSReconciliationEvent] = None) -> None:
        self.transition = transition
        self.actions: list[MacOSResponseAction] = []

    def reconcile(self) -> Optional[MacOSReconciliationEvent]:
        transition = self.transition
        self.transition = None
        return transition

    def execute(self, action: MacOSResponseAction) -> MacOSResponseResult:
        self.actions.append(action)
        return MacOSResponseResult(
            True,
            "isolated",
            "Endpoint network containment applied.",
            ("macos-pf-anchor:isolated", "management-addresses:1"),
        )

    def containment_status(self) -> MacOSContainmentStatus:
        return MacOSContainmentStatus("isolated", NOW + timedelta(minutes=15))


def collector_definition(project_root: Path, tmp_path: Path) -> CollectorDefinition:
    return CollectorDefinition(
        api_host="standalone.example.com",
        api_port=8443,
        device_id=DEVICE_ID,
        controls_path=project_root / "config" / "agents.yml",
        spool_path=tmp_path / "spool.db",
        status_snapshot_path=tmp_path / "status" / "agent-status.json",
        action_polling_enabled=True,
        response_adapter_enabled=True,
        access_proxy_required=False,
    )


def test_collector_submits_bounded_active_result_and_automatic_release_event(
    project_root: Path,
    tmp_path: Path,
) -> None:
    action = active_action(expires_at=datetime.now(timezone.utc) + timedelta(minutes=5))
    transport = CollectorTransport([action.model_dump(mode="json")])
    definition = collector_definition(project_root, tmp_path)
    client = SignedControlForgeClient(
        definition,
        "3970e11f-f87c-4e14-9a90-d574cd2bcd95",
        "s" * 48,
        transport=transport,
    )
    response = CollectorResponseAdapter(
        MacOSReconciliationEvent(
            datetime.now(timezone.utc),
            "released",
            "containment_expired",
        )
    )

    result = EndpointCollectorAgent(
        definition,
        client,
        AgentSpool(definition.spool_path),
        response_adapter=response,
    ).run_once()

    assert result["actions_processed"] == 1
    assert len(response.actions) == 1
    ingest_body = json.loads(transport.requests[0][2])
    containment_events = [
        event
        for event in ingest_body["events"]
        if event["event_type"] == "endpoint_containment_state"
    ]
    assert containment_events[0]["attributes"] == {
        "adapter": "macos_pf",
        "reason": "containment_expired",
        "state": "released",
    }
    result_body = json.loads(transport.requests[-1][2])
    assert result_body == {
        "status": "succeeded",
        "summary": "Endpoint network containment applied.",
        "evidence": ["macos-pf-anchor:isolated", "management-addresses:1"],
    }
    serialized = json.dumps(result_body)
    assert action.rationale not in serialized
    status_path = definition.status_snapshot_path
    assert status_path is not None
    local_status = json.loads(status_path.read_text(encoding="utf-8"))
    assert local_status["containment"] == {
        "state": "isolated",
        "expires_at": (NOW + timedelta(minutes=15)).isoformat().replace("+00:00", "Z"),
    }
    assert action.action_id not in json.dumps(local_status)
    assert action.rationale not in json.dumps(local_status)


def test_collector_spools_automatic_release_before_unrelated_probe_failure(
    project_root: Path,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    definition = collector_definition(project_root, tmp_path)
    transport = CollectorTransport([])
    client = SignedControlForgeClient(
        definition,
        "3970e11f-f87c-4e14-9a90-d574cd2bcd95",
        "s" * 48,
        transport=transport,
    )
    response = CollectorResponseAdapter(
        MacOSReconciliationEvent(NOW, "released", "containment_expired")
    )
    spool = AgentSpool(definition.spool_path)
    agent = EndpointCollectorAgent(
        definition,
        client,
        spool,
        response_adapter=response,
    )
    monkeypatch.setattr(
        agent,
        "_control_report",
        lambda: (_ for _ in ()).throw(RuntimeError("unrelated probe failed")),
    )

    with pytest.raises(RuntimeError, match="unrelated probe failed"):
        agent.run_once()

    pending = spool.pending()
    assert len(pending) == 1
    assert pending[0][1][0].event_type == "endpoint_containment_state"
    assert pending[0][1][0].attributes == {
        "adapter": "macos_pf",
        "reason": "containment_expired",
        "state": "released",
    }


def test_collector_reconciles_owned_state_after_adapter_config_is_disabled(
    project_root: Path,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    state_path = tmp_path / "response" / "pf-state.json"
    state_path.parent.mkdir(mode=0o700)
    state_path.write_text("owned-state-placeholder", encoding="utf-8")
    state_path.chmod(0o600)
    definition = collector_definition(project_root, tmp_path).model_copy(
        update={
            "action_polling_enabled": False,
            "response_adapter_enabled": False,
            "response_state_path": state_path,
        }
    )
    transport = CollectorTransport([])
    client = SignedControlForgeClient(
        definition,
        "3970e11f-f87c-4e14-9a90-d574cd2bcd95",
        "s" * 48,
        transport=transport,
    )
    constructed: list[dict[str, object]] = []

    def fake_adapter(**kwargs):  # type: ignore[no-untyped-def]
        constructed.append(kwargs)
        return CollectorResponseAdapter(
            MacOSReconciliationEvent(NOW, "released", "containment_expired")
        )

    monkeypatch.setattr("controlforge.collector_agent.MacOSPfResponseAdapter", fake_adapter)

    EndpointCollectorAgent(
        definition,
        client,
        AgentSpool(definition.spool_path),
    ).run_once()

    assert constructed[0]["enabled"] is False
    ingested = [
        event
        for method, path, body in transport.requests
        if method == "POST" and path == "/v1/ingest/events"
        for event in json.loads(body)["events"]
    ]
    assert any(event["event_type"] == "endpoint_containment_state" for event in ingested)


def test_action_batch_rejects_extra_unknown_type_wrong_risk_and_naive_expiry() -> None:
    valid = {
        "action_id": ACTION_ID,
        "action_type": "isolate_endpoint",
        "target_type": "device",
        "target_id": DEVICE_ID,
        "rationale": "approved",
        "risk_level": "active",
        "expires_at": "2026-08-22T12:05:00Z",
    }
    read_only = ActionBatch.model_validate(
        {
            "actions": [
                {
                    **valid,
                    "action_type": "collect_diagnostics",
                    "risk_level": "read_only",
                }
            ]
        }
    )
    assert read_only.actions[0].action_type == "collect_diagnostics"
    for update in (
        {"action_type": "arbitrary_shell"},
        {"risk_level": "read_only"},
        {"target_type": "identity"},
        {"expires_at": "2026-08-22T12:05:00"},
        {"raw_provider": "secret"},
    ):
        with pytest.raises(ValidationError):
            ActionBatch.model_validate({"actions": [{**valid, **update}]})


def test_production_collector_config_keeps_response_adapter_disabled(project_root: Path) -> None:
    definition = load_collector_definition(project_root / "config" / "collector.yml")

    assert definition.response_adapter_enabled is False
    assert definition.response_state_path == Path(
        "/Library/Application Support/ControlForge/response/pf-state.json"
    )
