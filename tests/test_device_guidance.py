from __future__ import annotations

import pytest

from controlforge.standalone.device_guidance import device_guidance
from controlforge.standalone.network_dashboard import network_dashboard_html


@pytest.mark.parametrize(
    ("status", "freshness", "credentials", "title"),
    [
        ("revoked", "fresh", 1, "Device access was revoked"),
        ("enrolling", "fresh", 1, "Finish connecting this Mac"),
        ("invalid", "fresh", 1, "Device state needs review"),
        ("active", "fresh", 0, "Device credentials need attention"),
        ("active", "never_seen", 1, "Waiting for the first check-in"),
        ("active", "stale", 1, "Check this Mac's connection"),
        ("active", "fresh", 1, "Recently checked in"),
        ("active", "clock_skew", 1, "Check-in time cannot be verified"),
        ("active", "unknown", 1, "Check-in time cannot be verified"),
    ],
)
def test_guidance_is_bounded_and_does_not_infer_protection(status, freshness, credentials, title):
    result = device_guidance(status, freshness, credentials)
    assert result["title"] == title
    assert 1 <= len(result["steps"]) <= 4
    assert "not a malware scan" in result["limits"]
    assert "Santa blocking" in result["limits"]
    assert "https://" not in str(result)


def test_guidance_preserves_collector_and_does_not_prescribe_password_workaround():
    stale = device_guidance("active", "stale", 1)
    assert "do not clear" in str(stale["steps"])
    missing = device_guidance("active", "fresh", 0)
    assert "does not repair" in str(missing["steps"])
    revoked = device_guidance("revoked", "revoked", 0)
    assert "does not undo a restriction" in str(revoked["steps"])


def test_device_dialog_uses_current_scoped_evidence_and_safe_text_rendering():
    html = network_dashboard_html("test-device-guidance-nonce")
    for contract in (
        'aria-labelledby="device-title"',
        'id="device-content" aria-live="polite"',
        "Active device records",
        "Connection details for ",
        "/v1/dashboard/devices/",
        "encodeURIComponent(deviceId)",
        "scope!==selected",
        "new AbortController()",
        "clearTimeout(timeout)",
        "Current evidence is unavailable",
        "This view is not a complete fleet health assessment",
        "#system-workspace",
        "if(!hasIssue&&!devices.devices.length",
    ):
        assert contract in html
    assert "innerHTML" not in html
    assert "devices.devices=devices.devices.filter" not in html


def test_network_console_dialogs_have_accessible_names():
    html = network_dashboard_html("test-dialog-accessibility-nonce")
    for dialog_name in (
        "network",
        "routing",
        "person",
        "invite",
        "reset",
        "settings",
        "namespace",
        "account-settings",
        "member",
        "cancel-invite",
        "secret",
        "device",
    ):
        assert f'<dialog id="{dialog_name}-dialog" aria-labelledby="{dialog_name}-title">' in html
    assert ".subtle-link{display:inline-flex;align-items:center;min-height:44px}" in html
    assert ".skip:focus{display:inline-flex;align-items:center;min-height:44px}" in html
    assert "button:focus-visible,a:focus-visible,input:focus-visible,select:focus-visible" in html
    assert '<a class="skip" href="#main">Skip to main content</a>' in html
