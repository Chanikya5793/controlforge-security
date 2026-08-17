"""Plain-language connection guidance, derived only from measured device facts."""

from __future__ import annotations


def device_guidance(status: str, freshness: str, active_credentials: int) -> dict[str, object]:
    """Do not infer permissions, malware, or containment from a check-in timestamp."""
    if status == "revoked":
        title = "Device access was revoked"
        detail = "This device can no longer authenticate with its recorded credentials."
        steps = [
            "Confirm with the network admin why access was removed.",
            "Do not reinstall or create another account to bypass that decision.",
            "Revoking access does not undo a restriction already applied on the Mac.",
        ]
    elif status == "enrolling":
        title = "Finish connecting this Mac"
        detail = "Enrollment has started, but the server has not recorded an active device."
        steps = [
            "Open ControlForge on this Mac and check Account for the next setup step.",
            "If setup was interrupted, use Finish setup when offered; do not reuse a grant.",
        ]
    elif status != "active":
        title = "Device state needs review"
        detail = "This record does not establish that the Mac can currently report."
        steps = ["Ask a network admin to inspect the device record before changing its setup."]
    elif active_credentials == 0:
        title = "Device credentials need attention"
        detail = (
            "No unexpired, unrevoked device credential is recorded, even if a check-in is recent."
        )
        steps = [
            "Ask the network admin to review expiry and revocation in the detailed tools.",
            "Do not delete the app, its Keychain credentials, or retained activity to reconnect.",
            "Changing the person's password does not repair the separate collector credential.",
        ]
    elif freshness == "never_seen":
        title = "Waiting for the first check-in"
        detail = (
            "Credentials exist, but this server has not yet received an authenticated check-in."
        )
        steps = [
            "On this Mac, open ControlForge and check Account for Finish setup.",
            "In Protection, follow any displayed permission or connection instructions.",
            "Keep the Mac awake and online, then refresh this page after a collector cycle.",
        ]
    elif freshness == "stale":
        title = "Check this Mac's connection"
        detail = (
            "The last authenticated check-in is more than 15 minutes old. "
            "The Mac may be asleep or offline."
        )
        steps = [
            "Check that the Mac is awake and has a working internet or appliance connection.",
            "Open ControlForge on that Mac and read the current Protection status.",
            "If it reports a setup or delivery problem, share that message with the network admin.",
            "Keep retained activity in place; do not clear it or repeatedly reinstall.",
        ]
    elif freshness == "fresh":
        title = "Recently checked in"
        detail = "An authenticated check-in reached the server within the last 15 minutes."
        steps = [
            "No connection repair is indicated by this check-in.",
            "Review open investigations separately. Recent reporting does not mean threat-free.",
            "Use Protection on the Mac for local permissions, backlog, and Santa status.",
        ]
    else:
        title = "Check-in time cannot be verified"
        detail = "The recorded time is inconsistent with the server clock or the state is unknown."
        steps = [
            "Ask the appliance operator to check server time and the device record.",
            "Refresh after the clock or record is corrected; do not assume current reporting.",
        ]
    return {
        "title": title,
        "detail": detail,
        "steps": steps,
        "limits": (
            "This view shows server connection evidence, not a malware scan. It does not verify "
            "local permissions, Santa blocking, or the Mac's current network restrictions."
        ),
    }
