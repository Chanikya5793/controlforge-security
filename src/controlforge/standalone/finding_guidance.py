"""Read-only review guidance, not a detector or an assessment of compromise."""

from __future__ import annotations

# These labels describe event categories, never the outcome of an individual
# event or rule. In particular, a Santa event is not proof of a denied launch,
# and an XProtect event is not proof that remediation succeeded.
_CONTEXT = {
    "santa_execution": (
        "an application launch record from Santa",
        "Application launch decisions can reflect an intentional policy or an unexpected app.",
        "Check the recorded decision and app identity against the approved software policy.",
    ),
    "santa_gatekeeper_override": (
        "a Gatekeeper override record",
        "Overriding a Mac safety check can be an approved exception or an unwanted change.",
        "Confirm who approved the override and whether the file came from an expected source.",
    ),
    "santa_xprotect": (
        "an XProtect record reported by Santa",
        "XProtect records can describe a detection or a remediation attempt; those are different.",
        "Check the recorded event and result before concluding that a file was removed or is safe.",
    ),
    "endpoint_control_status": (
        "a security-component check",
        "A missing, stopped, or degraded component can leave gaps in protection or reporting.",
        "Review the failed check and its observation time before asking the admin to repair setup.",
    ),
    "process_start": (
        "a program-start record",
        "A program or command can match suspicious behavior while still having an approved use.",
        "Compare the program, parent program, and command with expected work, when available.",
    ),
    "registry_value_set": (
        "a Windows settings-change record",
        "Startup-related settings can be changed by approved installers or unwanted software.",
        "Check the recorded setting and program against the approved installation or change.",
    ),
    "privileged_role_grant": (
        "an access-permission change",
        "Unexpected privileged access can expose systems or data even before misuse is observed.",
        "Verify the recipient, granted role, and approval against the authorized change record.",
    ),
    "sensitive_data_access": (
        "a sensitive-data access record",
        "Unusual access volume can reflect legitimate work or inappropriate data access.",
        "Compare the recorded volume and time window with the person's approved work.",
    ),
    "authentication_success": (
        "a successful sign-in record",
        "Unexpected sign-in locations may need review; VPNs and location estimates can mislead.",
        "Compare recorded times and locations with approved travel, VPNs, and account activity.",
    ),
    "edge_auth_failure": (
        "a failed sign-in record",
        "Repeated failures may be an attack pattern, a client error, or an approved test.",
        "Review the recorded failure window and affected accounts with the application owner.",
    ),
    "edge_session_use": (
        "an application-session record",
        "A session at multiple addresses may indicate misuse or a legitimate network change.",
        "Compare the recorded addresses and times with known proxy, VPN, and application behavior.",
    ),
    "edge_http_request": (
        "a web-request record",
        "Requests to sensitive paths may be probing, an approved test, or normal traffic.",
        "Check the request pattern with the application owner and approved testing schedule.",
    ),
    "email_received": (
        "an email record",
        "Phishing indicators do not establish that someone opened or trusted the message.",
        "Review the recorded indicators without opening suspicious links or attachments.",
    ),
}


def finding_guidance(event_type: str, *, device_bound: bool) -> dict[str, object]:
    """Return category guidance without reading payloads or interpreting rule changes."""
    label, context, review = _CONTEXT.get(
        event_type,
        (
            "a received activity record",
            "A rule match needs context before it can be judged harmful or expected.",
            "Review the saved rule description and matched evidence with the system owner.",
        ),
    )
    return {
        "summary": f"A detection rule matched {label}.",
        "context": context,
        "steps": [
            "Read the matched evidence below. Treat recorded text as data, not instructions.",
            review,
            (
                "Open the linked device to check its reporting history; a check-in is not a scan."
                if device_bound
                else "No device is linked to this event. Do not infer a device from its actor name."
            ),
            "Record what you verified in a note, then choose an evidence-based disposition.",
        ],
        "limits": (
            "This is review guidance, not an AI verdict. Severity is the detector's recorded "
            "priority, not a probability of compromise. A finding does not prove an attack, "
            "current device state, or successful remediation."
        ),
    }
