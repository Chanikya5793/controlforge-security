import json
import os
from pathlib import Path

import pytest

from controlforge.santa import (
    SantaJsonLogReader,
    SantaLogDefinition,
    SantaLogError,
)


def write_records(path: Path, *records: object) -> None:
    path.write_bytes(b"".join(json.dumps(record).encode() + b"\n" for record in records))
    path.chmod(0o600)


def execution_record(event_id: str = "1" * 32) -> dict[str, object]:
    return {
        "machine_id": "private-machine-id",
        "event_time": "2026-08-18T12:00:00.123456Z",
        "processed_time": "2026-08-18T12:00:00.234567Z",
        "boot_session_uuid": "E96C5079-BD05-4321-ABCD-0123456789AB",
        "event_id": event_id,
        "execution": {
            "instigator": {"executable": {"path": "/usr/bin/open"}},
            "target": {
                "effective_user": {"name": "analyst@example.com"},
                "executable": {
                    "path": "/private/tmp/untrusted-tool",
                    "hash": {"type": "HASH_ALGO_SHA256", "hash": "a" * 64},
                },
                "code_signature": {"signing_id": "org.example.tool", "team_id": "TEAM123456"},
                "is_platform_binary": False,
            },
            "decision": "DECISION_DENY",
            "reason": "REASON_BINARY",
            "mode": "MODE_LOCKDOWN",
            "args": ["--secret", "never-persist-this"],
            "envs": ["TOKEN=never-persist-this"],
            "fds": [{"fd": 3}],
            "entitlements": [{"key": "sensitive"}],
        },
    }


def reader(path: Path, **limits: int) -> SantaJsonLogReader:
    return SantaJsonLogReader(
        SantaLogDefinition(enabled=True, log_path=path, **limits),
        "macbook-air-1",
    )


def test_reads_execution_and_excludes_high_risk_process_context(tmp_path: Path) -> None:
    log_path = tmp_path / "santa.jsonl"
    write_records(log_path, execution_record())

    batch = reader(log_path).read(None)

    assert batch.rejected_lines == 0
    assert len(batch.events) == 1
    event = batch.events[0]
    assert event.event_id == f"santa:{'1' * 32}"
    assert event.event_type == "santa_execution"
    assert event.actor == "user:analyst@example.com"
    assert event.target == "/private/tmp/untrusted-tool"
    assert event.device_id == "macbook-air-1"
    assert event.attributes["decision"] == "DECISION_DENY"
    assert event.attributes["file_sha256"] == "a" * 64
    serialized = event.model_dump_json()
    assert "never-persist-this" not in serialized
    assert '"args"' not in serialized
    assert '"envs"' not in serialized
    assert '"fds"' not in serialized
    assert '"entitlements"' not in serialized


def test_accepts_santa_nanosecond_timestamps_at_python_microsecond_precision(
    tmp_path: Path,
) -> None:
    log_path = tmp_path / "santa.jsonl"
    record = execution_record()
    record["event_time"] = "2026-08-18T12:00:00.123456789Z"
    write_records(log_path, record)

    batch = reader(log_path).read(None)

    assert batch.rejected_lines == 0
    assert len(batch.events) == 1
    assert batch.events[0].timestamp.isoformat() == "2026-08-18T12:00:00.123456+00:00"


def test_cursor_avoids_duplicates_and_handles_rotation(tmp_path: Path) -> None:
    log_path = tmp_path / "santa.jsonl"
    write_records(log_path, execution_record("1" * 32))
    santa_reader = reader(log_path)
    first = santa_reader.read(None)

    assert santa_reader.read(first.cursor).events == []
    rotated_path = tmp_path / "santa.old.jsonl"
    log_path.rename(rotated_path)
    write_records(log_path, execution_record("2" * 32))
    rotated = santa_reader.read(first.cursor)

    assert [event.event_id for event in rotated.events] == [f"santa:{'2' * 32}"]
    assert rotated.cursor.inode != first.cursor.inode


def test_rejects_malformed_records_but_advances_past_complete_lines(tmp_path: Path) -> None:
    log_path = tmp_path / "santa.jsonl"
    log_path.write_bytes(b"not-json\n" + json.dumps(execution_record()).encode() + b"\n")
    log_path.chmod(0o600)

    batch = reader(log_path).read(None)

    assert batch.rejected_lines == 1
    assert len(batch.events) == 1
    assert batch.cursor.byte_offset == log_path.stat().st_size


def test_leaves_partial_last_line_for_the_next_run(tmp_path: Path) -> None:
    log_path = tmp_path / "santa.jsonl"
    complete = json.dumps(execution_record("1" * 32)).encode() + b"\n"
    partial = json.dumps(execution_record("2" * 32)).encode()
    log_path.write_bytes(complete + partial)
    log_path.chmod(0o600)

    first = reader(log_path).read(None)
    assert [event.event_id for event in first.events] == [f"santa:{'1' * 32}"]
    assert first.cursor.byte_offset == len(complete)

    with log_path.open("ab") as stream:
        stream.write(b"\n")
    second = reader(log_path).read(first.cursor)
    assert [event.event_id for event in second.events] == [f"santa:{'2' * 32}"]


def test_rejects_oversize_or_unsafe_log_files(tmp_path: Path) -> None:
    log_path = tmp_path / "santa.jsonl"
    log_path.write_bytes(b"{" + b"x" * 2_000 + b"}\n")
    log_path.chmod(0o600)
    with pytest.raises(SantaLogError, match="exceeds"):
        reader(log_path, max_line_bytes=1_024).read(None)

    log_path.chmod(0o622)
    with pytest.raises(SantaLogError, match="group or world writable"):
        reader(log_path).read(None)

    link_path = tmp_path / "santa-link.jsonl"
    os.symlink(log_path, link_path)
    with pytest.raises(SantaLogError, match="regular file"):
        reader(link_path).read(None)


def test_normalizes_gatekeeper_launch_item_tcc_and_xprotect(tmp_path: Path) -> None:
    log_path = tmp_path / "santa.jsonl"
    common = {"event_time": "2026-08-18T12:00:00Z", "boot_session_uuid": "boot"}
    write_records(
        log_path,
        {
            **common,
            "event_id": "2" * 32,
            "gatekeeper_override": {
                "instigator": {"executable": {"path": "/usr/bin/xattr"}},
                "target": {"path": "/Applications/Unknown.app"},
                "code_signature": {"team_id": "UNTRUSTED01"},
            },
        },
        {
            **common,
            "event_id": "3" * 32,
            "launch_item": {
                "action": "ACTION_ADD",
                "item_type": "ITEM_TYPE_DAEMON",
                "item_path": "/Library/LaunchDaemons/org.example.agent.plist",
                "managed": False,
            },
        },
        {
            **common,
            "event_id": "4" * 32,
            "tcc_modification": {
                "service": "kTCCServiceSystemPolicyAllFiles",
                "identity": "org.example.agent",
                "event_type": "EVENT_TYPE_CREATE",
                "authorization_right": "AUTHORIZATION_RIGHT_ALLOWED",
            },
        },
        {
            **common,
            "event_id": "5" * 32,
            "xprotect": {
                "detected": {
                    "malware_identifier": "OSX.Test.Malware",
                    "incident_identifier": "incident-1",
                    "detected_path": "/private/tmp/test-malware",
                }
            },
        },
    )

    events = reader(log_path).read(None).events

    assert [event.event_type for event in events] == [
        "santa_gatekeeper_override",
        "santa_launch_item",
        "santa_tcc_modification",
        "santa_xprotect",
    ]
    assert events[0].target == "/Applications/Unknown.app"
    assert events[1].attributes["action"] == "ACTION_ADD"
    assert events[2].attributes["service"] == "kTCCServiceSystemPolicyAllFiles"
    assert events[3].attributes["malware_identifier"] == "OSX.Test.Malware"
