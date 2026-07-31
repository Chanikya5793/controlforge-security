from datetime import datetime, timezone
from pathlib import Path

import pytest

from controlforge.models import SecurityEvent


@pytest.fixture
def project_root() -> Path:
    return Path(__file__).resolve().parents[1]


@pytest.fixture
def base_event() -> SecurityEvent:
    return SecurityEvent(
        event_id="evt-base",
        event_type="process_start",
        timestamp=datetime(2026, 8, 11, 14, 0, tzinfo=timezone.utc),
        actor="analyst@example.com",
        source_ip="203.0.113.10",
        target="WS-100",
        attributes={"process_name": "cmd.exe", "command_line": "cmd.exe /c whoami"},
    )
