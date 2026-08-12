from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

from controlforge.standalone.ratelimit import SlidingWindowRateLimiter

NOW = datetime(2026, 8, 22, 20, 0, tzinfo=timezone.utc)


def test_window_limits_then_recovers_at_boundary() -> None:
    limiter = SlidingWindowRateLimiter()

    assert limiter.check("login", "192.0.2.1", NOW, limit=2, window=timedelta(minutes=5)).allowed
    assert limiter.check(
        "login",
        "192.0.2.1",
        NOW + timedelta(seconds=1),
        limit=2,
        window=timedelta(minutes=5),
    ).allowed
    denied = limiter.check(
        "login",
        "192.0.2.1",
        NOW + timedelta(seconds=2),
        limit=2,
        window=timedelta(minutes=5),
    )
    assert denied.allowed is False
    assert denied.retry_after_seconds == 299
    assert limiter.check(
        "login",
        "192.0.2.1",
        NOW + timedelta(minutes=5),
        limit=2,
        window=timedelta(minutes=5),
    ).allowed


def test_scopes_and_keys_are_isolated_without_storing_raw_identity() -> None:
    limiter = SlidingWindowRateLimiter()
    assert limiter.check(
        "login", "User@Example.com", NOW, limit=1, window=timedelta(minutes=1)
    ).allowed
    assert not limiter.check(
        "login",
        " user@example.COM ",
        NOW,
        limit=1,
        window=timedelta(minutes=1),
    ).allowed
    assert limiter.check(
        "bootstrap",
        "user@example.com",
        NOW,
        limit=1,
        window=timedelta(minutes=1),
    ).allowed
    assert all("user@example.com" not in bucket for bucket in limiter._attempts)


def test_key_capacity_is_bounded() -> None:
    limiter = SlidingWindowRateLimiter(max_keys=128)
    for index in range(150):
        limiter.check(
            "enroll",
            f"192.0.2.{index}",
            NOW,
            limit=2,
            window=timedelta(minutes=1),
        )
    assert len(limiter._attempts) == 128


def test_invalid_policy_and_naive_clock_fail_closed() -> None:
    limiter = SlidingWindowRateLimiter()
    with pytest.raises(ValueError, match="timezone-aware"):
        limiter.check("login", "key", datetime(2026, 8, 22), limit=1, window=timedelta(minutes=1))
    with pytest.raises(ValueError, match="rate limit"):
        limiter.check("login", "key", NOW, limit=0, window=timedelta(minutes=1))
    with pytest.raises(ValueError, match="window"):
        limiter.check("login", "key", NOW, limit=1, window=timedelta(0))
