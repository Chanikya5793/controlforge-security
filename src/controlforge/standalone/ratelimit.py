"""Bounded in-process rate limiting for public standalone authentication routes."""

from __future__ import annotations

import hashlib
import threading
from collections import OrderedDict, deque
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone


@dataclass(frozen=True)
class RateLimitDecision:
    allowed: bool
    retry_after_seconds: int


class SlidingWindowRateLimiter:
    """Fail closed after a bounded number of attempts in one UTC window.

    The standalone service intentionally runs one Uvicorn worker. State is bounded
    and process-local; appliance restarts are controlled by a privileged operator.
    """

    def __init__(self, *, max_keys: int = 4_096) -> None:
        if max_keys < 128 or max_keys > 65_536:
            raise ValueError("rate-limit key capacity must be between 128 and 65536")
        self._max_keys = max_keys
        self._attempts: OrderedDict[str, deque[datetime]] = OrderedDict()
        self._lock = threading.Lock()

    @staticmethod
    def _bucket(scope: str, key: str) -> str:
        if not scope or len(scope) > 64:
            raise ValueError("rate-limit scope must contain between 1 and 64 characters")
        normalized_key = key.strip().casefold()
        if not normalized_key or len(normalized_key) > 512:
            normalized_key = "unknown"
        digest = hashlib.sha256(normalized_key.encode()).hexdigest()
        return f"{scope}:{digest}"

    def check(
        self,
        scope: str,
        key: str,
        now: datetime,
        *,
        limit: int,
        window: timedelta,
    ) -> RateLimitDecision:
        if now.tzinfo is None or now.utcoffset() is None:
            raise ValueError("rate-limit clock must be timezone-aware")
        if limit < 1 or limit > 10_000:
            raise ValueError("rate limit must be between 1 and 10000")
        if window < timedelta(seconds=1) or window > timedelta(days=1):
            raise ValueError("rate-limit window must be between 1 second and 1 day")
        utc_now = now.astimezone(timezone.utc)
        cutoff = utc_now - window
        bucket = self._bucket(scope, key)
        with self._lock:
            attempts = self._attempts.pop(bucket, deque())
            while attempts and attempts[0] <= cutoff:
                attempts.popleft()
            if len(attempts) >= limit:
                retry_at = attempts[0] + window
                retry_seconds = max(1, int((retry_at - utc_now).total_seconds()) + 1)
                self._attempts[bucket] = attempts
                return RateLimitDecision(False, retry_seconds)
            attempts.append(utc_now)
            self._attempts[bucket] = attempts
            while len(self._attempts) > self._max_keys:
                self._attempts.popitem(last=False)
        return RateLimitDecision(True, 0)


__all__ = ["RateLimitDecision", "SlidingWindowRateLimiter"]
