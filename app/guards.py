from collections import defaultdict, deque
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone


@dataclass
class RateLimitResult:
    allowed: bool
    retry_after_seconds: int


class SlidingWindowRateLimiter:
    def __init__(self, max_requests: int, window_seconds: int):
        self.max_requests = max_requests
        self.window_seconds = window_seconds
        self._requests: dict[str, deque[datetime]] = defaultdict(deque)

    def check(self, key: str) -> RateLimitResult:
        now = datetime.now(timezone.utc)
        window_start = now - timedelta(seconds=self.window_seconds)
        request_times = self._requests[key]

        while request_times and request_times[0] < window_start:
            request_times.popleft()

        if len(request_times) >= self.max_requests:
            retry_after = int((request_times[0] + timedelta(seconds=self.window_seconds) - now).total_seconds())
            return RateLimitResult(allowed=False, retry_after_seconds=max(retry_after, 1))

        request_times.append(now)
        return RateLimitResult(allowed=True, retry_after_seconds=0)


class BruteForceProtector:
    def __init__(self, max_failures: int, window_seconds: int, lock_seconds: int):
        self.max_failures = max_failures
        self.window_seconds = window_seconds
        self.lock_seconds = lock_seconds
        self._failures: dict[str, deque[datetime]] = defaultdict(deque)
        self._lock_until: dict[str, datetime] = {}

    def is_blocked(self, key: str) -> RateLimitResult:
        now = datetime.now(timezone.utc)
        lock_until = self._lock_until.get(key)
        if lock_until and lock_until > now:
            retry_after = int((lock_until - now).total_seconds())
            return RateLimitResult(allowed=False, retry_after_seconds=max(retry_after, 1))
        return RateLimitResult(allowed=True, retry_after_seconds=0)

    def register_failure(self, key: str) -> None:
        now = datetime.now(timezone.utc)
        window_start = now - timedelta(seconds=self.window_seconds)
        attempts = self._failures[key]

        while attempts and attempts[0] < window_start:
            attempts.popleft()

        attempts.append(now)
        if len(attempts) >= self.max_failures:
            self._lock_until[key] = now + timedelta(seconds=self.lock_seconds)
            attempts.clear()

    def reset(self, key: str) -> None:
        self._failures.pop(key, None)
        self._lock_until.pop(key, None)
