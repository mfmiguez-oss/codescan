"""Per-client token-bucket rate limiter for the web API.

Defends against unbounded resource/LLM consumption (OWASP LLM04/10): a runaway
client or hostile caller cannot drive unbounded cost by hammering `/api/scan`.
In-process and dependency-free — right for the single-instance default. Behind a
load balancer, prefer the proxy's own rate limiting (this still bounds each
replica). Keyed by the authenticated actor when present, else the client IP.
"""

from __future__ import annotations

import threading
import time


class TokenBucket:
    """Classic token bucket: `rate` tokens/second refill up to `capacity`.

    `capacity` is the burst allowance; sustained throughput converges to `rate`.
    """

    __slots__ = ("rate", "capacity", "_tokens", "_updated")

    def __init__(self, rate: float, capacity: float) -> None:
        self.rate = rate
        self.capacity = capacity
        self._tokens = capacity
        self._updated = time.monotonic()

    def take(self, now: float | None = None) -> bool:
        now = time.monotonic() if now is None else now
        elapsed = max(0.0, now - self._updated)     # clamp: time never runs backward
        self._updated = now
        self._tokens = min(self.capacity, self._tokens + elapsed * self.rate)
        if self._tokens >= 1.0:
            self._tokens -= 1.0
            return True
        return False


class RateLimiter:
    """Thread-safe collection of per-client token buckets.

    Idle buckets are evicted lazily so the map can't grow without bound under a
    spray of distinct clients (itself a resource-exhaustion vector).
    """

    def __init__(self, rpm: int, burst: int) -> None:
        self.rate = max(rpm, 1) / 60.0
        self.capacity = float(max(burst, 1))
        self._buckets: dict[str, TokenBucket] = {}
        self._lock = threading.Lock()
        self._last_sweep = time.monotonic()

    def allow(self, key: str) -> bool:
        now = time.monotonic()
        with self._lock:
            if now - self._last_sweep > 300:
                self._evict_idle(now)
                self._last_sweep = now
            bucket = self._buckets.get(key)
            if bucket is None:
                bucket = self._buckets[key] = TokenBucket(self.rate, self.capacity)
            return bucket.take(now)

    def _evict_idle(self, now: float) -> None:
        # A bucket seen more than 10 min ago has long since refilled to full;
        # dropping it is equivalent to keeping it and costs no fairness.
        stale = [k for k, b in self._buckets.items() if now - b._updated > 600]
        for k in stale:
            del self._buckets[k]
