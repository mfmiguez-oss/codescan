"""Token-bucket rate limiter — burst, refill, per-client isolation, eviction."""

from __future__ import annotations

from codescan.ratelimit import RateLimiter, TokenBucket


def test_bucket_allows_burst_then_blocks():
    b = TokenBucket(rate=1.0, capacity=3.0)
    t = 1000.0
    assert [b.take(t) for _ in range(3)] == [True, True, True]   # burst of 3
    assert b.take(t) is False                                     # 4th blocked same instant


def test_bucket_refills_over_time():
    b = TokenBucket(rate=2.0, capacity=2.0)
    t = 1000.0
    assert b.take(t) and b.take(t)          # drain
    assert b.take(t) is False
    assert b.take(t + 0.5) is True          # 0.5s * 2/s = 1 token back


def test_limiter_isolates_clients():
    rl = RateLimiter(rpm=60, burst=2)
    assert rl.allow("a") and rl.allow("a")  # a spends its burst
    assert rl.allow("a") is False
    assert rl.allow("b") is True            # b unaffected


def test_limiter_evicts_idle_buckets():
    rl = RateLimiter(rpm=60, burst=1)
    rl.allow("old")
    # Force the idle bucket far into the past and trip the sweep window.
    rl._buckets["old"]._updated -= 10_000
    rl._last_sweep -= 10_000
    rl.allow("new")                          # triggers _evict_idle
    assert "old" not in rl._buckets
