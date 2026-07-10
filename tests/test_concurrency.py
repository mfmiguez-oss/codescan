"""map_workers — bounded parallel map that preserves input order."""

from __future__ import annotations

import threading
import time

from codescan.concurrency import map_workers, resilient_map


def test_preserves_order_sequential():
    assert map_workers(lambda x: x * 2, [1, 2, 3, 4], max_workers=1) == [2, 4, 6, 8]


def test_preserves_order_parallel():
    # Reverse-proportional sleeps: if results came back in completion order they'd
    # be reversed. Order-preserving map_workers must still return input order.
    def slow(x):
        time.sleep((5 - x) * 0.02)
        return x
    assert map_workers(slow, [1, 2, 3, 4], max_workers=4) == [1, 2, 3, 4]


def test_actually_runs_concurrently():
    seen = []
    lock = threading.Lock()
    barrier = threading.Barrier(3, timeout=5)

    def work(x):
        barrier.wait()          # only completes if 3 threads run at once
        with lock:
            seen.append(x)
        return x

    result = map_workers(work, [1, 2, 3], max_workers=3)
    assert sorted(result) == [1, 2, 3]
    assert len(seen) == 3       # barrier didn't time out -> genuine concurrency


def test_single_item_takes_sequential_path():
    # <=1 item must not spin up a pool (no behavior change, no overhead).
    assert map_workers(lambda x: x + 1, [41], max_workers=8) == [42]
    assert map_workers(lambda x: x, [], max_workers=8) == []


def test_resilient_map_isolates_failures():
    # An item whose fn raises is dropped (logged), the rest still run — one bad
    # repo must not abort the estate. Order of successes is preserved.
    def fn(x):
        if x == 3:
            raise ValueError("boom")
        return x * 10

    results, failures = resilient_map(fn, [1, 2, 3, 4], max_workers=1)
    assert results == [10, 20, 40]
    assert len(failures) == 1
    item, exc = failures[0]
    assert item == 3 and isinstance(exc, ValueError)


def test_resilient_map_all_succeed():
    results, failures = resilient_map(lambda x: x, [1, 2, 3], max_workers=4)
    assert sorted(results) == [1, 2, 3] and failures == []
