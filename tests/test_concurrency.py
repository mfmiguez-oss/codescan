"""map_workers — bounded parallel map that preserves input order."""

from __future__ import annotations

import threading
import time

from codescan.concurrency import map_workers


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
