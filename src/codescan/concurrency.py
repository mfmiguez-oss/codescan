"""Bounded parallelism for the per-service AI stages.

The pipeline's judgement-heavy stages (exploitability, threat modeling, AI
enrichment, semantic dedup) each issue one LLM request per repo/service group.
Those groups are independent, so running them strictly sequentially makes a large
enterprise scan's wall-clock time scale linearly with the repo count — the run is
I/O-bound on the model API, not on CPU.

`map_workers` runs the per-group calls on a small thread pool (Anthropic's client
is thread-safe) while **preserving input order** in the results, so callers apply
the results deterministically afterwards. Concurrency is a latency optimization
only — it changes neither the requests made nor their cost. It is bounded (config
`ai.max_concurrency`, default modest) to stay well within provider rate limits;
set it to 1 to force sequential execution.
"""

from __future__ import annotations

import logging
from collections.abc import Callable, Iterable
from concurrent.futures import ThreadPoolExecutor
from typing import TypeVar

logger = logging.getLogger(__name__)

T = TypeVar("T")
R = TypeVar("R")


def workers_of(llm: object) -> int:
    """Concurrency bound from an LLM client, defaulting to sequential.

    Reads `llm.max_workers` when present; a minimal client (or a test double)
    that only implements `complete_json` runs sequentially.
    """
    return max(1, int(getattr(llm, "max_workers", 1)))


def map_workers(fn: Callable[[T], R], items: Iterable[T], max_workers: int) -> list[R]:
    """Apply `fn` to each item, up to `max_workers` in parallel, order preserved.

    Falls back to a plain sequential map for a single worker or a single item, so
    there is no thread-pool overhead (and no behavior change) in those cases.
    """
    work = list(items)
    if max_workers <= 1 or len(work) <= 1:
        return [fn(x) for x in work]
    with ThreadPoolExecutor(max_workers=min(max_workers, len(work))) as pool:
        # executor.map preserves the order of `work` in its results.
        return list(pool.map(fn, work))


def resilient_map(
    fn: Callable[[T], R],
    items: Iterable[T],
    max_workers: int,
    *,
    describe: Callable[[T], str] = repr,
) -> tuple[list[R], list[tuple[T, Exception]]]:
    """Like `map_workers`, but **isolate per-item failures** instead of aborting.

    An item whose `fn` raises is logged (WARNING, tagged with `describe(item)`) and
    dropped; the rest still run. Returns `(successes_in_order, failures)` where
    `failures` is a list of `(item, exception)`. This keeps one repo's model
    timeout or refusal from failing an entire estate scan — the trade-off is that a
    genuine bug in `fn` is caught and logged rather than surfaced immediately.
    """
    def _run(item: T) -> tuple[bool, object]:
        try:
            return True, fn(item)
        except Exception as exc:  # noqa: BLE001 - deliberate per-item isolation
            logger.warning("concurrent task failed for %s: %s", describe(item), exc)
            return False, (item, exc)

    outcomes = map_workers(_run, list(items), max_workers)
    results = [payload for ok, payload in outcomes if ok]
    failures = [payload for ok, payload in outcomes if not ok]
    return results, failures  # type: ignore[return-value]
