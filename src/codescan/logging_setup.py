"""Logging configuration for the CLI and web entry points.

Library modules never configure logging on import — they only
`logging.getLogger(__name__)` and emit. The entry points (`cli.py`, `web.py`)
call `configure()` once so those records reach a handler. Level comes from
`CODESCAN_LOG_LEVEL` (default INFO), so operators can raise it to DEBUG without a
code change.
"""

from __future__ import annotations

import logging
import os

_CONFIGURED = False


def configure(level: str | None = None) -> None:
    """Attach a stderr handler to the `codescan` logger (idempotent)."""
    global _CONFIGURED
    if _CONFIGURED:
        return
    resolved = (level or os.environ.get("CODESCAN_LOG_LEVEL", "INFO")).upper()

    handler = logging.StreamHandler()
    handler.setFormatter(logging.Formatter(
        "%(asctime)s %(levelname)-7s %(name)s: %(message)s",
        datefmt="%Y-%m-%dT%H:%M:%S",
    ))
    root = logging.getLogger("codescan")
    root.setLevel(getattr(logging, resolved, logging.INFO))
    root.handlers[:] = [handler]
    root.propagate = False
    _CONFIGURED = True
