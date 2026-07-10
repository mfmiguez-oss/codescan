"""Append-only audit log — one JSON event per line (JSONL).

A durable, greppable record of the key actions and decisions the system makes:
scan runs, configuration changes, and analyst validation-state changes — each with
an `actor` and a UTC timestamp. Append-only from the application's side (events are
only ever added, never rewritten), so it supports monitoring and after-the-fact
auditing. It complements the operational logs (`logging_setup.py`), which are for
debugging rather than a decision record.

Actor attribution is best-effort: the web layer derives it from an SSO/reverse-proxy
identity header when present, falling back to a generic principal. Wiring real
per-user identity is then just populating that header upstream.
"""

from __future__ import annotations

import json
import logging
from datetime import datetime, timezone
from pathlib import Path

from .config import AuditConfig

logger = logging.getLogger(__name__)


class AuditLog:
    """Writes/reads a JSONL audit file. A no-op when disabled or without a path."""

    def __init__(self, cfg: AuditConfig, base_dir: str | Path = ".") -> None:
        self.enabled = cfg.enabled and bool(cfg.path)
        path = Path(cfg.path) if cfg.path else None
        if path is not None and not path.is_absolute():
            path = Path(base_dir) / path
        self.path = path

    def record(self, event: str, *, actor: str = "system", **fields: object) -> None:
        """Append one event. Never raises — an audit-write failure is logged, not
        propagated, so it can't take down a scan or an analyst action."""
        if not self.enabled or self.path is None:
            return
        entry = {
            "ts": datetime.now(timezone.utc).isoformat(timespec="seconds"),
            "event": event,
            "actor": actor,
            **fields,
        }
        try:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            with self.path.open("a", encoding="utf-8") as fh:   # append-only
                fh.write(json.dumps(entry, default=str) + "\n")
        except OSError as exc:
            logger.warning("audit write failed for %s: %s", event, exc)

    def tail(self, limit: int = 200) -> list[dict]:
        """Return the most recent events, newest first (best-effort; skips bad lines)."""
        if self.path is None or not self.path.exists():
            return []
        try:
            lines = self.path.read_text(encoding="utf-8").splitlines()
        except OSError:
            return []
        out: list[dict] = []
        for line in reversed(lines):
            if len(out) >= limit:
                break
            line = line.strip()
            if not line:
                continue
            try:
                out.append(json.loads(line))
            except json.JSONDecodeError:
                continue
        return out
