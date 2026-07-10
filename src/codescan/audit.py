"""Append-only audit log — one JSON event per line, shippable to a SIEM.

A durable, greppable record of the key actions and decisions the system makes:
scan runs, configuration changes, and analyst validation-state changes — each with
an `actor` and a UTC timestamp. It supports monitoring and after-the-fact auditing,
distinct from the operational logs (`logging_setup.py`), which are for debugging.

Events fan out to one or more **sinks** (config `audit.*`):
  * **file** — local JSONL (default). Durable, greppable, tail-able by any log
    forwarder (Filebeat/Fluent Bit/Vector), and the source for `GET /api/audit`.
  * **syslog** — the classic SIEM ingestion path (Splunk/QRadar/ArcSight/rsyslog);
    one JSON syslog message per event.
  * **http** — POST to a collector (Splunk HEC, Elastic, Datadog, or a webhook).

Delivery to the syslog/HTTP sinks is best-effort: a sink failure is logged, never
raised, so shipping problems can't take down a scan or an analyst action. The file
sink remains the durable local record.

Actor attribution is best-effort: the web layer derives it from an SSO/reverse-proxy
identity header when present, falling back to a generic principal.
"""

from __future__ import annotations

import json
import logging
import logging.handlers
from datetime import datetime, timezone
from pathlib import Path

import requests

from .config import AuditConfig, HttpSinkConfig, SyslogSinkConfig

logger = logging.getLogger(__name__)


class _FileSink:
    name = "file"

    def __init__(self, path: str, base_dir: str | Path) -> None:
        p = Path(path)
        self.path = p if p.is_absolute() else Path(base_dir) / p

    def emit(self, entry: dict) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with self.path.open("a", encoding="utf-8") as fh:   # append-only
            fh.write(json.dumps(entry, default=str) + "\n")

    def tail(self, limit: int) -> list[dict]:
        if not self.path.exists():
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


class _SyslogSink:
    name = "syslog"

    def __init__(self, cfg: SyslogSinkConfig) -> None:
        import socket

        addr = cfg.address
        address: str | tuple[str, int]
        if "/" in addr and ":" not in addr:
            address = addr                               # unix socket path (e.g. /dev/log)
        else:
            host, _, port = addr.partition(":")
            address = (host or "localhost", int(port or 514))
        socktype = socket.SOCK_STREAM if cfg.protocol.lower() == "tcp" else socket.SOCK_DGRAM
        facility = getattr(
            logging.handlers.SysLogHandler,
            f"LOG_{cfg.facility.upper()}",
            logging.handlers.SysLogHandler.LOG_USER,
        )
        handler = logging.handlers.SysLogHandler(address=address, facility=facility, socktype=socktype)
        handler.setFormatter(logging.Formatter("codescan_audit %(message)s"))
        self._logger = logging.getLogger("codescan.audit.syslog")
        self._logger.handlers[:] = [handler]
        self._logger.propagate = False
        self._logger.setLevel(logging.INFO)

    def emit(self, entry: dict) -> None:
        self._logger.info(json.dumps(entry, default=str))


class _HttpSink:
    name = "http"

    def __init__(self, cfg: HttpSinkConfig) -> None:
        self.cfg = cfg

    def emit(self, entry: dict) -> None:
        body = {self.cfg.event_key: entry} if self.cfg.event_key else entry
        headers = {}
        if self.cfg.token:
            headers[self.cfg.auth_header] = f"{self.cfg.token_prefix}{self.cfg.token}"
        resp = requests.post(
            self.cfg.url, json=body, headers=headers,
            timeout=self.cfg.timeout, verify=self.cfg.verify_tls,
        )
        if resp.status_code >= 400:
            raise RuntimeError(f"{resp.status_code} {resp.reason}")


class AuditLog:
    """Fans an event out to the configured sinks; a no-op when disabled."""

    def __init__(self, cfg: AuditConfig, base_dir: str | Path = ".") -> None:
        self.enabled = cfg.enabled
        self._file = _FileSink(cfg.path, base_dir) if (cfg.enabled and cfg.path) else None
        self._sinks: list = []
        if self._file:
            self._sinks.append(self._file)
        if cfg.enabled and cfg.syslog.enabled:
            try:
                self._sinks.append(_SyslogSink(cfg.syslog))
            except Exception as exc:  # noqa: BLE001 - a bad sink must not break startup
                logger.warning("audit syslog sink unavailable: %s", exc)
        if cfg.enabled and cfg.http.enabled and cfg.http.url:
            self._sinks.append(_HttpSink(cfg.http))

    def record(self, event: str, *, actor: str = "system", **fields: object) -> None:
        if not self.enabled or not self._sinks:
            return
        entry = {
            "ts": datetime.now(timezone.utc).isoformat(timespec="seconds"),
            "event": event,
            "actor": actor,
            **fields,
        }
        for sink in self._sinks:
            try:
                sink.emit(entry)
            except Exception as exc:  # noqa: BLE001 - never let a sink failure propagate
                logger.warning("audit sink %s failed for %s: %s", sink.name, event, exc)

    def tail(self, limit: int = 200) -> list[dict]:
        """Recent events (newest first) from the file sink; empty if push-only."""
        return self._file.tail(limit) if self._file else []
