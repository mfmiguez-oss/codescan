"""Validation-state assignment.

The pipeline proposes an initial validation state; a human analyst confirms or
overrides it (in ServiceNow or the codescan UI). The proposal is deliberately
conservative — it only auto-classifies unambiguous cases and leaves the rest.

  * Provably unreachable + low exploitability  -> under_investigation (candidate FP)
  * Actively exploited (KEV) or a scored chain  -> confirmed
  * Everything else                             -> new

Decisions are persisted in a state store keyed by finding fingerprint. Each
entry is tagged `manual` when a human set it: manual decisions (and terminal
closures) always prevail on rescan, so triage is not silently overwritten.
"""

from __future__ import annotations

import json
import os
import tempfile
from abc import ABC, abstractmethod
from pathlib import Path

from .config import StorageConfig
from .models import Finding, ValidationState

# Terminal closure states that a rescan must not overturn, even if machine-recorded.
_TERMINAL_CLOSURE_STATES = {
    ValidationState.false_positive,
    ValidationState.risk_accepted,
    ValidationState.resolved,
}


class StateStoreBase(ABC):
    """The persistence contract for validation decisions. The file-backed
    `StateStore` and the DB-backed `SqlStateStore` are interchangeable behind it
    (select via `storage.backend` and `open_state_store`)."""

    @abstractmethod
    def entry(self, finding_id: str) -> dict | None: ...
    @abstractmethod
    def prior(self, finding_id: str) -> ValidationState | None: ...
    @abstractmethod
    def all_entries(self) -> dict[str, dict]: ...
    @abstractmethod
    def record(self, finding: Finding, *, manual: bool = False) -> None: ...
    @abstractmethod
    def save(self) -> None: ...


class StateStore(StateStoreBase):
    """Persists validation decisions across runs, keyed by finding fingerprint.

    Each entry records the state and whether a human set it (`manual`). Legacy
    flat entries (`{id: "state"}`) are read as manual analyst overrides.
    """

    def __init__(self, path: str | Path | None) -> None:
        self.path = Path(path) if path else None
        self._entries: dict[str, dict] = {}
        if self.path and self.path.exists():
            raw = json.loads(self.path.read_text(encoding="utf-8"))
            for fid, val in raw.items():
                if isinstance(val, str):
                    self._entries[fid] = {"state": _coerce_state(val), "manual": True,
                                          "cwes": [], "component": ""}
                else:
                    self._entries[fid] = {
                        "state": _coerce_state(val["state"]),
                        "manual": bool(val.get("manual", False)),
                        # Attributes captured for the analyst-feedback prior (feedback.py);
                        # absent on legacy entries, which simply don't contribute.
                        "cwes": list(val.get("cwes", [])),
                        "component": val.get("component", ""),
                    }

    def entry(self, finding_id: str) -> dict | None:
        return self._entries.get(finding_id)

    def all_entries(self) -> dict[str, dict]:
        return self._entries

    def prior(self, finding_id: str) -> ValidationState | None:
        e = self._entries.get(finding_id)
        return e["state"] if e else None

    def record(self, finding: Finding, *, manual: bool = False) -> None:
        # Capture the weakness/component so a manual decision can inform the
        # feedback prior for similar findings later (feedback.py).
        self._entries[finding.id] = {
            "state": finding.validation_state, "manual": manual,
            "cwes": list(finding.cwe_ids), "component": finding.component.name,
        }

    def save(self) -> None:
        if not self.path:
            return
        def _dump(v: dict) -> dict:
            e = {"state": v["state"].value, "manual": v["manual"]}
            if v.get("cwes"):
                e["cwes"] = v["cwes"]
            if v.get("component"):
                e["component"] = v["component"]
            return e

        payload = json.dumps({k: _dump(v) for k, v in self._entries.items()}, indent=2)
        # Atomic write: a crash mid-write must not truncate persisted analyst
        # decisions. Write a sibling temp file, then os.replace (atomic on the
        # same filesystem) over the target.
        self.path.parent.mkdir(parents=True, exist_ok=True)
        fd, tmp = tempfile.mkstemp(dir=self.path.parent, prefix=self.path.name, suffix=".tmp")
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as fh:
                fh.write(payload)
                fh.flush()
                os.fsync(fh.fileno())
            os.replace(tmp, self.path)
        except BaseException:
            Path(tmp).unlink(missing_ok=True)
            raise


_DDL = (
    "CREATE TABLE IF NOT EXISTS validation_state ("
    " finding_id VARCHAR(64) PRIMARY KEY,"
    " state VARCHAR(32) NOT NULL,"
    " manual BOOLEAN NOT NULL,"
    " cwes TEXT,"
    " component TEXT)"
)


class SqlStateStore(StateStoreBase):
    """Database-backed store (SQLAlchemy → Postgres / SQLite) for shared, HA use.

    Writes are immediate and concurrency-safe: a manual (analyst) decision always
    wins, while a machine proposal never overwrites an existing manual or terminal
    decision — so a scheduled scan can't clobber triage an analyst made on another
    replica. Reads use a snapshot loaded at construction (matching the file store's
    semantics), so `save()` is a no-op.
    """

    def __init__(self, dsn: str) -> None:
        try:
            import sqlalchemy as sa
        except ImportError as exc:  # pragma: no cover - exercised via message
            raise RuntimeError(
                "storage.backend='sql' needs SQLAlchemy — install it with: "
                "pip install 'codescan[sql]' (plus a driver, e.g. psycopg, for Postgres)."
            ) from exc
        self._sa = sa
        self._engine = sa.create_engine(dsn, future=True)
        with self._engine.begin() as conn:
            conn.execute(sa.text(_DDL))
        self._entries: dict[str, dict] = self._load()

    def _load(self) -> dict[str, dict]:
        sa = self._sa
        with self._engine.connect() as conn:
            rows = conn.execute(sa.text(
                "SELECT finding_id, state, manual, cwes, component FROM validation_state"
            )).mappings().all()
        out: dict[str, dict] = {}
        for r in rows:
            out[r["finding_id"]] = {
                "state": _coerce_state(r["state"]),
                "manual": bool(r["manual"]),
                "cwes": json.loads(r["cwes"]) if r["cwes"] else [],
                "component": r["component"] or "",
            }
        return out

    def entry(self, finding_id: str) -> dict | None:
        return self._entries.get(finding_id)

    def all_entries(self) -> dict[str, dict]:
        return self._entries

    def prior(self, finding_id: str) -> ValidationState | None:
        e = self._entries.get(finding_id)
        return e["state"] if e else None

    def record(self, finding: Finding, *, manual: bool = False) -> None:
        entry = {
            "state": finding.validation_state, "manual": manual,
            "cwes": list(finding.cwe_ids), "component": finding.component.name,
        }
        self._write(finding.id, entry)
        self._entries[finding.id] = entry

    def save(self) -> None:
        return  # writes are immediate

    def _write(self, fid: str, entry: dict) -> None:
        sa = self._sa
        params = {
            "id": fid, "state": entry["state"].value, "manual": entry["manual"],
            "cwes": json.dumps(entry["cwes"]) if entry["cwes"] else None,
            "component": entry["component"] or None,
        }
        terminal = [s.value for s in _TERMINAL_CLOSURE_STATES]
        with self._engine.begin() as conn:
            if entry["manual"]:
                # Analyst decision always wins.
                updated = conn.execute(sa.text(
                    "UPDATE validation_state SET state=:state, manual=:manual,"
                    " cwes=:cwes, component=:component WHERE finding_id=:id"), params).rowcount
                if not updated:
                    self._insert(conn, params)
                return
            # Machine proposal: only update a row that isn't a protected (manual or
            # terminal) decision; insert if the row is absent.
            stmt = sa.text(
                "UPDATE validation_state SET state=:state, cwes=:cwes, component=:component"
                " WHERE finding_id=:id AND manual=:false AND state NOT IN :terminal"
            ).bindparams(sa.bindparam("terminal", expanding=True))
            updated = conn.execute(stmt, {**params, "false": False, "terminal": terminal}).rowcount
            if not updated:
                exists = conn.execute(sa.text(
                    "SELECT 1 FROM validation_state WHERE finding_id=:id"), {"id": fid}).fetchone()
                if not exists:
                    self._insert(conn, params)   # else the row is protected -> leave it

    def _insert(self, conn, params: dict) -> None:
        sa = self._sa
        try:
            conn.execute(sa.text(
                "INSERT INTO validation_state (finding_id, state, manual, cwes, component)"
                " VALUES (:id, :state, :manual, :cwes, :component)"), params)
        except sa.exc.IntegrityError:
            pass  # a concurrent writer inserted first — fine, their row stands


def open_state_store(cfg: StorageConfig, path: str | Path | None) -> StateStoreBase:
    """Pick the state-store backend from config: file (default) or a shared DB."""
    if (cfg.backend or "file").lower() == "sql":
        if not cfg.dsn:
            raise RuntimeError("storage.backend='sql' requires storage.dsn (a SQLAlchemy URL)")
        return SqlStateStore(cfg.dsn)
    return StateStore(path)


def assign_states(findings: list[Finding], store: StateStoreBase) -> None:
    for f in findings:
        e = store.entry(f.id)
        if e and (e["manual"] or e["state"] in _TERMINAL_CLOSURE_STATES):
            f.validation_state = e["state"]     # respect the analyst's decision
            continue
        f.validation_state = _propose(f)
        store.record(f, manual=False)


def _coerce_state(value: object) -> ValidationState:
    return ValidationState(value) if not isinstance(value, ValidationState) else value


def _propose(f: Finding) -> ValidationState:
    ex = f.exploitability
    if ex.in_kev or ex.chain_ids:
        return ValidationState.confirmed
    if ex.reachable is False and ex.score < 30:
        return ValidationState.under_investigation   # likely false positive
    if ex.score >= 70 or f.severity.rank >= 3:
        return ValidationState.confirmed
    return ValidationState.new
