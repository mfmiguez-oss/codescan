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
from pathlib import Path

from .models import Finding, ValidationState

# Terminal closure states that a rescan must not overturn, even if machine-recorded.
_TERMINAL_CLOSURE_STATES = {
    ValidationState.false_positive,
    ValidationState.risk_accepted,
    ValidationState.resolved,
}


class StateStore:
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


def assign_states(findings: list[Finding], store: StateStore) -> None:
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
