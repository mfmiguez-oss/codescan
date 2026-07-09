"""Validation-state assignment.

The pipeline proposes an initial validation state; a human analyst confirms or
overrides it (in ServiceNow or the codescan UI). The proposal is deliberately
conservative — it only auto-classifies unambiguous cases and leaves the rest.

  * Provably unreachable + low exploitability  -> under_investigation (candidate FP)
  * Actively exploited (KEV) or a scored chain  -> confirmed
  * Everything else                             -> new

Decisions are persisted in a state store keyed by finding fingerprint. Each
entry is tagged `manual` when a human set it: manual decisions (and terminal
closures) always win on rescan, so triage is never silently overwritten.
"""

from __future__ import annotations

import json
from pathlib import Path

from .models import Finding, ValidationState

# Terminal closure states that a rescan must never overturn, even if machine-recorded.
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
                    self._entries[fid] = {"state": ValidationState(val), "manual": True}
                else:
                    self._entries[fid] = {
                        "state": ValidationState(val["state"]),
                        "manual": bool(val.get("manual", False)),
                    }

    def entry(self, finding_id: str) -> dict | None:
        return self._entries.get(finding_id)

    def prior(self, finding_id: str) -> ValidationState | None:
        e = self._entries.get(finding_id)
        return e["state"] if e else None

    def record(self, finding: Finding, *, manual: bool = False) -> None:
        self._entries[finding.id] = {"state": finding.validation_state, "manual": manual}

    def save(self) -> None:
        if self.path:
            self.path.write_text(
                json.dumps(
                    {k: {"state": v["state"].value, "manual": v["manual"]}
                     for k, v in self._entries.items()},
                    indent=2,
                ),
                encoding="utf-8",
            )


def assign_states(findings: list[Finding], store: StateStore) -> None:
    for f in findings:
        e = store.entry(f.id)
        if e and (e["manual"] or e["state"] in _TERMINAL_CLOSURE_STATES):
            f.validation_state = e["state"]     # respect the analyst's decision
            continue
        f.validation_state = _propose(f)
        store.record(f, manual=False)


def _propose(f: Finding) -> ValidationState:
    ex = f.exploitability
    if ex.in_kev or ex.chain_ids:
        return ValidationState.confirmed
    if ex.reachable is False and ex.score < 30:
        return ValidationState.under_investigation   # likely false positive
    if ex.score >= 70 or f.severity.rank >= 3:
        return ValidationState.confirmed
    return ValidationState.new
