"""Analyst-feedback loop — calibrate scores from persisted triage decisions.

The validation state store (`validation.py`) accumulates the org's human ground
truth: findings analysts marked **confirmed** (a real, exploitable issue) or
**false_positive** (not real). This module turns that history into a small,
bounded, *explainable* prior: if analysts have repeatedly dismissed findings of a
given weakness family (CWE) or component as false positives, a new finding sharing
that trait is nudged **down**; a repeatedly-confirmed trait nudges **up**.

Design constraints, deliberately conservative:
  * **Bounded** — the adjustment is capped at `feedback.max_adjust` points and
    requires `feedback.min_evidence` prior decisions, so a couple of calls can't
    swing a score wildly.
  * **Explainable** — every adjusted finding gets a plain-language reason in its
    rationale and a `feedback-adjusted` tag; the scan's audit event records how
    many were touched. Nothing about the calibration is a black box.
  * **Respects the human & the floor** — it only moves the *machine score*, never
    an analyst's validation state; a finding never counts toward adjusting itself;
    and an actively-exploited (KEV) finding is never pushed below `kev_floor`.
  * **Self-activating, not speculative** — with no manual history it is a no-op.
"""

from __future__ import annotations

import logging

from .config import FeedbackConfig
from .models import Finding, ValidationState
from .validation import StateStoreBase

logger = logging.getLogger(__name__)

# Only these two states are accuracy signals: confirmed = true positive,
# false_positive = analyst says not real. risk_accepted / resolved are business or
# lifecycle outcomes, not "was the tool right", so they don't feed the prior.
_POSITIVE = ValidationState.confirmed
_NEGATIVE = ValidationState.false_positive


def _finding_keys(f: Finding) -> list[str]:
    keys = [f"cwe:{c}" for c in f.cwe_ids]
    if f.component.name:
        keys.append(f"comp:{f.component.name.lower()}")
    return keys


def _entry_keys(entry: dict) -> list[str]:
    keys = [f"cwe:{c}" for c in entry.get("cwes", [])]
    comp = entry.get("component", "")
    if comp:
        keys.append(f"comp:{comp.lower()}")
    return keys


class FeedbackModel:
    """Per-key tallies of manual confirmed vs false-positive decisions (by finding
    id, so a finding can be excluded from adjusting itself)."""

    def __init__(self) -> None:
        self._pos: dict[str, set[str]] = {}
        self._neg: dict[str, set[str]] = {}

    @classmethod
    def from_store(cls, store: StateStoreBase) -> "FeedbackModel":
        m = cls()
        for fid, entry in store.all_entries().items():
            if not entry.get("manual"):
                continue
            bucket = m._pos if entry["state"] == _POSITIVE else m._neg if entry["state"] == _NEGATIVE else None
            if bucket is None:
                continue
            for key in _entry_keys(entry):
                bucket.setdefault(key, set()).add(fid)
        return m

    def delta(self, finding: Finding, cfg: FeedbackConfig) -> tuple[float, str]:
        """Bounded score delta + reason for `finding`, from prior decisions on the
        same weakness/component (excluding the finding's own past decision)."""
        pos: set[str] = set()
        neg: set[str] = set()
        for key in _finding_keys(finding):
            pos |= self._pos.get(key, set()) - {finding.id}
            neg |= self._neg.get(key, set()) - {finding.id}
        total = len(pos) + len(neg)
        if total < cfg.min_evidence:
            return 0.0, ""
        # Scale by the strength of consensus: unanimous -> full ±max_adjust.
        delta = cfg.max_adjust * (len(pos) - len(neg)) / total
        delta = max(-cfg.max_adjust, min(cfg.max_adjust, round(delta, 1)))
        if abs(delta) < 0.5:
            return 0.0, ""
        verb = "raised" if delta > 0 else "lowered"
        reason = (f"score {verb} {abs(delta):.0f} by analyst-feedback prior "
                  f"({len(pos)} confirmed, {len(neg)} false-positive on related "
                  f"weakness/component)")
        return delta, reason


def apply_feedback(
    findings: list[Finding], store: StateStoreBase, cfg: FeedbackConfig, kev_floor: float
) -> int:
    """Adjust findings' risk scores from the analyst-feedback prior, in place.

    Returns the number of findings adjusted. A no-op when disabled or when there is
    no manual history to learn from.
    """
    if not cfg.enabled:
        return 0
    model = FeedbackModel.from_store(store)
    adjusted = 0
    for f in findings:
        delta, reason = model.delta(f, cfg)
        if not delta:
            continue
        new = max(0.0, min(100.0, f.risk_score + delta))
        if f.exploitability.in_kev:
            new = max(new, kev_floor)     # active exploitation still outweighs the prior
        new = round(new, 1)
        if new == f.risk_score:
            continue
        f.risk_score = new
        f.exploitability.rationale = f"{f.exploitability.rationale} [{reason}]".strip()
        if "feedback-adjusted" not in f.tags:
            f.tags.append("feedback-adjusted")
        adjusted += 1
    if adjusted:
        logger.info("feedback prior adjusted %d finding score(s)", adjusted)
    return adjusted
