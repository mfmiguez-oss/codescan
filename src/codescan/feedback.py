"""Analyst-feedback loop — calibrate scores from persisted triage decisions.

The validation state store (`validation.py`) accumulates the org's human ground
truth: findings analysts marked **confirmed** (a real, exploitable issue) or
**false_positive** (not real). This module turns that history into a small,
bounded, *explainable* prior: if analysts have repeatedly dismissed findings of a
given weakness family (CWE) or component as false positives, a new finding sharing
that trait is nudged **down**; a repeatedly-confirmed trait nudges **up**.

The prior is statistically honest about its evidence:
  * **Shrinkage** (`feedback.shrinkage`) — pseudo-count damping, so confidence
    grows with volume: two unanimous decisions move a score far less than twenty.
  * **Time decay** (`feedback.half_life_days`) — a decision's weight halves every
    half-life; a component dismissed two years and four versions ago barely votes.
  * **Repo scoping** (`feedback.same_repo_boost`) — a decision made in the *same
    repo* as the new finding outweighs estate-wide precedent.

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
from datetime import datetime, timezone

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
    id, so a finding can be excluded from adjusting itself), plus per-decision
    metadata (age, repo) so the delta can weight evidence honestly."""

    def __init__(self) -> None:
        self._pos: dict[str, set[str]] = {}
        self._neg: dict[str, set[str]] = {}
        self._meta: dict[str, tuple[str, str]] = {}   # fid -> (decided_at, repo)

    @classmethod
    def from_store(cls, store: StateStoreBase) -> "FeedbackModel":
        m = cls()
        for fid, entry in store.all_entries().items():
            if not entry.get("manual") or fid.startswith("chain:"):
                continue
            bucket = m._pos if entry["state"] == _POSITIVE else m._neg if entry["state"] == _NEGATIVE else None
            if bucket is None:
                continue
            snapshot = entry.get("snapshot") or {}
            m._meta[fid] = (entry.get("decided_at", ""), snapshot.get("repo", ""))
            for key in _entry_keys(entry):
                bucket.setdefault(key, set()).add(fid)
        return m

    def evidence(self, finding: Finding) -> tuple[set[str], set[str]]:
        """Ids of prior manual decisions on the same weakness/component:
        (confirmed, false_positive) — excluding the finding's own past decision."""
        pos: set[str] = set()
        neg: set[str] = set()
        for key in _finding_keys(finding):
            pos |= self._pos.get(key, set()) - {finding.id}
            neg |= self._neg.get(key, set()) - {finding.id}
        return pos, neg

    def _weight(self, fid: str, finding: Finding, cfg: FeedbackConfig,
                now: datetime) -> float:
        """Evidence weight of one prior decision: recency-decayed, same-repo-boosted."""
        decided_at, repo = self._meta.get(fid, ("", ""))
        w = 1.0
        if cfg.half_life_days > 0:
            age_days = cfg.half_life_days     # unknown age (legacy) -> one half-life
            if decided_at:
                try:
                    age_days = max(0.0, (now - datetime.fromisoformat(decided_at))
                                   .total_seconds() / 86400)
                except (ValueError, TypeError):
                    pass      # unparseable/naive timestamp -> keep the legacy default
            w *= 0.5 ** (age_days / cfg.half_life_days)
        if repo and repo == finding.location.repo:
            w *= max(1.0, cfg.same_repo_boost)
        return w

    def delta(self, finding: Finding, cfg: FeedbackConfig,
              now: datetime | None = None) -> tuple[float, str]:
        """Bounded score delta + reason for `finding`, from prior decisions on the
        same weakness/component (excluding the finding's own past decision)."""
        pos, neg = self.evidence(finding)
        total = len(pos) + len(neg)
        if total < cfg.min_evidence:
            return 0.0, ""
        now = now or datetime.now(timezone.utc)
        wpos = sum(self._weight(fid, finding, cfg, now) for fid in pos)
        wneg = sum(self._weight(fid, finding, cfg, now) for fid in neg)
        denom = wpos + wneg + max(0.0, cfg.shrinkage)
        if denom <= 0:
            return 0.0, ""
        # Shrinkage keeps thin evidence humble: the delta approaches ±max_adjust
        # only as (weighted) unanimous evidence outgrows the pseudo-count.
        delta = cfg.max_adjust * (wpos - wneg) / denom
        delta = max(-cfg.max_adjust, min(cfg.max_adjust, round(delta, 1)))
        if abs(delta) < 0.5:
            return 0.0, ""
        verb = "raised" if delta > 0 else "lowered"
        reason = (f"score {verb} {abs(delta):.0f} by analyst-feedback prior "
                  f"({len(pos)} confirmed, {len(neg)} false-positive on related "
                  f"weakness/component; recency- and repo-weighted)")
        return delta, reason


class TriageHistory:
    """Prior manual accuracy decisions packaged as grounded facts for the AI prompt.

    Where the feedback prior (`apply_feedback`) adjusts scores *after* the AI
    stage, this puts the same org ground truth *into* the model's reasoning: a
    finding's prompt digest gains the counts of how analysts triaged similar
    findings (same weakness family / component), plus the analysts' own one-line
    reasons where they left one. Unlike the blind prior, the model can judge
    whether the history applies to *this* instance — and it is told to treat it
    as context, never as a verdict (see exploitability.py).
    """

    MAX_NOTES = 3     # most recent analyst notes carried per finding — signal, not bulk

    def __init__(self, store: StateStoreBase) -> None:
        self._model = FeedbackModel.from_store(store)
        self._entries = store.all_entries()

    def context(self, finding: Finding) -> dict | None:
        """Counts (and recent analyst notes) of similar manual decisions, or None
        when there is no history (so findings without history add nothing)."""
        pos, neg = self._model.evidence(finding)
        if not pos and not neg:
            return None
        ctx: dict = {"confirmed": len(pos), "false_positive": len(neg)}
        noted = []
        for fid in pos | neg:
            e = self._entries.get(fid, {})
            if e.get("note"):
                noted.append((e.get("decided_at", ""), f"{e['state'].value}: {e['note']}"))
        if noted:
            noted.sort(reverse=True)                       # most recent decisions first
            ctx["analyst_notes"] = [n for _, n in noted[: self.MAX_NOTES]]
        return ctx


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
