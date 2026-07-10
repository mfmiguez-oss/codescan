"""Calibration report — how well do the pipeline's scores predict analyst outcomes?

The state store accumulates manual triage decisions, and (since decision
snapshots landed in `validation.py`) each one carries what the machine believed
at decision time — most importantly the composite risk score. Comparing the two
answers the question no amount of modelling can: *is the scoring actually
right?*

The report is deliberately simple and explainable, matching the feedback
prior's design constraints:

  * **Score buckets** — manual confirmed / false-positive decisions grouped by
    the risk score the pipeline had assigned. A well-calibrated pipeline shows
    a confirm rate that rises with the bucket; a flat or inverted curve means
    the weights (or the AI stage) need work.
  * **Separation** — mean predicted score of confirmed vs false-positive
    decisions. Bigger gap = the score carries real signal.
  * **Noisiest families** — CWE families and components whose manual history is
    dominated by false positives: the concrete "what is wasting analyst time"
    list, and the same keys the feedback prior (feedback.py) nudges on.

Only manual `confirmed` / `false_positive` decisions count — the same accuracy
signals feedback.py uses; lifecycle outcomes (risk_accepted, resolved) say
nothing about whether the tool was right. Legacy decisions recorded before
snapshots existed still count toward totals but can't be bucketed by score.
"""

from __future__ import annotations

from .models import ValidationState
from .validation import StateStoreBase

# Risk-score buckets, aligned with the severity bands analysts already think in.
BUCKETS = (
    ("0-39", 0.0, 40.0),
    ("40-59", 40.0, 60.0),
    ("60-79", 60.0, 80.0),
    ("80-100", 80.0, 100.1),
)

_POSITIVE = ValidationState.confirmed
_NEGATIVE = ValidationState.false_positive


def _bucket_label(score: float) -> str:
    for label, lo, hi in BUCKETS:
        if lo <= score < hi:
            return label
    return BUCKETS[-1][0]


def calibration_report(store: StateStoreBase, *, top_n: int = 5) -> dict:
    """Grade persisted machine predictions against manual analyst outcomes.

    Returns a JSON-ready dict; all rates are 0-1 floats rounded to 2 places.
    Empty history yields zeroed totals, so callers can render unconditionally.
    """
    confirmed = 0
    false_pos = 0
    unscored = 0                       # legacy manual decisions without a snapshot
    buckets: dict[str, dict[str, int]] = {label: {"confirmed": 0, "false_positive": 0}
                                          for label, _, _ in BUCKETS}
    score_sum = {"confirmed": 0.0, "false_positive": 0.0}
    scored = {"confirmed": 0, "false_positive": 0}
    fp_by_key: dict[str, dict[str, int]] = {}

    for entry in store.all_entries().values():
        if not entry.get("manual"):
            continue
        state = entry["state"]
        if state == _POSITIVE:
            confirmed += 1
            outcome = "confirmed"
        elif state == _NEGATIVE:
            false_pos += 1
            outcome = "false_positive"
        else:
            continue

        for key in [f"CWE {c}" for c in entry.get("cwes", [])] + (
                [entry["component"]] if entry.get("component") else []):
            tally = fp_by_key.setdefault(key, {"confirmed": 0, "false_positive": 0})
            tally[outcome] += 1

        snap = entry.get("snapshot")
        if not snap or snap.get("risk_score") is None:
            unscored += 1
            continue
        score = float(snap["risk_score"])
        buckets[_bucket_label(score)][outcome] += 1
        score_sum[outcome] += score
        scored[outcome] += 1

    labeled = confirmed + false_pos
    bucket_rows = []
    for label, _, _ in BUCKETS:
        b = buckets[label]
        total = b["confirmed"] + b["false_positive"]
        bucket_rows.append({
            "bucket": label, "total": total,
            "confirmed": b["confirmed"], "false_positive": b["false_positive"],
            "confirm_rate": round(b["confirmed"] / total, 2) if total else None,
        })

    # Families/components where analysts mostly say "not real" — needs more FPs
    # than confirms and at least 2 decisions to be worth surfacing.
    noisy = sorted(
        ({"key": k, **v, "fp_rate": round(v["false_positive"] / (v["confirmed"] + v["false_positive"]), 2)}
         for k, v in fp_by_key.items()
         if v["false_positive"] > v["confirmed"] and v["confirmed"] + v["false_positive"] >= 2),
        key=lambda r: (r["false_positive"], r["fp_rate"]), reverse=True,
    )[:top_n]

    return {
        "decisions": labeled,
        "confirmed": confirmed,
        "false_positives": false_pos,
        "confirm_rate": round(confirmed / labeled, 2) if labeled else None,
        "unscored": unscored,
        "buckets": bucket_rows,
        "mean_score_confirmed": (
            round(score_sum["confirmed"] / scored["confirmed"], 1)
            if scored["confirmed"] else None),
        "mean_score_false_positive": (
            round(score_sum["false_positive"] / scored["false_positive"], 1)
            if scored["false_positive"] else None),
        "noisy_keys": noisy,
    }
