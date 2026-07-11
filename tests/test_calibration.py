"""Calibration report — grading persisted predictions against analyst outcomes."""

from __future__ import annotations

import json

from codescan.calibration import calibration_report, drift_alerts
from codescan.config import CalibrationConfig
from codescan.models import Component, Exploitability, Finding, Location, Source, ValidationState
from codescan.validation import StateStore


def _finding(fid, *, score=50.0, cwe=None, comp="pkg", state=ValidationState.new):
    f = Finding(
        id=fid, source=Source.snyk, source_ref="r", title=f"finding {fid}",
        cwe_ids=[cwe] if cwe else [], component=Component(name=comp),
        location=Location(repo="a/b"),
        exploitability=Exploitability(score=score),
    )
    f.risk_score = score
    f.validation_state = state
    return f


def _seed(store, fid, state, *, score, cwe=None, comp="pkg", manual=True):
    store.record(_finding(fid, score=score, cwe=cwe, comp=comp, state=state), manual=manual)


def test_empty_store_yields_zeroed_report(tmp_path):
    report = calibration_report(StateStore(tmp_path / "s.json"))
    assert report["decisions"] == 0
    assert report["confirm_rate"] is None
    assert all(b["total"] == 0 for b in report["buckets"])
    assert report["noisy_keys"] == []


def test_buckets_and_rates(tmp_path):
    store = StateStore(tmp_path / "s.json")
    # High-scored predictions the analysts confirmed…
    _seed(store, "a", ValidationState.confirmed, score=90.0)
    _seed(store, "b", ValidationState.confirmed, score=85.0)
    # …one high-scored miss, and low-scored dismissals.
    _seed(store, "c", ValidationState.false_positive, score=82.0)
    _seed(store, "d", ValidationState.false_positive, score=20.0)
    _seed(store, "e", ValidationState.false_positive, score=35.0)

    report = calibration_report(store)
    assert report["decisions"] == 5
    assert report["confirmed"] == 2 and report["false_positives"] == 3
    assert report["confirm_rate"] == 0.4

    by_bucket = {b["bucket"]: b for b in report["buckets"]}
    assert by_bucket["80-100"] == {"bucket": "80-100", "total": 3, "confirmed": 2,
                                   "false_positive": 1, "confirm_rate": 0.67}
    assert by_bucket["0-39"]["total"] == 2 and by_bucket["0-39"]["confirm_rate"] == 0.0
    assert by_bucket["40-59"]["total"] == 0 and by_bucket["40-59"]["confirm_rate"] is None

    # Confirmed decisions carried higher predicted scores than false positives.
    assert report["mean_score_confirmed"] == 87.5
    assert report["mean_score_false_positive"] == 45.7


def test_lifecycle_and_machine_states_dont_count(tmp_path):
    store = StateStore(tmp_path / "s.json")
    _seed(store, "a", ValidationState.risk_accepted, score=70.0)          # lifecycle
    _seed(store, "b", ValidationState.resolved, score=70.0)               # lifecycle
    _seed(store, "c", ValidationState.confirmed, score=70.0, manual=False)  # machine
    assert calibration_report(store)["decisions"] == 0


def test_noisy_keys_surface_fp_dominated_families(tmp_path):
    store = StateStore(tmp_path / "s.json")
    for fid in ("a", "b", "c"):
        _seed(store, fid, ValidationState.false_positive, score=50.0,
              cwe="CWE-79", comp="lodash")
    _seed(store, "d", ValidationState.confirmed, score=50.0, cwe="CWE-89", comp="pgdriver")

    noisy = calibration_report(store)["noisy_keys"]
    keys = {n["key"] for n in noisy}
    assert keys == {"CWE CWE-79", "lodash"}
    assert all(n["fp_rate"] == 1.0 and n["false_positive"] == 3 for n in noisy)


def test_chain_decisions_dont_pollute_the_report(tmp_path):
    store = StateStore(tmp_path / "s.json")
    store.record_chain("fp1", ValidationState.false_positive, note="steps don't connect")
    store.record_chain("fp2", ValidationState.confirmed)
    _seed(store, "f", ValidationState.confirmed, score=90.0)

    report = calibration_report(store)
    assert report["decisions"] == 1                   # only the finding decision counts
    assert report["unscored"] == 0


def _drifting_store(tmp_path, *, n_fp=5, score=90.0):
    """A store where high-scored predictions were mostly dismissed — drift."""
    store = StateStore(tmp_path / "s.json")
    for i in range(n_fp):
        _seed(store, f"fp{i}", ValidationState.false_positive, score=score)
    return store


def test_drift_alert_on_high_bucket_precision(tmp_path):
    report = calibration_report(_drifting_store(tmp_path))
    alerts = drift_alerts(report, CalibrationConfig())
    assert any("high-score precision drift" in a for a in alerts)


def test_drift_silent_below_min_evidence(tmp_path):
    report = calibration_report(_drifting_store(tmp_path, n_fp=3))   # < 5 decisions
    assert drift_alerts(report, CalibrationConfig()) == []


def test_drift_silent_when_disabled_or_healthy(tmp_path):
    drifting = calibration_report(_drifting_store(tmp_path))
    assert drift_alerts(drifting, CalibrationConfig(alerts_enabled=False)) == []

    healthy = StateStore(tmp_path / "h.json")
    for i in range(5):
        _seed(healthy, f"c{i}", ValidationState.confirmed, score=90.0)
    for i in range(5):
        _seed(healthy, f"f{i}", ValidationState.false_positive, score=20.0)
    assert drift_alerts(calibration_report(healthy), CalibrationConfig()) == []


def test_drift_alert_on_collapsed_separation(tmp_path):
    # Confirmed findings scored *lower* than false positives: inverted signal.
    store = StateStore(tmp_path / "s.json")
    for i in range(3):
        _seed(store, f"c{i}", ValidationState.confirmed, score=30.0)
    for i in range(3):
        _seed(store, f"f{i}", ValidationState.false_positive, score=70.0)
    alerts = drift_alerts(calibration_report(store), CalibrationConfig())
    assert any("separation collapsed" in a for a in alerts)


def test_legacy_decisions_without_snapshot_counted_but_unbucketed(tmp_path):
    path = tmp_path / "s.json"
    # A decision persisted by a release before snapshots existed.
    path.write_text(json.dumps({
        "old": {"state": "confirmed", "manual": True, "cwes": ["CWE-1"], "component": "x"},
    }), encoding="utf-8")
    store = StateStore(path)
    _seed(store, "new", ValidationState.confirmed, score=90.0)

    report = calibration_report(store)
    assert report["decisions"] == 2
    assert report["unscored"] == 1
    assert sum(b["total"] for b in report["buckets"]) == 1
    assert report["mean_score_confirmed"] == 90.0     # only the scored one averages
