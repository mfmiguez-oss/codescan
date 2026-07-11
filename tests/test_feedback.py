"""Analyst-feedback prior — bounded, explainable score calibration."""

from __future__ import annotations

from codescan.config import FeedbackConfig
from codescan.feedback import TriageHistory, apply_feedback
from codescan.models import Component, Finding, Location, Source, ValidationState
from codescan.validation import StateStore

CWE79, CWE89 = "CWE-79", "CWE-89"
FP = ValidationState.false_positive
CONF = ValidationState.confirmed


def _f(fid, *, cwe=None, comp="pkg", score=50.0, kev=False, state=None):
    f = Finding(
        id=fid, source=Source.snyk, source_ref="r", title="t",
        cwe_ids=[cwe] if cwe else [],
        component=Component(name=comp), location=Location(repo="a/b"),
    )
    f.risk_score = score
    f.exploitability.in_kev = kev
    if state:
        f.validation_state = state
    return f


def _store(decisions, path=None, *, manual=True):
    store = StateStore(path)
    for fid, cwe, state in decisions:
        store.record(_f(fid, cwe=cwe, state=state), manual=manual)
    return store


def test_false_positive_history_lowers_score():
    store = _store([("a", CWE79, FP), ("b", CWE79, FP), ("c", CWE79, FP)])
    new = _f("new", cwe=CWE79, score=60)
    assert apply_feedback([new], store, FeedbackConfig(), kev_floor=85) == 1
    assert new.risk_score == 45.0                     # 60 - 15 (unanimous, capped)
    assert "feedback-adjusted" in new.tags
    assert "false-positive" in new.exploitability.rationale


def test_confirmed_history_raises_score():
    store = _store([("a", CWE89, CONF), ("b", CWE89, CONF)])
    new = _f("new", cwe=CWE89, score=40)
    apply_feedback([new], store, FeedbackConfig(), kev_floor=85)
    assert new.risk_score == 55.0                     # 40 + 15


def test_below_min_evidence_no_change():
    store = _store([("a", CWE79, FP)])                # only one prior decision
    new = _f("new", cwe=CWE79, score=60)
    assert apply_feedback([new], store, FeedbackConfig(min_evidence=2), kev_floor=85) == 0
    assert new.risk_score == 60.0


def test_finding_is_excluded_from_its_own_adjustment():
    # 'new' is the only FP for its CWE; excluding itself leaves no evidence, so
    # even with min_evidence=1 it is not adjusted (proves self-exclusion).
    store = _store([("new", CWE79, FP)])
    new = _f("new", cwe=CWE79, score=60)
    assert apply_feedback([new], store, FeedbackConfig(min_evidence=1), kev_floor=85) == 0


def test_kev_finding_not_pushed_below_floor():
    store = _store([("a", CWE79, FP), ("b", CWE79, FP), ("c", CWE79, FP)])
    kev = _f("k", cwe=CWE79, score=90, kev=True)
    apply_feedback([kev], store, FeedbackConfig(), kev_floor=85)
    assert kev.risk_score == 85.0                     # -15 would be 75; floored


def test_disabled_is_noop():
    store = _store([("a", CWE79, FP), ("b", CWE79, FP)])
    new = _f("new", cwe=CWE79, score=60)
    assert apply_feedback([new], store, FeedbackConfig(enabled=False), kev_floor=85) == 0
    assert new.risk_score == 60.0


def test_only_manual_accuracy_states_count():
    store = StateStore(None)
    store.record(_f("a", cwe=CWE79, state=FP), manual=False)                 # machine -> ignored
    store.record(_f("b", cwe=CWE79, state=ValidationState.risk_accepted), manual=True)  # not accuracy
    new = _f("new", cwe=CWE79, score=60)
    assert apply_feedback([new], store, FeedbackConfig(min_evidence=1), kev_floor=85) == 0
    assert new.risk_score == 60.0


def test_triage_history_context_counts():
    store = _store([("a", CWE79, FP), ("b", CWE79, FP), ("c", CWE79, CONF)])
    ctx = TriageHistory(store).context(_f("new", cwe=CWE79))
    assert ctx == {"confirmed": 1, "false_positive": 2}


def test_triage_history_none_without_similar_decisions():
    store = _store([("a", CWE79, FP)])
    history = TriageHistory(store)
    # Different weakness AND different component -> nothing similar.
    assert history.context(_f("new", cwe=CWE89, comp="otherpkg")) is None
    # Self-exclusion: a finding's own past decision is not "history" for it.
    assert history.context(_f("a", cwe=CWE79)) is None


def test_triage_history_ignores_machine_and_lifecycle_states():
    store = StateStore(None)
    store.record(_f("m", cwe=CWE79, state=FP), manual=False)  # machine proposal
    store.record(_f("r", cwe=CWE79, state=ValidationState.risk_accepted), manual=True)
    assert TriageHistory(store).context(_f("new", cwe=CWE79)) is None


def test_component_history_and_store_roundtrip(tmp_path):
    store = StateStore(tmp_path / "s.json")
    for fid in ("a", "b"):
        f = _f(fid, comp="lodash", state=FP)
        store.record(f, manual=True)
    store.save()

    reloaded = StateStore(tmp_path / "s.json")         # attributes survive persistence
    assert reloaded.all_entries()["a"]["component"] == "lodash"

    new = _f("new", comp="lodash", score=50)
    apply_feedback([new], reloaded, FeedbackConfig(), kev_floor=85)
    assert new.risk_score == 35.0                      # -15 via comp:lodash
