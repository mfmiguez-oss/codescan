"""Validation state store — atomic, crash-safe persistence."""

from __future__ import annotations

import json

import pytest

from codescan.models import Component, Finding, Location, Source, ValidationState
from codescan.validation import StateStore, active_chains, annotate_chain_states


def _finding(fid: str = "f1") -> Finding:
    return Finding(
        id=fid, source=Source.snyk, source_ref="r", title="t",
        component=Component(name="pkg"), location=Location(repo="a/b"),
    )


def test_save_reload_roundtrip(tmp_path):
    path = tmp_path / "state.json"
    store = StateStore(path)
    f = _finding()
    f.validation_state = ValidationState.risk_accepted
    store.record(f, manual=True)
    store.save()

    reloaded = StateStore(path)
    assert reloaded.prior("f1") == ValidationState.risk_accepted
    assert reloaded.entry("f1")["manual"] is True


def test_record_captures_machine_belief_snapshot(tmp_path):
    path = tmp_path / "state.json"
    store = StateStore(path)
    f = _finding()
    f.risk_score = 87.5
    f.exploitability.score = 80.0
    f.exploitability.epss = 0.42
    f.exploitability.in_kev = True
    f.exploitability.reachable = True
    f.validation_state = ValidationState.confirmed
    store.record(f, manual=True)
    store.save()

    snap = StateStore(path).entry("f1")["snapshot"]
    assert snap["risk_score"] == 87.5 and snap["ai_score"] == 80.0
    assert snap["epss"] == 0.42 and snap["in_kev"] is True and snap["reachable"] is True
    assert snap["repo"] == "a/b" and snap["severity"] == "info"
    assert StateStore(path).entry("f1")["decided_at"]     # ISO timestamp recorded


def test_analyst_note_round_trip(tmp_path):
    path = tmp_path / "state.json"
    store = StateStore(path)
    f = _finding()
    f.validation_state = ValidationState.false_positive
    store.record(f, manual=True, note="  vendored test fixture, never shipped  ")
    store.save()

    entry = StateStore(path).entry("f1")
    assert entry["note"] == "vendored test fixture, never shipped"   # stripped

    # A later decision without a note clears it (the caller sends the current
    # note when it wants to keep it — see web.py changeState).
    store2 = StateStore(path)
    store2.record(f, manual=True)
    store2.save()
    assert StateStore(path).entry("f1")["note"] == ""


def test_legacy_entries_load_without_snapshot(tmp_path):
    path = tmp_path / "state.json"
    path.write_text(json.dumps({
        "flat": "confirmed",                                            # oldest format
        "pre_snapshot": {"state": "false_positive", "manual": True},    # pre-snapshot dict
    }), encoding="utf-8")
    store = StateStore(path)
    for fid in ("flat", "pre_snapshot"):
        assert store.entry(fid)["snapshot"] is None
        assert store.entry(fid)["decided_at"] == ""
        assert store.entry(fid)["note"] == ""


def test_save_is_atomic_no_temp_leftover(tmp_path):
    path = tmp_path / "state.json"
    store = StateStore(path)
    store.record(_finding(), manual=False)
    store.save()

    # Exactly the target file remains — no .tmp sibling left behind.
    files = list(tmp_path.iterdir())
    assert files == [path]
    json.loads(path.read_text(encoding="utf-8"))   # valid JSON


def test_chain_decision_round_trip_and_annotation(tmp_path):
    path = tmp_path / "state.json"
    store = StateStore(path)
    store.record_chain("fp1", ValidationState.false_positive, note="steps don't connect")
    store.save()

    reloaded = StateStore(path)
    assert reloaded.chain_state("fp1") == ValidationState.false_positive
    assert reloaded.chain_state("unknown") is None

    chains = [
        {"chain_id": "CH-1", "fingerprint": "fp1", "chain_score": 70},
        {"chain_id": "CH-2", "fingerprint": "fp2", "chain_score": 50},
    ]
    annotate_chain_states(chains, reloaded)
    assert chains[0]["validation_state"] == "false_positive"
    assert chains[1]["validation_state"] == "new"
    # The dismissed chain stays visible but stops counting.
    assert [c["chain_id"] for c in active_chains(chains)] == ["CH-2"]


def test_chain_rejects_lifecycle_states(tmp_path):
    store = StateStore(tmp_path / "s.json")
    with pytest.raises(ValueError, match="invalid chain state"):
        store.record_chain("fp1", ValidationState.risk_accepted)


def test_crash_during_replace_preserves_existing(tmp_path, monkeypatch):
    path = tmp_path / "state.json"
    path.write_text('{"f1": {"state": "confirmed", "manual": true}}', encoding="utf-8")
    original = path.read_text(encoding="utf-8")

    store = StateStore(path)
    store.record(_finding(), manual=False)

    import codescan.validation as v
    monkeypatch.setattr(v.os, "replace", lambda *a: (_ for _ in ()).throw(OSError("disk full")))
    with pytest.raises(OSError):
        store.save()

    # Original file is intact (not truncated) and no temp file leaked.
    assert path.read_text(encoding="utf-8") == original
    assert list(tmp_path.iterdir()) == [path]
