"""Validation state store — atomic, crash-safe persistence."""

from __future__ import annotations

import json

import pytest

from codescan.models import Component, Finding, Location, Source, ValidationState
from codescan.validation import StateStore


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


def test_save_is_atomic_no_temp_leftover(tmp_path):
    path = tmp_path / "state.json"
    store = StateStore(path)
    store.record(_finding(), manual=False)
    store.save()

    # Exactly the target file remains — no .tmp sibling left behind.
    files = list(tmp_path.iterdir())
    assert files == [path]
    json.loads(path.read_text(encoding="utf-8"))   # valid JSON


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
