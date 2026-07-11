"""Pluggable state store — SQL backend (SQLite) behind the shared interface."""

from __future__ import annotations

from pathlib import Path

import pytest

from codescan.config import Config, FeedbackConfig, StorageConfig
from codescan.feedback import apply_feedback
from codescan.models import Component, Finding, Location, Source, ValidationState
from codescan.pipeline import Pipeline
from codescan.validation import SqlStateStore, StateStore, open_state_store

ROOT = Path(__file__).resolve().parents[1]


def _dsn(tmp_path: Path) -> str:
    return f"sqlite:///{(tmp_path / 'state.db').as_posix()}"


def _f(fid, *, state=None, cwe=None, comp="pkg", score=50.0):
    f = Finding(
        id=fid, source=Source.snyk, source_ref="r", title="t",
        cwe_ids=[cwe] if cwe else [], component=Component(name=comp),
        location=Location(repo="a/b"),
    )
    f.risk_score = score
    if state:
        f.validation_state = state
    return f


def test_factory_selects_backend(tmp_path):
    assert isinstance(open_state_store(StorageConfig(), tmp_path / "s.json"), StateStore)
    sql = open_state_store(StorageConfig(backend="sql", dsn=_dsn(tmp_path)), None)
    assert isinstance(sql, SqlStateStore)


def test_sql_requires_dsn():
    with pytest.raises(RuntimeError, match="requires storage.dsn"):
        open_state_store(StorageConfig(backend="sql"), None)


def test_roundtrip_and_persistence(tmp_path):
    dsn = _dsn(tmp_path)
    SqlStateStore(dsn).record(
        _f("f1", state=ValidationState.confirmed, cwe="CWE-79", comp="lodash"),
        manual=True, note="reachable from the payment callback")

    reloaded = SqlStateStore(dsn).entry("f1")            # a fresh connection sees it
    assert reloaded["state"] == ValidationState.confirmed and reloaded["manual"] is True
    assert reloaded["cwes"] == ["CWE-79"] and reloaded["component"] == "lodash"
    assert reloaded["note"] == "reachable from the payment callback"
    # The machine-belief snapshot rides along for the calibration report.
    assert reloaded["snapshot"]["risk_score"] == 50.0
    assert reloaded["snapshot"]["repo"] == "a/b"
    assert reloaded["decided_at"]


def test_pre_snapshot_schema_upgrades_in_place(tmp_path):
    """A DB created before the snapshot columns existed migrates on open."""
    import sqlite3

    db = tmp_path / "state.db"
    conn = sqlite3.connect(db)
    conn.execute(
        "CREATE TABLE validation_state (finding_id VARCHAR(64) PRIMARY KEY,"
        " state VARCHAR(32) NOT NULL, manual BOOLEAN NOT NULL, cwes TEXT, component TEXT)")
    conn.execute(
        "INSERT INTO validation_state VALUES ('old', 'confirmed', 1, NULL, 'lodash')")
    conn.commit()
    conn.close()

    store = SqlStateStore(_dsn(tmp_path))
    old = store.entry("old")                             # legacy row still readable…
    assert old["state"] == ValidationState.confirmed
    assert old["snapshot"] is None and old["decided_at"] == "" and old["note"] == ""
    store.record(_f("new"), manual=True, note="n")       # …and new rows get snapshots
    fresh = SqlStateStore(_dsn(tmp_path)).entry("new")
    assert fresh["snapshot"]["risk_score"] == 50.0 and fresh["note"] == "n"


def test_manual_decision_not_clobbered_by_machine(tmp_path):
    dsn = _dsn(tmp_path)
    SqlStateStore(dsn).record(_f("f1", state=ValidationState.false_positive), manual=True)
    # A later machine proposal (e.g. a scheduled scan on another replica) must not
    # overwrite the analyst's terminal decision.
    SqlStateStore(dsn).record(_f("f1", state=ValidationState.confirmed), manual=False)
    assert SqlStateStore(dsn).entry("f1")["state"] == ValidationState.false_positive


def test_machine_proposal_inserts_when_absent(tmp_path):
    dsn = _dsn(tmp_path)
    SqlStateStore(dsn).record(_f("new", state=ValidationState.new), manual=False)
    assert SqlStateStore(dsn).entry("new")["state"] == ValidationState.new


def test_feedback_reads_sql_store(tmp_path):
    dsn = _dsn(tmp_path)
    seed = SqlStateStore(dsn)
    for fid in ("a", "b", "c"):
        seed.record(_f(fid, state=ValidationState.false_positive, cwe="CWE-79"), manual=True)

    new = _f("new", cwe="CWE-79", score=60.0)
    assert apply_feedback([new], SqlStateStore(dsn), FeedbackConfig(), kev_floor=85) == 1
    assert new.risk_score == 50.0                        # 15 * -6/(6+3) via the SQL prior


def test_chain_decision_round_trip_sql(tmp_path):
    dsn = _dsn(tmp_path)
    SqlStateStore(dsn).record_chain("abc123", ValidationState.confirmed, note="real path")
    fresh = SqlStateStore(dsn)                            # a fresh connection sees it
    assert fresh.chain_state("abc123") == ValidationState.confirmed
    assert fresh.entry("chain:abc123")["note"] == "real path"


def test_pipeline_persists_to_sql(tmp_path):
    cfg = Config.load(ROOT / "config" / "config.example.yaml")
    cfg.storage.backend = "sql"
    cfg.storage.dsn = _dsn(tmp_path)
    cfg.audit.enabled = False
    result = Pipeline(cfg, offline=True, use_ai=False).run(
        fixtures=ROOT / "fixtures", out_path=tmp_path / "sn.json", state_path=tmp_path / "unused.json",
    )
    # State landed in the DB (not a JSON file), and reloads to the same count.
    assert not (tmp_path / "unused.json").exists()
    assert len(SqlStateStore(_dsn(tmp_path)).all_entries()) == len(result.findings)
