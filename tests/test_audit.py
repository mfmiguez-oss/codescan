"""Append-only audit log — record/tail, pipeline scan events, web actor events."""

from __future__ import annotations

import json
from pathlib import Path

from fastapi.testclient import TestClient

from codescan.audit import AuditLog
from codescan.config import AuditConfig, Config
from codescan.pipeline import Pipeline
from codescan.web import create_app

ROOT = Path(__file__).resolve().parents[1]
FIXTURES = ROOT / "fixtures"
CONFIG = ROOT / "config" / "config.example.yaml"


def test_record_and_tail_roundtrip(tmp_path):
    log = AuditLog(AuditConfig(path=str(tmp_path / "audit.jsonl")))
    log.record("scan.started", actor="cli", run_id="abc")
    log.record("validation.changed", actor="alice", finding_id="f1", **{"from": "new", "to": "confirmed"})

    events = log.tail()
    assert [e["event"] for e in events] == ["validation.changed", "scan.started"]  # newest first
    assert events[0]["actor"] == "alice" and events[0]["to"] == "confirmed"
    assert all("ts" in e for e in events)
    # It's real JSONL: one object per line.
    lines = (tmp_path / "audit.jsonl").read_text().splitlines()
    assert len(lines) == 2 and json.loads(lines[0])["event"] == "scan.started"


def test_disabled_is_noop(tmp_path):
    log = AuditLog(AuditConfig(enabled=False, path=str(tmp_path / "a.jsonl")))
    log.record("scan.started", actor="cli")
    assert log.tail() == []
    assert not (tmp_path / "a.jsonl").exists()


def test_pipeline_emits_scan_events(tmp_path):
    cfg = Config.load(CONFIG)
    cfg.audit.path = str(tmp_path / "audit.jsonl")
    Pipeline(cfg, offline=True, use_ai=False).run(
        fixtures=FIXTURES, out_path=tmp_path / "sn.json", state_path=tmp_path / "state.json",
        actor="cli",
    )
    events = AuditLog(cfg.audit, base_dir=tmp_path).tail()
    kinds = {e["event"] for e in events}
    assert {"scan.started", "scan.completed"} <= kinds
    done = next(e for e in events if e["event"] == "scan.completed")
    assert done["actor"] == "cli" and done["findings"] == 6 and "duration_s" in done


def _app(tmp_path):
    return create_app(
        config_path=str(CONFIG), fixtures=str(FIXTURES), use_ai=False, offline=True,
        out_path=str(tmp_path / "sn.json"), state_path=str(tmp_path / "state.json"),
        overrides_path=str(tmp_path / "ov.json"),
    )


def test_web_records_state_change_with_actor(tmp_path):
    client = TestClient(_app(tmp_path))
    fid = client.get("/api/state").json()["findings"][0]["id"]

    client.post(f"/api/findings/{fid}/state", json={"state": "risk_accepted"},
                headers={"X-Remote-User": "alice@corp"})

    events = client.get("/api/audit").json()["events"]
    change = next(e for e in events if e["event"] == "validation.changed")
    assert change["actor"] == "alice@corp"
    assert change["finding_id"] == fid and change["to"] == "risk_accepted"


def test_web_records_config_change(tmp_path):
    client = TestClient(_app(tmp_path))
    client.post("/api/config", json={"scoring": {"kev_floor": 90}},
                headers={"X-Forwarded-User": "bob"})
    events = client.get("/api/audit").json()["events"]
    cfg_change = next(e for e in events if e["event"] == "config.changed")
    assert cfg_change["actor"] == "bob" and "scoring.kev_floor" in cfg_change["keys"]


def test_web_startup_scan_is_audited(tmp_path):
    client = TestClient(_app(tmp_path))
    events = client.get("/api/audit").json()["events"]
    assert any(e["event"] == "scan.completed" and e["actor"] == "startup" for e in events)
