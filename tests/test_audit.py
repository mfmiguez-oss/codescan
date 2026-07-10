"""Append-only audit log — record/tail, pipeline scan events, web actor events."""

from __future__ import annotations

import json
from pathlib import Path

from fastapi.testclient import TestClient

import codescan.audit as audit_mod
from codescan.audit import AuditLog
from codescan.config import AuditConfig, Config, HttpSinkConfig, SyslogSinkConfig
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


# --- SIEM sinks -----------------------------------------------------------

class _FakeResp:
    status_code, reason = 200, "OK"


def test_http_sink_posts_events(tmp_path, monkeypatch):
    posts = []
    monkeypatch.setattr(audit_mod, "requests",
                        type("R", (), {"post": staticmethod(lambda url, **kw: (posts.append((url, kw)), _FakeResp())[1])}))
    cfg = AuditConfig(
        path=str(tmp_path / "a.jsonl"),
        http=HttpSinkConfig(enabled=True, url="https://siem/collector/event",
                            token="tok", token_prefix="Splunk ", event_key="event"),
    )
    AuditLog(cfg).record("scan.completed", actor="cli", findings=6)

    assert len(posts) == 1
    url, kw = posts[0]
    assert url == "https://siem/collector/event"
    assert kw["headers"]["Authorization"] == "Splunk tok"
    assert kw["json"] == {"event": {"ts": kw["json"]["event"]["ts"], "event": "scan.completed",
                                    "actor": "cli", "findings": 6}}
    # File sink still wrote it too (durable local record).
    assert (tmp_path / "a.jsonl").exists()


def test_http_sink_failure_is_isolated(tmp_path, monkeypatch):
    def boom(*a, **k):
        raise RuntimeError("SIEM unreachable")
    monkeypatch.setattr(audit_mod, "requests", type("R", (), {"post": staticmethod(boom)}))
    cfg = AuditConfig(path=str(tmp_path / "a.jsonl"),
                      http=HttpSinkConfig(enabled=True, url="https://siem"))
    log = AuditLog(cfg)
    log.record("scan.started", actor="cli")     # must not raise
    assert log.tail()[0]["event"] == "scan.started"   # file sink unaffected


def test_syslog_sink_smoke(tmp_path):
    # UDP to a closed local port is fire-and-forget; building + emitting must not raise.
    cfg = AuditConfig(path="",   # push-only (no file)
                      syslog=SyslogSinkConfig(enabled=True, address="localhost:59999", protocol="udp"))
    AuditLog(cfg).record("config.changed", actor="alice")


def test_bad_syslog_sink_does_not_break_startup(tmp_path):
    # An unresolvable/invalid syslog target is logged and skipped, not fatal.
    cfg = AuditConfig(path=str(tmp_path / "a.jsonl"),
                      syslog=SyslogSinkConfig(enabled=True, address="tcp-nowhere.invalid:514", protocol="tcp"))
    log = AuditLog(cfg)                            # must construct despite the bad sink
    log.record("scan.started", actor="cli")
    assert (tmp_path / "a.jsonl").exists()         # file sink still works
