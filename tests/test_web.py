"""Web API tests — offline, no AI, no network. Uses the FastAPI TestClient."""

from __future__ import annotations

from pathlib import Path

from fastapi.testclient import TestClient

from codescan.web import create_app

ROOT = Path(__file__).resolve().parents[1]


def _app(tmp_path, overrides="overrides.json"):
    return create_app(
        config_path=str(ROOT / "config" / "config.example.yaml"),
        fixtures=str(ROOT / "fixtures"),
        use_ai=False,
        offline=True,
        out_path=str(tmp_path / "sn.json"),
        state_path=str(tmp_path / "state.json"),
        overrides_path=str(tmp_path / overrides),
    )


def _client(tmp_path):
    return TestClient(_app(tmp_path))


def test_index_served(tmp_path):
    r = _client(tmp_path).get("/")
    assert r.status_code == 200
    assert "codescan" in r.text


def test_state_endpoint(tmp_path):
    r = _client(tmp_path).get("/api/state")
    assert r.status_code == 200
    body = r.json()
    assert body["summary"]["findings"] == 4
    # Findings come back highest-risk first for the triage queue.
    scores = [f["risk_score"] for f in body["findings"]]
    assert scores == sorted(scores, reverse=True)
    assert "states" in body and "confirmed" in body["states"]


def test_change_validation_state_persists(tmp_path):
    client = _client(tmp_path)
    fid = client.get("/api/state").json()["findings"][0]["id"]

    r = client.post(f"/api/findings/{fid}/state", json={"state": "risk_accepted"})
    assert r.status_code == 200
    assert r.json()["validation_state"] == "risk_accepted"

    # A re-scan must keep the analyst's decision (sticky).
    client.post("/api/scan", json={"use_ai": False, "offline": True})
    findings = client.get("/api/state").json()["findings"]
    reran = next(f for f in findings if f["id"] == fid)
    assert reran["validation_state"] == "risk_accepted"


def test_invalid_state_rejected(tmp_path):
    client = _client(tmp_path)
    fid = client.get("/api/state").json()["findings"][0]["id"]
    assert client.post(f"/api/findings/{fid}/state", json={"state": "bogus"}).status_code == 400
    assert client.post("/api/findings/nope/state", json={"state": "confirmed"}).status_code == 404


def test_servicenow_endpoint(tmp_path):
    r = _client(tmp_path).get("/api/servicenow")
    assert r.status_code == 200
    records = r.json()["records"]
    assert len(records) == 4
    assert all(rec["correlation_id"] for rec in records)


def test_get_config_masks_secrets(tmp_path):
    body = _client(tmp_path).get("/api/config").json()
    assert body["options"]["known_models"] and body["options"]["routed_tasks"]
    assert "severity" in body["scoring"]["weights"]
    assert set(body["enrichment"]) >= {"kev_enabled", "epss_enabled", "reachability_enabled", "ai_enabled"}
    # Any configured secret is masked, never returned raw.
    for conn in body["connectors"].values():
        tok = conn.get("token", "")
        assert tok in ("", "••••••••")


def test_update_config_applies_and_persists(tmp_path):
    client = _client(tmp_path)
    update = {
        "enrichment": {"kev_enabled": False, "ai_enabled": True},
        "scoring": {"weights": {"severity": 0.5, "exploitability": 0.2, "exposure": 0.2, "chaining": 0.1}, "kev_floor": 90},
        "ai": {"model": "claude-opus-4-8", "effort": "high", "max_tokens": 32000,
               "tasks": {"exploitability": {"model": "claude-fable-5", "effort": "xhigh", "max_tokens": 40000}}},
    }
    body = client.post("/api/config", json=update).json()
    assert body["enrichment"]["kev_enabled"] is False
    assert body["enrichment"]["ai_enabled"] is True
    assert body["scoring"]["kev_floor"] == 90
    assert body["ai"]["tasks"]["exploitability"]["model"] == "claude-fable-5"
    assert (tmp_path / "overrides.json").exists()


def test_invalid_effort_rejected(tmp_path):
    assert _client(tmp_path).post("/api/config", json={"ai": {"effort": "turbo"}}).status_code == 400


def test_servicenow_format_config(tmp_path):
    client = _client(tmp_path)
    body = client.post("/api/config", json={"servicenow": {"format": "csv"}}).json()
    assert body["servicenow"]["format"] == "csv"
    # Invalid format is rejected.
    assert client.post("/api/config", json={"servicenow": {"format": "xml"}}).status_code == 400


def test_threat_model_toggle_and_state(tmp_path):
    client = _client(tmp_path)
    body = client.post("/api/config", json={"threat_model": {"enabled": True}}).json()
    assert body["threat_model"]["enabled"] is True
    assert "threat_model" in body["options"]["routed_tasks"]
    # State always carries the threat_models list (empty in the offline/no-AI client).
    assert "threat_models" in client.get("/api/state").json()


def test_overrides_survive_restart(tmp_path):
    TestClient(_app(tmp_path, "ov.json")).post("/api/config", json={"enrichment": {"ai_enabled": True}})
    # A fresh app with the same overrides file must reflect the saved change.
    body = TestClient(_app(tmp_path, "ov.json")).get("/api/config").json()
    assert body["enrichment"]["ai_enabled"] is True
