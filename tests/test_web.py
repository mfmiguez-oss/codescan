"""Web API tests — offline, no AI, no network. Uses the FastAPI TestClient."""

from __future__ import annotations

from pathlib import Path

from fastapi.testclient import TestClient

from codescan.web import create_app

ROOT = Path(__file__).resolve().parents[1]


def _client(tmp_path):
    app = create_app(
        config_path=str(ROOT / "config" / "config.example.yaml"),
        fixtures=str(ROOT / "fixtures"),
        use_ai=False,
        offline=True,
        out_path=str(tmp_path / "sn.json"),
        state_path=str(tmp_path / "state.json"),
    )
    return TestClient(app)


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
