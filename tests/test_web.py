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


def test_healthz(tmp_path):
    r = _client(tmp_path).get("/healthz")
    assert r.status_code == 200
    assert r.json() == {"status": "ok"}


def test_state_endpoint(tmp_path):
    r = _client(tmp_path).get("/api/state")
    assert r.status_code == 200
    body = r.json()
    assert body["summary"]["findings"] == 6
    # Findings come back highest-risk first for the triage queue.
    scores = [f["risk_score"] for f in body["findings"]]
    assert scores == sorted(scores, reverse=True)
    assert "states" in body and "confirmed" in body["states"]


def test_scan_records_mode_and_time(tmp_path):
    body = _client(tmp_path).post(
        "/api/scan", json={"use_ai": False, "offline": True, "live": False}).json()
    assert body["last_scan"]                    # run timestamp recorded
    assert body["mode"]["live"] is False
    assert "startup_error" in body


def test_scan_failure_surfaced_not_500(tmp_path, monkeypatch):
    """A failed run (e.g. live mode, no creds) returns 200 with an error, not 500."""
    client = _client(tmp_path)
    import codescan.web as web

    class Boom:
        def __init__(self, *a, **k):
            pass

        def run(self, *a, **k):
            raise RuntimeError("bitbucket unreachable")

    monkeypatch.setattr(web, "Pipeline", Boom)
    r = client.post("/api/scan", json={"live": True})
    assert r.status_code == 200
    assert "bitbucket unreachable" in (r.json()["startup_error"] or "")


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
    assert len(records) == 6
    assert all(rec["correlation_id"] for rec in records)


def test_export_json_download(tmp_path):
    r = _client(tmp_path).get("/api/export?format=json")
    assert r.status_code == 200
    assert "attachment" in r.headers["content-disposition"]
    assert "servicenow_import.json" in r.headers["content-disposition"]
    assert "records" in r.json()


def test_export_csv_download(tmp_path):
    r = _client(tmp_path).get("/api/export?format=csv")
    assert r.status_code == 200
    assert r.headers["content-type"].startswith("text/csv")
    assert "servicenow_import.csv" in r.headers["content-disposition"]
    assert "correlation_id" in r.text.splitlines()[0]


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


def test_source_provider_config(tmp_path):
    client = _client(tmp_path)
    body = client.get("/api/config").json()
    assert body["source"]["provider"] in ("bitbucket", "github")
    assert "github" in body["connectors"]
    assert body["options"]["scm_providers"] == ["bitbucket", "github"]

    for provider in ("bitbucket", "github"):
        switched = client.post("/api/config", json={"source": {"provider": provider}}).json()
        assert switched["source"]["provider"] == provider
    # Unknown provider is rejected.
    assert client.post("/api/config", json={"source": {"provider": "gitlab"}}).status_code == 400


def test_github_repos_editable_via_config(tmp_path):
    client = _client(tmp_path)
    body = client.post("/api/config", json={
        "source": {"provider": "github", "github_repos": ["acme/checkout", " ", "acme/gateway"]},
    }).json()
    # Blanks are stripped; the list round-trips.
    assert body["source"]["github_repos"] == ["acme/checkout", "acme/gateway"]

    # It reaches the connector: a live scan would target exactly those repos.
    from codescan.web import create_app  # persisted to overrides -> new app picks it up
    cfg_path = str(ROOT / "config" / "config.example.yaml")
    app2 = create_app(config_path=cfg_path, fixtures=str(ROOT / "fixtures"),
                      overrides_path=str(tmp_path / "overrides.json"),
                      out_path=str(tmp_path / "o.json"), state_path=str(tmp_path / "s.json"))
    from fastapi.testclient import TestClient
    reran = TestClient(app2).get("/api/config").json()
    assert reran["source"]["github_repos"] == ["acme/checkout", "acme/gateway"]


def test_openhack_config(tmp_path):
    client = _client(tmp_path)
    body = client.post("/api/config", json={
        "openhack": {
            "enabled": True, "findings_dir": "runs/x/1", "repo": "acme/checkout",
            "auto": True, "command": "bash run.sh {repo_path} {output_dir}",
            "workspace": ".oh", "clone": False,
        },
    }).json()
    oh = body["openhack"]
    assert oh["enabled"] is True and oh["auto"] is True and oh["clone"] is False
    assert oh["repo"] == "acme/checkout" and oh["workspace"] == ".oh"
    # Command round-trips (parsed to argv server-side, joined back for display).
    assert oh["command"] == "bash run.sh {repo_path} {output_dir}"


def test_ai_provider_config(tmp_path):
    client = _client(tmp_path)
    body = client.get("/api/config").json()
    assert body["ai"]["provider"] == "anthropic"
    assert body["options"]["ai_providers"] == ["anthropic", "openai", "google"]

    updated = client.post("/api/config", json={
        "ai": {"provider": "openai", "model": "gpt-5",
               "tasks": {"exploitability": {"provider": "google", "model": "gemini-2.5-pro"}}},
    }).json()
    assert updated["ai"]["provider"] == "openai" and updated["ai"]["model"] == "gpt-5"
    assert updated["ai"]["tasks"]["exploitability"]["provider"] == "google"
    # Unknown provider rejected.
    assert client.post("/api/config", json={"ai": {"provider": "acme"}}).status_code == 400


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
