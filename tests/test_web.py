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


def test_no_auth_by_default(tmp_path):
    # CODESCAN_API_TOKEN unset -> API is open (the "behind SSO" default).
    assert _client(tmp_path).get("/api/state").status_code == 200


def test_api_token_guard(tmp_path, monkeypatch):
    monkeypatch.setenv("CODESCAN_API_TOKEN", "s3cr3t")
    client = _client(tmp_path)

    # /api/* requires the token; healthz and the static shell stay open.
    assert client.get("/api/state").status_code == 401
    assert client.get("/healthz").status_code == 200
    assert client.get("/").status_code == 200

    # Accepted via Authorization: Bearer …
    ok = client.get("/api/state", headers={"Authorization": "Bearer s3cr3t"})
    assert ok.status_code == 200
    # …and via X-API-Token; a wrong token is rejected.
    assert client.get("/api/state", headers={"X-API-Token": "s3cr3t"}).status_code == 200
    assert client.get("/api/state", headers={"X-API-Token": "nope"}).status_code == 401


def test_browser_cookie_bootstrap(tmp_path, monkeypatch):
    monkeypatch.setenv("CODESCAN_API_TOKEN", "s3cr3t")
    client = _client(tmp_path)
    # Visiting /?token=SECRET sets the cookie; the TestClient jar then carries it.
    assert client.get("/", params={"token": "s3cr3t"}).status_code == 200
    assert client.cookies.get("codescan_token") == "s3cr3t"
    assert client.get("/api/state").status_code == 200


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

    r = client.post(f"/api/findings/{fid}/state",
                    json={"state": "risk_accepted", "note": "accepted for Q3"})
    assert r.status_code == 200
    assert r.json()["validation_state"] == "risk_accepted"
    assert r.json()["analyst_note"] == "accepted for Q3"

    # A rescan must preserve the analyst's decision — and the note.
    client.post("/api/scan", json={"use_ai": False, "offline": True})
    findings = client.get("/api/state").json()["findings"]
    reran = next(f for f in findings if f["id"] == fid)
    assert reran["validation_state"] == "risk_accepted"
    assert reran["analyst_note"] == "accepted for Q3"


def test_calibration_endpoint(tmp_path):
    client = _client(tmp_path)
    findings = client.get("/api/state").json()["findings"]

    # No manual decisions yet -> an empty, renderable report.
    assert client.get("/api/calibration").json()["decisions"] == 0

    client.post(f"/api/findings/{findings[0]['id']}/state", json={"state": "confirmed"})
    client.post(f"/api/findings/{findings[1]['id']}/state", json={"state": "false_positive"})
    report = client.get("/api/calibration").json()

    assert report["decisions"] == 2
    assert report["confirmed"] == 1 and report["false_positives"] == 1
    # Both decisions carried a score snapshot, so both landed in a bucket.
    assert sum(b["total"] for b in report["buckets"]) == 2
    # Drift alerting rides the report (silent here: too little evidence).
    assert report["alerts"] == []


def test_calibration_alerts_config_round_trip(tmp_path):
    client = _client(tmp_path)
    assert client.get("/api/config").json()["calibration"] == {"alerts_enabled": True}
    updated = client.post("/api/config", json={"calibration": {"alerts_enabled": False}}).json()
    assert updated["calibration"]["alerts_enabled"] is False


def test_rate_limit_returns_429_on_flood(tmp_path, monkeypatch):
    # Force a small burst so the flood is cheap and deterministic.
    from codescan.ratelimit import RateLimiter
    real_init = RateLimiter.__init__
    monkeypatch.setattr(RateLimiter, "__init__",
                        lambda self, rpm, burst: real_init(self, rpm=60, burst=3))
    client = _client(tmp_path)

    codes = [client.get("/api/state").status_code for _ in range(8)]
    assert codes[:3] == [200, 200, 200]             # burst allowed
    assert 429 in codes                              # then throttled
    limited = client.get("/api/state")
    assert limited.status_code == 429 and limited.headers.get("Retry-After") == "1"
    # The liveness probe is not under /api and is never throttled.
    assert client.get("/healthz").status_code == 200


def test_rate_limit_config_surfaced_read_only(tmp_path):
    server = _client(tmp_path).get("/api/config").json()["server"]
    assert server["rate_limit_enabled"] is True
    assert server["max_findings_per_scan"] == 5000


def test_rate_limit_wraps_auth_so_bad_token_floods_are_throttled(tmp_path, monkeypatch):
    # The limiter must sit OUTSIDE the token guard: a bad-token brute-force flood
    # has to hit 429, not an unlimited stream of 401s.
    monkeypatch.setenv("CODESCAN_API_TOKEN", "s3cr3t")
    from codescan.ratelimit import RateLimiter
    real_init = RateLimiter.__init__
    monkeypatch.setattr(RateLimiter, "__init__",
                        lambda self, rpm, burst: real_init(self, rpm=60, burst=3))
    client = _client(tmp_path)

    codes = [client.get("/api/state", headers={"X-API-Token": "wrong"}).status_code
             for _ in range(8)]
    assert codes[:3] == [401, 401, 401]     # burst passes the limiter, guard rejects
    assert 429 in codes[3:]                 # then the limiter throttles the brute-force


def test_invalid_state_rejected(tmp_path):
    client = _client(tmp_path)
    fid = client.get("/api/state").json()["findings"][0]["id"]
    assert client.post(f"/api/findings/{fid}/state", json={"state": "invalid_state"}).status_code == 400
    assert client.post("/api/findings/invalid-id/state", json={"state": "confirmed"}).status_code == 404


def test_chain_state_persists_and_suppresses(tmp_path):
    import pytest

    from codescan.models import ValidationState
    from codescan.validation import StateStore
    from codescan.web import AppState

    st = AppState(str(ROOT / "config" / "config.example.yaml"), str(ROOT / "fixtures"),
                  False, False, True, str(tmp_path / "sn.json"),
                  str(tmp_path / "state.json"), str(tmp_path / "ov.json"))
    st.result.chains = [{"chain_id": "CH-1", "fingerprint": "abc", "chain_score": 70,
                         "finding_ids": [], "validation_state": "new"}]

    updated = st.set_chain_state("abc", "false_positive", note="steps don't connect")
    assert updated["validation_state"] == "false_positive"
    # Persisted under the chain key, so a rescan re-applies it…
    assert StateStore(tmp_path / "state.json").chain_state("abc") == ValidationState.false_positive
    # …and the dismissed chain no longer reaches the ServiceNow export context.
    for item in st.servicenow_items():
        assert "CH-1" not in item.get("work_notes", "")

    with pytest.raises(ValueError):
        st.set_chain_state("abc", "risk_accepted")      # lifecycle states are for findings
    with pytest.raises(KeyError):
        st.set_chain_state("missing", "confirmed")


def test_chain_endpoint_unknown_fingerprint_404(tmp_path):
    r = _client(tmp_path).post("/api/chains/deadbeef/state", json={"state": "confirmed"})
    assert r.status_code == 404


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
    assert body["options"]["ai_providers"] == ["anthropic", "openai", "google", "foundry"]

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


def test_feedback_config_round_trip(tmp_path):
    client = _client(tmp_path)
    body = client.get("/api/config").json()
    assert body["feedback"] == {"enabled": True, "prompt_history": True}

    updated = client.post("/api/config", json={
        "feedback": {"enabled": True, "prompt_history": False},
    }).json()
    assert updated["feedback"]["prompt_history"] is False


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
