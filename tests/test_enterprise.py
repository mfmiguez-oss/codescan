"""Enterprise profile tests — Fable-5-on-Foundry routing, HA + SIEM wiring."""

from __future__ import annotations

from pathlib import Path

from codescan.config import Config

ROOT = Path(__file__).resolve().parents[1]


def test_enterprise_profile_routes_deep_tasks_to_fable():
    cfg = Config.load(ROOT / "config" / "config.enterprise.yaml")
    assert cfg.ai.provider == "foundry"
    for task in ("exploitability", "threat_model", "openhack"):
        assert cfg.ai.tasks[task].model == "claude-fable-5"
    assert cfg.ai.tasks["dedup"].model == "claude-haiku-4-5"     # mechanical stays cheap
    assert cfg.storage.backend == "sql" and cfg.audit.http.enabled  # HA + SIEM wired
