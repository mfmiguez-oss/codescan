"""Enterprise / Fable-5 tuning — data residency, retention errors, config profile."""

from __future__ import annotations

from pathlib import Path

import anthropic
import httpx
import pytest

from codescan import providers
from codescan.config import AIConfig, Config
from codescan.llm import LLMClient, ModelRouter
from codescan.providers.anthropic_provider import AnthropicProvider
from codescan.providers.base import CompletionRequest, LLMProvider

ROOT = Path(__file__).resolve().parents[1]


@pytest.fixture(autouse=True)
def _restore_registry():
    saved = dict(providers._INSTANCES)
    yield
    providers._INSTANCES.clear()
    providers._INSTANCES.update(saved)


def _req(**kw):
    base = dict(model="claude-opus-4-8", system="s", user="u", schema={})
    base.update(kw)
    return CompletionRequest(**base)


def test_base_params_carries_inference_geo():
    p = AnthropicProvider._base_params(_req(inference_geo="eu"))
    assert p["inference_geo"] == "eu"                 # data residency threaded (both paths)


def test_base_params_omits_empty_inference_geo():
    assert "inference_geo" not in AnthropicProvider._base_params(_req())


def test_llmclient_threads_inference_geo():
    captured = {}

    class Fake(LLMProvider):
        name = "anthropic"

        def complete_json(self, req):
            captured["geo"] = req.inference_geo
            return {}

    providers._INSTANCES["anthropic"] = Fake()
    LLMClient(ModelRouter(AIConfig(inference_geo="us"))).complete_json("exploitability", "s", "u", {})
    assert captured["geo"] == "us"


def test_fable_retention_400_is_actionable():
    err = anthropic.BadRequestError(
        "zero data retention", response=httpx.Response(400, request=httpx.Request("POST", "https://api")),
        body=None,
    )

    class _Msgs:
        def stream(self, **kw):
            raise err

    class _Client:
        beta = type("B", (), {"messages": _Msgs()})()

    provider = AnthropicProvider()
    provider._client = _Client()   # type: ignore[assignment]
    with pytest.raises(RuntimeError, match="30-day data retention"):
        provider.complete_json(_req(model="claude-fable-5"))


def test_enterprise_profile_routes_deep_tasks_to_fable():
    cfg = Config.load(ROOT / "config" / "config.enterprise.yaml")
    for task in ("exploitability", "threat_model", "openhack"):
        assert cfg.ai.tasks[task].model == "claude-fable-5"
    assert cfg.ai.tasks["dedup"].model == "claude-haiku-4-5"     # mechanical stays cheap
    assert cfg.storage.backend == "sql" and cfg.audit.http.enabled  # HA + SIEM wired
