"""Multi-provider harness tests — registry, dispatch, JSON parsing. No network."""

from __future__ import annotations

import pytest

import codescan.llm as llm_mod
from codescan.config import AIConfig, TaskModel
from codescan.llm import LLMClient, ModelRouter
from codescan.providers import PROVIDERS, get_provider
from codescan.providers.anthropic_provider import AnthropicProvider
from codescan.providers.base import CompletionRequest, build_json_instruction, extract_json
from codescan.providers.google_provider import GoogleProvider
from codescan.providers.openai_provider import OpenAIProvider


def test_registry_resolves_suppliers():
    assert set(PROVIDERS) == {"anthropic", "openai", "google"}
    assert isinstance(get_provider("anthropic"), AnthropicProvider)
    assert isinstance(get_provider("openai"), OpenAIProvider)
    assert isinstance(get_provider("google"), GoogleProvider)
    assert get_provider("anthropic") is get_provider("anthropic")   # cached
    with pytest.raises(RuntimeError):
        get_provider("acme")


def test_extract_json_variants():
    assert extract_json('{"a": 1}') == {"a": 1}
    assert extract_json('```json\n{"a": 1}\n```') == {"a": 1}
    assert extract_json('Sure — here it is: {"a": 1}. Done.') == {"a": 1}
    with pytest.raises(RuntimeError):
        extract_json("no json here")


def test_build_json_instruction_includes_schema():
    req = CompletionRequest(
        model="gpt-4.1",
        system="system prompt",
        user="user prompt",
        schema={"type": "object", "properties": {"ok": {"type": "boolean"}}},
    )

    instruction = build_json_instruction(req)

    assert instruction.startswith("Respond ONLY with a single JSON object matching this schema:")
    assert '"type": "object"' in instruction


def test_llmclient_dispatches_to_routed_provider(monkeypatch):
    captured = {}

    class Fake:
        def complete_json(self, req):
            captured.update(model=req.model, effort=req.effort, max_tokens=req.max_tokens)
            return {"ok": True}

    def fake_get_provider(name):
        captured["provider"] = name
        return Fake()

    monkeypatch.setattr(llm_mod, "get_provider", fake_get_provider)

    cfg = AIConfig(tasks={
        "exploitability": TaskModel(provider="openai", model="gpt-5", effort="high", max_tokens=1234),
    })
    client = LLMClient(ModelRouter(cfg))
    out = client.complete_json("exploitability", "sys", "user", {"type": "object"})

    assert out == {"ok": True}
    assert captured == {"provider": "openai", "model": "gpt-5", "effort": "high", "max_tokens": 1234}
