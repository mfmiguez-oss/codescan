"""Microsoft Foundry provider tests — registry, client selection, contract. No network."""

from __future__ import annotations

import pytest

from codescan.providers import PROVIDERS, get_provider
from codescan.providers.base import CompletionRequest
from codescan.providers.foundry_provider import FoundryProvider

_ENV_VARS = (
    "FOUNDRY_API_KEY", "AZURE_OPENAI_API_KEY",
    "FOUNDRY_BASE_URL", "AZURE_OPENAI_BASE_URL",
    "FOUNDRY_API_VERSION", "AZURE_OPENAI_API_VERSION",
)


@pytest.fixture(autouse=True)
def _clean_env(monkeypatch):
    for var in _ENV_VARS:
        monkeypatch.delenv(var, raising=False)


def test_registered_in_harness():
    assert "foundry" in PROVIDERS
    assert isinstance(get_provider("foundry"), FoundryProvider)


def test_missing_api_key_is_a_clear_error(monkeypatch):
    monkeypatch.setenv("FOUNDRY_BASE_URL", "https://example.test/openai/v1/")
    with pytest.raises(RuntimeError, match="FOUNDRY_API_KEY"):
        _ = FoundryProvider().client


def test_missing_base_url_is_a_clear_error(monkeypatch):
    monkeypatch.setenv("FOUNDRY_API_KEY", "test-key")
    with pytest.raises(RuntimeError, match="FOUNDRY_BASE_URL"):
        _ = FoundryProvider().client


def test_openai_compatible_endpoint_uses_plain_client(monkeypatch):
    openai = pytest.importorskip("openai")
    monkeypatch.setenv("FOUNDRY_API_KEY", "test-key")
    monkeypatch.setenv("FOUNDRY_BASE_URL", "https://example.test/openai/v1/")

    client = FoundryProvider().client

    assert isinstance(client, openai.OpenAI)
    assert not isinstance(client, openai.AzureOpenAI)
    assert str(client.base_url).startswith("https://example.test/openai/v1")


def test_api_version_selects_azure_client(monkeypatch):
    openai = pytest.importorskip("openai")
    monkeypatch.setenv("AZURE_OPENAI_API_KEY", "test-key")
    monkeypatch.setenv("AZURE_OPENAI_BASE_URL", "https://example.openai.azure.com")
    monkeypatch.setenv("AZURE_OPENAI_API_VERSION", "2024-10-21")

    client = FoundryProvider().client

    assert isinstance(client, openai.AzureOpenAI)


def test_complete_json_contract():
    captured = {}

    class FakeCompletions:
        def create(self, **kwargs):
            captured.update(kwargs)
            msg = type("Msg", (), {"content": '{"ok": true}'})
            choice = type("Choice", (), {"message": msg})
            return type("Resp", (), {"choices": [choice]})

    class FakeClient:
        chat = type("Chat", (), {"completions": FakeCompletions()})()

    provider = FoundryProvider()
    provider._client = FakeClient()
    req = CompletionRequest(
        model="my-deployment", system="sys", user="user",
        schema={"type": "object"}, max_tokens=500,
    )

    out = provider.complete_json(req)

    assert out == {"ok": True}
    assert captured["model"] == "my-deployment"
    assert captured["response_format"] == {"type": "json_object"}
    assert captured["max_completion_tokens"] == 500
    assert "single JSON object matching this schema" in captured["messages"][0]["content"]
    assert captured["messages"][1] == {"role": "user", "content": "user"}
