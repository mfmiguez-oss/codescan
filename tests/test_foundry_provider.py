"""Microsoft Foundry provider tests — client selection, request shape, contract.

No network: clients are either constructed against fake endpoints or replaced
with fakes; the anthropic/openai SDKs are exercised only for construction.
"""

from __future__ import annotations

import pytest

from codescan.providers import PROVIDERS, get_provider
from codescan.providers.base import CompletionRequest
from codescan.providers.foundry_provider import FoundryProvider

_ENV_VARS = (
    "FOUNDRY_API_KEY", "AZURE_OPENAI_API_KEY", "FOUNDRY_RESOURCE",
    "FOUNDRY_BASE_URL", "AZURE_OPENAI_BASE_URL",
    "FOUNDRY_API_VERSION", "AZURE_OPENAI_API_VERSION",
)


@pytest.fixture(autouse=True)
def _clean_env(monkeypatch):
    for var in _ENV_VARS:
        monkeypatch.delenv(var, raising=False)


def _req(**kw) -> CompletionRequest:
    base = dict(model="claude-opus-4-8", system="sys", user="user",
                schema={"type": "object"}, max_tokens=500)
    base.update(kw)
    return CompletionRequest(**base)


def test_foundry_is_the_only_provider():
    assert PROVIDERS == ["foundry"]
    assert isinstance(get_provider("foundry"), FoundryProvider)
    assert isinstance(get_provider(""), FoundryProvider)      # default
    with pytest.raises(RuntimeError):
        get_provider("anthropic")


# --- client construction ---------------------------------------------------

def test_missing_api_key_is_a_clear_error(monkeypatch):
    monkeypatch.setenv("FOUNDRY_RESOURCE", "myresource")
    with pytest.raises(RuntimeError, match="FOUNDRY_API_KEY"):
        _ = FoundryProvider().anthropic_client
    with pytest.raises(RuntimeError, match="FOUNDRY_API_KEY"):
        _ = FoundryProvider().openai_client


def test_claude_models_need_the_foundry_resource(monkeypatch):
    monkeypatch.setenv("FOUNDRY_API_KEY", "test-key")
    with pytest.raises(RuntimeError, match="FOUNDRY_RESOURCE"):
        _ = FoundryProvider().anthropic_client


def test_openai_compat_endpoint_derived_from_resource(monkeypatch):
    openai = pytest.importorskip("openai")
    monkeypatch.setenv("FOUNDRY_API_KEY", "test-key")
    monkeypatch.setenv("FOUNDRY_RESOURCE", "myresource")

    client = FoundryProvider().openai_client

    assert isinstance(client, openai.OpenAI)
    assert not isinstance(client, openai.AzureOpenAI)
    assert str(client.base_url).startswith("https://myresource.services.ai.azure.com/openai/v1")


def test_explicit_base_url_wins(monkeypatch):
    pytest.importorskip("openai")
    monkeypatch.setenv("FOUNDRY_API_KEY", "test-key")
    monkeypatch.setenv("FOUNDRY_RESOURCE", "myresource")
    monkeypatch.setenv("FOUNDRY_BASE_URL", "https://example.test/openai/v1/")

    client = FoundryProvider().openai_client

    assert str(client.base_url).startswith("https://example.test/openai/v1")


def test_api_version_selects_azure_client(monkeypatch):
    openai = pytest.importorskip("openai")
    monkeypatch.setenv("AZURE_OPENAI_API_KEY", "test-key")
    monkeypatch.setenv("AZURE_OPENAI_BASE_URL", "https://example.openai.azure.com")
    monkeypatch.setenv("AZURE_OPENAI_API_VERSION", "2024-10-21")

    client = FoundryProvider().openai_client

    assert isinstance(client, openai.AzureOpenAI)


def test_anthropic_client_targets_the_foundry_resource(monkeypatch):
    pytest.importorskip("anthropic")
    monkeypatch.setenv("FOUNDRY_API_KEY", "test-key")
    monkeypatch.setenv("FOUNDRY_RESOURCE", "myresource")

    client = FoundryProvider().anthropic_client

    assert "myresource" in str(client.base_url)


# --- request routing + shape ----------------------------------------------

class _FakeStream:
    def __init__(self, msg):
        self._msg = msg

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False

    def get_final_message(self):
        return self._msg


class _Msg:
    def __init__(self, stop_reason="end_turn", text='{"ok": true}'):
        self.stop_reason = stop_reason
        self.stop_details = None
        self.content = [type("Block", (), {"type": "text", "text": text})]


def _fake_anthropic(captured, msg):
    class _Messages:
        def stream(self, **kwargs):
            captured.update(kwargs)
            return _FakeStream(msg)

    class _Client:
        messages = _Messages()
        beta = type("Beta", (), {"messages": _Messages()})()

    return _Client()


def test_claude_request_uses_structured_outputs():
    captured: dict = {}
    provider = FoundryProvider()
    provider._anthropic_client = _fake_anthropic(captured, _Msg())

    out = provider.complete_json(_req(model="claude-opus-4-8", effort="xhigh"))

    assert out == {"ok": True}
    assert captured["output_config"]["format"]["type"] == "json_schema"
    assert captured["output_config"]["effort"] == "xhigh"
    assert captured["thinking"] == {"type": "adaptive"}
    assert captured["max_tokens"] == 500


def test_claude_refusal_is_an_actionable_error():
    provider = FoundryProvider()
    provider._anthropic_client = _fake_anthropic({}, _Msg(stop_reason="refusal"))

    with pytest.raises(RuntimeError, match="claude-opus-4-8"):
        provider.complete_json(_req(model="claude-fable-5"))


def test_other_models_use_chat_completions_contract():
    captured: dict = {}

    class FakeCompletions:
        def create(self, **kwargs):
            captured.update(kwargs)
            msg = type("Msg", (), {"content": '{"ok": true}'})
            choice = type("Choice", (), {"message": msg})
            return type("Resp", (), {"choices": [choice]})

    class FakeClient:
        chat = type("Chat", (), {"completions": FakeCompletions()})()

    provider = FoundryProvider()
    provider._openai_client = FakeClient()

    out = provider.complete_json(_req(model="mistral-large-2411"))

    assert out == {"ok": True}
    assert captured["model"] == "mistral-large-2411"
    assert captured["response_format"] == {"type": "json_object"}
    assert captured["max_completion_tokens"] == 500
    assert "single JSON object matching this schema" in captured["messages"][0]["content"]
    assert captured["messages"][1] == {"role": "user", "content": "user"}
