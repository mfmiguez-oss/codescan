"""Batches API — LLMClient fan-out modes + AnthropicProvider batch collection.

No network: a fake provider is injected into the registry, and the Anthropic
provider is driven with a fake `client.messages.batches`.
"""

from __future__ import annotations

import pytest

from codescan import providers
from codescan.config import AIConfig
from codescan.llm import BatchItem, LLMClient, ModelRouter
from codescan.providers.anthropic_provider import AnthropicProvider
from codescan.providers.base import CompletionRequest, LLMProvider


@pytest.fixture(autouse=True)
def _restore_registry():
    saved = dict(providers._INSTANCES)
    yield
    providers._INSTANCES.clear()
    providers._INSTANCES.update(saved)


class FakeProvider(LLMProvider):
    name = "anthropic"
    supports_batch = True

    def __init__(self, batch_fn=None):
        self.batch_calls: list[list[str]] = []
        self.sync_models: list[str] = []
        self._batch_fn = batch_fn

    def complete_json(self, req):
        self.sync_models.append(req.model)
        return {"via": "sync", "model": req.model}

    def complete_json_batch(self, requests, *, poll_seconds, max_wait_seconds):
        if self._batch_fn:
            return self._batch_fn(requests)
        self.batch_calls.append([cid for cid, _ in requests])
        return {cid: {"via": "batch", "model": r.model} for cid, r in requests}


def _items():
    return [BatchItem("repoA", "sys", "u"), BatchItem("repoB", "sys", "u")]


def _client(**ai):
    return LLMClient(ModelRouter(AIConfig(**ai)))


def test_sync_path_when_batch_off():
    fake = FakeProvider()
    providers._INSTANCES["anthropic"] = fake
    res = _client(batch=False, model="claude-opus-4-8").complete_json_many("exploitability", _items(), {})
    assert set(res) == {"repoA", "repoB"}
    assert all(v["via"] == "sync" for v in res.values())
    assert fake.batch_calls == []


def test_batch_path_when_enabled():
    fake = FakeProvider()
    providers._INSTANCES["anthropic"] = fake
    res = _client(batch=True, model="claude-opus-4-8").complete_json_many("exploitability", _items(), {})
    assert all(v["via"] == "batch" for v in res.values())        # one batch, both keys
    assert fake.batch_calls == [["b0", "b1"]] and fake.sync_models == []


def test_fable_excluded_from_batch():
    # Fable needs refusal fallbacks the Batches API rejects -> stays synchronous.
    fake = FakeProvider()
    providers._INSTANCES["anthropic"] = fake
    res = _client(batch=True, model="claude-fable-5").complete_json_many("exploitability", _items(), {})
    assert all(v["via"] == "sync" for v in res.values())
    assert fake.batch_calls == []


def test_batch_error_falls_back_to_sync():
    def boom(_requests):
        raise RuntimeError("batch service down")

    fake = FakeProvider(batch_fn=boom)
    providers._INSTANCES["anthropic"] = fake
    res = _client(batch=True, model="claude-opus-4-8").complete_json_many("exploitability", _items(), {})
    assert set(res) == {"repoA", "repoB"}
    assert all(v["via"] == "sync" for v in res.values())         # degraded to sync


# --- AnthropicProvider.complete_json_batch (fake batches client) -----------

class _Msg:
    def __init__(self, text, stop="end_turn"):
        self.content = [type("B", (), {"type": "text", "text": text})()]
        self.stop_reason = stop


class _Item:
    def __init__(self, cid, rtype="succeeded", text='{"ok": 1}', stop="end_turn"):
        self.custom_id = cid
        self.result = type("R", (), {"type": rtype, "message": _Msg(text, stop)})()


class _Batches:
    def __init__(self, items):
        self._items = items
    def create(self, requests):
        self.requests = requests
        return type("B", (), {"id": "batch_1"})()
    def retrieve(self, _bid):
        return type("B", (), {"processing_status": "ended"})()
    def results(self, _bid):
        return iter(self._items)


def _req(cid):
    return (cid, CompletionRequest(model="claude-opus-4-8", system="s", user="u", schema={}))


def test_provider_batch_collects_and_skips_failures():
    items = [
        _Item("b0", text='{"x": 1}'),
        _Item("b1", rtype="errored"),                  # skipped
        _Item("b2", text="{}", stop="refusal"),        # skipped
    ]
    p = AnthropicProvider()
    p._client = type("C", (), {"messages": type("M", (), {"batches": _Batches(items)})()})()
    out = p.complete_json_batch([_req("b0"), _req("b1"), _req("b2")], poll_seconds=0, max_wait_seconds=5)
    assert out == {"b0": {"x": 1}}
