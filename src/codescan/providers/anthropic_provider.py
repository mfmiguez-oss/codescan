"""Anthropic provider — native structured outputs, adaptive thinking, effort,
and Fable refusal fallbacks. The reference implementation of the harness."""

from __future__ import annotations

import json
import logging
import time
from typing import Any

import anthropic

from .base import CompletionRequest, LLMProvider

logger = logging.getLogger(__name__)

# Capability matrix (substring match on model id).
_EFFORT_MODELS = ("opus-4-5", "opus-4-6", "opus-4-7", "opus-4-8", "sonnet-5", "sonnet-4-6", "fable", "mythos")
_ADAPTIVE_MODELS = ("opus-4-6", "opus-4-7", "opus-4-8", "sonnet-5", "sonnet-4-6", "fable", "mythos")


def _has(model: str, subs: tuple[str, ...]) -> bool:
    return any(s in model for s in subs)


class AnthropicProvider(LLMProvider):
    name = "anthropic"
    supports_batch = True

    def __init__(self) -> None:
        self._client: anthropic.Anthropic | None = None

    @property
    def client(self) -> anthropic.Anthropic:
        if self._client is None:
            self._client = anthropic.Anthropic()   # resolves ANTHROPIC_API_KEY / profile
        return self._client

    @staticmethod
    def _base_params(req: CompletionRequest) -> dict:
        """Model + structured-output params shared by the streaming and batch paths."""
        output_config: dict = {"format": {"type": "json_schema", "schema": req.schema}}
        if _has(req.model, _EFFORT_MODELS):
            output_config["effort"] = req.effort
        params: dict = dict(
            model=req.model, max_tokens=req.max_tokens, system=req.system,
            messages=[{"role": "user", "content": req.user}], output_config=output_config,
        )
        if _has(req.model, _ADAPTIVE_MODELS):
            params["thinking"] = {"type": "adaptive"}
        return params

    def complete_json(self, req: CompletionRequest) -> dict:
        kwargs = self._base_params(req)

        # Fable/Mythos: security tooling can trip false-positive refusals — opt into
        # server-side fallback so the request is re-served on Opus 4.8 in the same call.
        msg: Any  # beta vs standard stream return slightly different SDK types
        if req.model.startswith("claude-fable") or req.model.startswith("claude-mythos"):
            kwargs["betas"] = ["server-side-fallback-2026-06-01"]
            kwargs["fallbacks"] = [{"model": "claude-opus-4-8"}]
            with self.client.beta.messages.stream(**kwargs) as stream:
                msg = stream.get_final_message()
        else:
            with self.client.messages.stream(**kwargs) as stream:
                msg = stream.get_final_message()

        if msg.stop_reason == "refusal":
            raise RuntimeError(
                f"anthropic model {req.model} refused: {getattr(msg, 'stop_details', None)}"
            )
        text = next((b.text for b in msg.content if b.type == "text"), "{}")
        return json.loads(text)

    def complete_json_batch(
        self,
        requests: list[tuple[str, CompletionRequest]],
        *,
        poll_seconds: int = 30,
        max_wait_seconds: int = 3600,
    ) -> dict[str, dict]:
        """Submit requests as one Message Batch (~50% cost), poll, and collect.

        Non-streaming params (no HTTP-timeout concern — the batch is async) and no
        Fable fallbacks (the Batches API rejects them; callers keep Fable on the
        synchronous path). Per-item failures/refusals are logged and skipped.
        """
        payload = [{"custom_id": cid, "params": self._base_params(req)} for cid, req in requests]
        # The SDK types `requests` as Iterable[Request] (a TypedDict) but accepts
        # plain dicts at runtime; dicts avoid importing version-specific helpers.
        batch = self.client.messages.batches.create(requests=payload)  # type: ignore[arg-type]
        logger.info("submitted batch %s (%d requests)", batch.id, len(payload))

        deadline = time.monotonic() + max_wait_seconds
        while self.client.messages.batches.retrieve(batch.id).processing_status != "ended":
            if time.monotonic() >= deadline:
                raise RuntimeError(f"batch {batch.id} unfinished after {max_wait_seconds}s")
            time.sleep(poll_seconds)

        out: dict[str, dict] = {}
        for result in self.client.messages.batches.results(batch.id):
            if result.result.type != "succeeded":
                logger.warning("batch %s item %s: %s", batch.id, result.custom_id, result.result.type)
                continue
            msg = result.result.message
            if getattr(msg, "stop_reason", None) == "refusal":
                logger.warning("batch %s item %s refused", batch.id, result.custom_id)
                continue
            text = next((b.text for b in msg.content if b.type == "text"), "{}")
            out[result.custom_id] = json.loads(text)
        logger.info("batch %s ended: %d/%d succeeded", batch.id, len(out), len(payload))
        return out
