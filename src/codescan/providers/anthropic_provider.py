"""Anthropic provider — native structured outputs, adaptive thinking, effort,
and Fable refusal fallbacks. The reference implementation of the harness."""

from __future__ import annotations

import json

import anthropic

from .base import CompletionRequest, LLMProvider

# Capability matrix (substring match on model id).
_EFFORT_MODELS = ("opus-4-5", "opus-4-6", "opus-4-7", "opus-4-8", "sonnet-5", "sonnet-4-6", "fable", "mythos")
_ADAPTIVE_MODELS = ("opus-4-6", "opus-4-7", "opus-4-8", "sonnet-5", "sonnet-4-6", "fable", "mythos")


def _has(model: str, subs: tuple[str, ...]) -> bool:
    return any(s in model for s in subs)


class AnthropicProvider(LLMProvider):
    name = "anthropic"

    def __init__(self) -> None:
        self._client: anthropic.Anthropic | None = None

    @property
    def client(self) -> anthropic.Anthropic:
        if self._client is None:
            self._client = anthropic.Anthropic()   # resolves ANTHROPIC_API_KEY / profile
        return self._client

    def complete_json(self, req: CompletionRequest) -> dict:
        output_config: dict = {"format": {"type": "json_schema", "schema": req.schema}}
        if _has(req.model, _EFFORT_MODELS):
            output_config["effort"] = req.effort

        kwargs: dict = dict(
            model=req.model, max_tokens=req.max_tokens, system=req.system,
            messages=[{"role": "user", "content": req.user}], output_config=output_config,
        )
        if _has(req.model, _ADAPTIVE_MODELS):
            kwargs["thinking"] = {"type": "adaptive"}

        # Fable/Mythos: security tooling can trip false-positive refusals — opt into
        # server-side fallback so the request is re-served on Opus 4.8 in the same call.
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
