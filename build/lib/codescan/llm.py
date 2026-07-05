"""Model routing + a shared structured-output client.

Different pipeline tasks need different intelligence tiers. Semantic dedup is
mechanical pattern-matching — a cheap, fast model (Haiku) is plenty.
Exploitability and attack-chain reasoning are the hard part — they justify a
deep model (Opus 4.8 / Fable 5).

`ModelRouter` resolves a task name to a `ModelSpec` (model + effort + token
budget), using built-in defaults that config can override per task.
`LLMClient` runs the request, adapting the request shape to each model's
capabilities (Haiku doesn't take `effort` or adaptive thinking; Fable needs
refusal fallbacks) so callers don't have to care which tier they got.
"""

from __future__ import annotations

import json
from dataclasses import dataclass

import anthropic

from .config import AIConfig

# --- capability matrix (substring match on model id) ---------------------
# effort is supported on Opus 4.5+, Sonnet 5/4.6, Fable/Mythos — not Haiku 4.5.
_EFFORT_MODELS = ("opus-4-5", "opus-4-6", "opus-4-7", "opus-4-8", "sonnet-5", "sonnet-4-6", "fable", "mythos")
# adaptive thinking is 4.6+ / Fable / Mythos — not Haiku 4.5, not Opus 4.5.
_ADAPTIVE_MODELS = ("opus-4-6", "opus-4-7", "opus-4-8", "sonnet-5", "sonnet-4-6", "fable", "mythos")


def _has(model: str, subs: tuple[str, ...]) -> bool:
    return any(s in model for s in subs)


@dataclass(frozen=True)
class ModelSpec:
    model: str
    effort: str
    max_tokens: int

    @property
    def uses_fallbacks(self) -> bool:
        # Security tooling can trip Fable's false-positive classifier refusals;
        # server-side fallback re-serves on Opus 4.8 in the same call.
        return self.model.startswith("claude-fable") or self.model.startswith("claude-mythos")


# Built-in per-task tiers. Anything not listed falls back to the default tier
# (config `ai.model`/`effort`/`max_tokens`). Config `ai.tasks.<name>` overrides.
_BUILTIN_TASKS: dict[str, ModelSpec] = {
    "dedup": ModelSpec("claude-haiku-4-5", "low", 8000),
    "enrichment": ModelSpec("claude-haiku-4-5", "low", 8000),
}


class ModelRouter:
    def __init__(self, cfg: AIConfig) -> None:
        self.cfg = cfg

    def resolve(self, task: str) -> ModelSpec:
        default = ModelSpec(self.cfg.model, self.cfg.effort, self.cfg.max_tokens)
        spec = _BUILTIN_TASKS.get(task, default)
        override = self.cfg.tasks.get(task)
        if override:
            spec = ModelSpec(
                override.model or spec.model,
                override.effort or spec.effort,
                override.max_tokens or spec.max_tokens,
            )
        return spec


class LLMClient:
    """Runs a structured-output request for a given task through the router."""

    def __init__(self, router: ModelRouter, client: anthropic.Anthropic | None = None) -> None:
        self.router = router
        self.client = client or anthropic.Anthropic()

    def spec_for(self, task: str) -> ModelSpec:
        return self.router.resolve(task)

    def complete_json(self, task: str, system: str, user: str, schema: dict) -> dict:
        spec = self.router.resolve(task)
        output_config: dict = {"format": {"type": "json_schema", "schema": schema}}
        if _has(spec.model, _EFFORT_MODELS):
            output_config["effort"] = spec.effort

        kwargs: dict = dict(
            model=spec.model,
            max_tokens=spec.max_tokens,
            system=system,
            messages=[{"role": "user", "content": user}],
            output_config=output_config,
        )
        if _has(spec.model, _ADAPTIVE_MODELS):
            kwargs["thinking"] = {"type": "adaptive"}

        if spec.uses_fallbacks:
            kwargs["betas"] = ["server-side-fallback-2026-06-01"]
            kwargs["fallbacks"] = [{"model": "claude-opus-4-8"}]
            with self.client.beta.messages.stream(**kwargs) as stream:
                msg = stream.get_final_message()
        else:
            with self.client.messages.stream(**kwargs) as stream:
                msg = stream.get_final_message()

        if msg.stop_reason == "refusal":
            raise RuntimeError(
                f"Model {spec.model} refused task '{task}': "
                f"{getattr(msg, 'stop_details', None)}"
            )

        text = next((b.text for b in msg.content if b.type == "text"), "{}")
        return json.loads(text)
