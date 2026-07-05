"""Task-based model routing over the multi-provider harness.

Each pipeline task resolves to a `ModelSpec` (provider + model + effort + token
budget). `LLMClient.complete_json` dispatches to the resolved supplier via the
provider registry, so different tasks can run on different models from different
suppliers — e.g. dedup on Anthropic Haiku, exploitability on OpenAI, threat
modeling on Google — all set in config.
"""

from __future__ import annotations

from dataclasses import dataclass

from .config import AIConfig
from .providers import CompletionRequest, get_provider


@dataclass(frozen=True)
class ModelSpec:
    provider: str
    model: str
    effort: str
    max_tokens: int


# Built-in per-task tiers. Anything not listed uses the default tier (config
# ai.provider/model/effort/max_tokens). Config ai.tasks.<name> overrides.
_BUILTIN_TASKS: dict[str, ModelSpec] = {
    "dedup": ModelSpec("anthropic", "claude-haiku-4-5", "low", 8000),
    "enrichment": ModelSpec("anthropic", "claude-haiku-4-5", "low", 8000),
}


class ModelRouter:
    def __init__(self, cfg: AIConfig) -> None:
        self.cfg = cfg

    def resolve(self, task: str) -> ModelSpec:
        default = ModelSpec(self.cfg.provider, self.cfg.model, self.cfg.effort, self.cfg.max_tokens)
        spec = _BUILTIN_TASKS.get(task, default)
        override = self.cfg.tasks.get(task)
        if override:
            spec = ModelSpec(
                override.provider or spec.provider,
                override.model or spec.model,
                override.effort or spec.effort,
                override.max_tokens or spec.max_tokens,
            )
        return spec


class LLMClient:
    """Runs a structured-output request for a task through the routed provider."""

    def __init__(self, router: ModelRouter) -> None:
        self.router = router

    def spec_for(self, task: str) -> ModelSpec:
        return self.router.resolve(task)

    def complete_json(self, task: str, system: str, user: str, schema: dict) -> dict:
        spec = self.router.resolve(task)
        provider = get_provider(spec.provider)
        req = CompletionRequest(
            model=spec.model, system=system, user=user, schema=schema,
            effort=spec.effort, max_tokens=spec.max_tokens,
        )
        return provider.complete_json(req)
