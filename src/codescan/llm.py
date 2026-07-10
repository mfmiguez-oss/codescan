"""Task-based model routing over the multi-provider harness.

Each pipeline task resolves to a `ModelSpec` (provider + model + effort + token
budget). `LLMClient.complete_json` dispatches to the resolved supplier via the
provider registry, so different tasks can run on different models from different
suppliers — e.g. dedup on Anthropic Haiku, exploitability on OpenAI, threat
modeling on Google — all set in config.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, replace

from .config import AIConfig
from .providers import CompletionRequest, get_provider

logger = logging.getLogger(__name__)


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

# Anthropic capability ladder, cheapest → most capable. `auto_route` shifts a task's
# resolved model along this ladder by the difficulty delta below. Ladder-only: a
# model not on it (a custom id, or another supplier's) is never auto-shifted.
_MODEL_LADDER: tuple[str, ...] = (
    "claude-haiku-4-5", "claude-sonnet-5", "claude-opus-4-8", "claude-fable-5",
)
# One rung per difficulty bucket. "normal" is a no-op.
_DIFFICULTY_DELTA: dict[str, int] = {"low": -1, "normal": 0, "high": +1}


def auto_route(spec: ModelSpec, difficulty: str) -> ModelSpec:
    """Shift `spec` up/down the Anthropic ladder by difficulty; a no-op otherwise.

    Returns `spec` unchanged for non-Anthropic providers, models off the ladder,
    unknown difficulties, or when the shift is clamped to the same rung.
    """
    delta = _DIFFICULTY_DELTA.get(difficulty, 0)
    if delta == 0 or spec.provider != "anthropic" or spec.model not in _MODEL_LADDER:
        return spec
    idx = _MODEL_LADDER.index(spec.model)
    new_idx = min(max(idx + delta, 0), len(_MODEL_LADDER) - 1)
    if new_idx == idx:
        return spec
    return replace(spec, model=_MODEL_LADDER[new_idx])


class ModelRouter:
    def __init__(self, cfg: AIConfig) -> None:
        self.cfg = cfg

    def resolve(self, task: str, difficulty: str | None = None) -> ModelSpec:
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
        # Silent adaptive selection: nudge the resolved model along the ladder by
        # the caller's difficulty signal. Config tiers stay authoritative as the
        # baseline; auto-route only moves relative to them.
        if self.cfg.auto_route and difficulty:
            spec = auto_route(spec, difficulty)
        return spec


class LLMClient:
    """Runs a structured-output request for a task through the routed provider."""

    def __init__(self, router: ModelRouter) -> None:
        self.router = router

    @property
    def max_workers(self) -> int:
        """Bound on concurrent per-service AI calls (config ai.max_concurrency)."""
        return max(1, self.router.cfg.max_concurrency)

    def spec_for(self, task: str) -> ModelSpec:
        return self.router.resolve(task)

    def complete_json(
        self, task: str, system: str, user: str, schema: dict, *, difficulty: str | None = None
    ) -> dict:
        spec = self.router.resolve(task, difficulty)
        logger.debug("task=%s -> %s/%s (effort=%s, difficulty=%s)",
                     task, spec.provider, spec.model, spec.effort, difficulty or "-")
        provider = get_provider(spec.provider)
        req = CompletionRequest(
            model=spec.model, system=system, user=user, schema=schema,
            effort=spec.effort, max_tokens=spec.max_tokens,
        )
        return provider.complete_json(req)
