"""Task-based model routing over the Microsoft Foundry provider.

Each pipeline task resolves to a `ModelSpec` (provider + model + effort + token
budget). `LLMClient.complete_json` dispatches through the provider registry, so
different tasks can run on different Foundry model deployments — e.g. dedup on
Claude Haiku, exploitability on Claude Opus, threat modeling on GPT or Mistral
— all set in config.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, replace
from typing import NamedTuple

from .concurrency import resilient_map
from .config import AIConfig, TaskModel
from .providers import CompletionRequest, get_provider

logger = logging.getLogger(__name__)


class BatchItem(NamedTuple):
    """One structured-output request in a fan-out (`complete_json_many`)."""

    custom_id: str          # caller's key for the result (any string)
    system: str
    user: str
    difficulty: str | None = None   # auto-route hint


@dataclass(frozen=True)
class ModelSpec:
    provider: str
    model: str
    effort: str
    max_tokens: int


# Built-in per-task tiers. Anything not listed uses the default tier (config
# ai.provider/model/effort/max_tokens). Config ai.tasks.<name> overrides.
_BUILTIN_TASKS: dict[str, ModelSpec] = {
    "dedup": ModelSpec("foundry", "claude-haiku-4-5", "low", 8000),
    "enrichment": ModelSpec("foundry", "claude-haiku-4-5", "low", 8000),
}

# Claude capability ladder, cheapest → most capable. `auto_route` shifts a task's
# resolved model along this ladder by the difficulty delta below. Ladder-only: a
# model not on it (a custom deployment name, or another family's) is never
# auto-shifted.
_MODEL_LADDER: tuple[str, ...] = (
    "claude-haiku-4-5", "claude-sonnet-5", "claude-opus-4-8", "claude-fable-5",
)
# One rung per difficulty bucket. "normal" is a no-op.
_DIFFICULTY_DELTA: dict[str, int] = {"low": -1, "normal": 0, "high": +1}


def auto_route(spec: ModelSpec, difficulty: str) -> ModelSpec:
    """Shift `spec` up/down the Claude ladder by difficulty; a no-op otherwise.

    Returns `spec` unchanged for models off the ladder, unknown difficulties,
    or when the shift is clamped to the same rung.
    """
    delta = _DIFFICULTY_DELTA.get(difficulty, 0)
    if delta == 0 or spec.model not in _MODEL_LADDER:
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

    def override(self, task: str, task_model: TaskModel) -> ModelSpec:
        """A task's baseline spec with a per-call override layered on (unset fields
        inherit the baseline). Used to route each OpenHack pass to its own model."""
        base = self.resolve(task)
        return ModelSpec(
            task_model.provider or base.provider,
            task_model.model or base.model,
            task_model.effort or base.effort,
            task_model.max_tokens or base.max_tokens,
        )


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

    def resolve_spec(self, task: str, override: TaskModel | None = None) -> ModelSpec:
        """Routed spec for a task, or the task baseline with `override` layered on."""
        return self.router.override(task, override) if override else self.router.resolve(task)

    def complete_json(
        self, task: str, system: str, user: str, schema: dict, *,
        difficulty: str | None = None, spec: ModelSpec | None = None,
    ) -> dict:
        # An explicit `spec` (e.g. a per-pass model override) wins over routing.
        spec = spec or self.router.resolve(task, difficulty)
        logger.debug("task=%s -> %s/%s (effort=%s, difficulty=%s)",
                     task, spec.provider, spec.model, spec.effort, difficulty or "-")
        provider = get_provider(spec.provider)
        req = CompletionRequest(
            model=spec.model, system=system, user=user, schema=schema,
            effort=spec.effort, max_tokens=spec.max_tokens,
        )
        return provider.complete_json(req)

    def complete_json_many(
        self, task: str, items: list[BatchItem], schema: dict
    ) -> dict[str, dict]:
        """Run many structured-output requests for `task`; return {custom_id: json}.

        Runs concurrently (bounded by ai.max_concurrency), isolating per-item
        failures. A failed item is simply omitted from the result (callers skip it).
        """
        items = list(items)
        if not items:
            return {}
        pairs, _failed = resilient_map(
            lambda it: (it.custom_id, self.complete_json(
                task, it.system, it.user, schema, difficulty=it.difficulty)),
            items, self.max_workers, describe=lambda it: it.custom_id,
        )
        return dict(pairs)
