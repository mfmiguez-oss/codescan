"""Model-router tests — pure resolution logic, no network or API key."""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from codescan.config import AIConfig, Config, TaskModel
from codescan.llm import ModelRouter, auto_route, ModelSpec


def test_unknown_config_key_is_rejected():
    # A typo'd setting must fail loudly, not be silently ignored.
    with pytest.raises(ValidationError):
        AIConfig(max_concurency=8)          # note the typo
    with pytest.raises(ValidationError):
        Config.model_validate({"servicnow": {"push": True}})   # typo'd section


def test_dedup_defaults_to_haiku():
    spec = ModelRouter(AIConfig()).resolve("dedup")
    assert spec.model == "claude-haiku-4-5"
    assert spec.provider == "foundry"


def test_unknown_task_uses_default_tier():
    router = ModelRouter(AIConfig(model="claude-opus-4-8", effort="high", max_tokens=32000))
    spec = router.resolve("exploitability")
    assert (spec.provider, spec.model, spec.effort) == ("foundry", "claude-opus-4-8", "high")


def test_config_override_wins_incl_model_family():
    cfg = AIConfig(
        model="claude-opus-4-8",
        tasks={
            "dedup": TaskModel(model="claude-sonnet-5", max_tokens=5000),
            # Route exploitability to a different model family on the resource.
            "exploitability": TaskModel(model="gpt-5", effort="high"),
        },
    )
    router = ModelRouter(cfg)
    dedup = router.resolve("dedup")
    assert dedup.model == "claude-sonnet-5" and dedup.max_tokens == 5000
    assert dedup.provider == "foundry"

    exploit = router.resolve("exploitability")
    assert exploit.provider == "foundry" and exploit.model == "gpt-5"


def test_default_model_propagates():
    cfg = AIConfig(model="gemini-2.5-pro")
    spec = ModelRouter(cfg).resolve("exploitability")   # unknown task -> default tier
    assert spec.provider == "foundry" and spec.model == "gemini-2.5-pro"


def test_override_layers_on_task_baseline():
    # Per-pass model override (openhack.pass_models) — unset fields inherit.
    router = ModelRouter(AIConfig(model="claude-opus-4-8", effort="high"))
    full = router.override("openhack", TaskModel(model="gpt-5"))
    assert (full.provider, full.model, full.effort) == ("foundry", "gpt-5", "high")

    partial = router.override("openhack", TaskModel(effort="low"))
    assert partial.provider == "foundry"            # inherited from the baseline
    assert partial.model == "claude-opus-4-8"
    assert partial.effort == "low"                   # overridden


def test_partial_override_inherits_default():
    cfg = AIConfig(model="claude-opus-4-8", effort="high",
                   tasks={"dedup": TaskModel(effort="medium")})
    spec = ModelRouter(cfg).resolve("dedup")
    assert spec.model == "claude-haiku-4-5"      # built-in
    assert spec.effort == "medium"               # overridden
    assert spec.provider == "foundry"            # inherited


# --- auto-route (silent adaptive model selection) --------------------------

def _opus():
    return ModelSpec("foundry", "claude-opus-4-8", "high", 32000)


def test_auto_route_off_by_default_no_shift():
    router = ModelRouter(AIConfig(model="claude-opus-4-8"))   # auto_route defaults False
    assert router.resolve("exploitability", difficulty="high").model == "claude-opus-4-8"
    assert router.resolve("exploitability", difficulty="low").model == "claude-opus-4-8"


def test_auto_route_downgrades_and_upgrades():
    router = ModelRouter(AIConfig(model="claude-opus-4-8", auto_route=True))
    assert router.resolve("x", difficulty="low").model == "claude-sonnet-5"    # down 1
    assert router.resolve("x", difficulty="normal").model == "claude-opus-4-8"  # unchanged
    assert router.resolve("x", difficulty="high").model == "claude-fable-5"    # up 1


def test_auto_route_clamps_at_ladder_ends():
    # Haiku can't go lower; Fable can't go higher.
    assert auto_route(ModelSpec("foundry", "claude-haiku-4-5", "low", 8000), "low").model == "claude-haiku-4-5"
    assert auto_route(ModelSpec("foundry", "claude-fable-5", "high", 32000), "high").model == "claude-fable-5"


def test_auto_route_leaves_off_ladder_models_alone():
    # A model not on the ladder is never shifted — custom Claude deployments
    # and other model families alike.
    assert auto_route(ModelSpec("foundry", "claude-opus-4-6", "high", 32000), "low").model == "claude-opus-4-6"
    assert auto_route(ModelSpec("foundry", "gpt-5", "high", 32000), "high").model == "gpt-5"
    assert auto_route(ModelSpec("foundry", "mistral-large-2411", "high", 32000), "high").model == "mistral-large-2411"


def test_auto_route_preserves_effort_and_tokens():
    out = auto_route(_opus(), "high")
    assert (out.model, out.effort, out.max_tokens) == ("claude-fable-5", "high", 32000)
