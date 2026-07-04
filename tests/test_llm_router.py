"""Model-router tests — pure resolution logic, no network or API key."""

from __future__ import annotations

from codescan.config import AIConfig, TaskModel
from codescan.llm import ModelRouter


def test_dedup_defaults_to_haiku():
    # No config overrides — the built-in tier routes dedup to the cheap model.
    router = ModelRouter(AIConfig())
    assert router.resolve("dedup").model == "claude-haiku-4-5"


def test_unknown_task_uses_default_tier():
    router = ModelRouter(AIConfig(model="claude-opus-4-8", effort="high", max_tokens=32000))
    spec = router.resolve("exploitability")
    assert spec.model == "claude-opus-4-8"
    assert spec.effort == "high"


def test_config_override_wins():
    cfg = AIConfig(
        model="claude-opus-4-8",
        tasks={
            "dedup": TaskModel(model="claude-sonnet-5", max_tokens=5000),
            "exploitability": TaskModel(model="claude-fable-5", effort="xhigh"),
        },
    )
    router = ModelRouter(cfg)
    dedup = router.resolve("dedup")
    assert dedup.model == "claude-sonnet-5"   # override beats the built-in Haiku default
    assert dedup.max_tokens == 5000

    exploit = router.resolve("exploitability")
    assert exploit.model == "claude-fable-5"
    assert exploit.uses_fallbacks is True     # Fable auto-enables refusal fallbacks


def test_partial_override_inherits_default():
    cfg = AIConfig(model="claude-opus-4-8", effort="high",
                   tasks={"dedup": TaskModel(effort="medium")})
    spec = ModelRouter(cfg).resolve("dedup")
    # model inherits the built-in Haiku; only effort was overridden.
    assert spec.model == "claude-haiku-4-5"
    assert spec.effort == "medium"
