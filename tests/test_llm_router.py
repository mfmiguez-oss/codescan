"""Model-router tests — pure resolution logic, no network or API key."""

from __future__ import annotations

from codescan.config import AIConfig, TaskModel
from codescan.llm import ModelRouter


def test_dedup_defaults_to_haiku():
    spec = ModelRouter(AIConfig()).resolve("dedup")
    assert spec.model == "claude-haiku-4-5"
    assert spec.provider == "anthropic"


def test_unknown_task_uses_default_tier():
    router = ModelRouter(AIConfig(model="claude-opus-4-8", effort="high", max_tokens=32000))
    spec = router.resolve("exploitability")
    assert (spec.provider, spec.model, spec.effort) == ("anthropic", "claude-opus-4-8", "high")


def test_config_override_wins_incl_provider():
    cfg = AIConfig(
        provider="anthropic", model="claude-opus-4-8",
        tasks={
            "dedup": TaskModel(model="claude-sonnet-5", max_tokens=5000),
            # Route exploitability to a different supplier entirely.
            "exploitability": TaskModel(provider="openai", model="gpt-5", effort="high"),
        },
    )
    router = ModelRouter(cfg)
    dedup = router.resolve("dedup")
    assert dedup.model == "claude-sonnet-5" and dedup.max_tokens == 5000
    assert dedup.provider == "anthropic"

    exploit = router.resolve("exploitability")
    assert exploit.provider == "openai" and exploit.model == "gpt-5"


def test_default_provider_propagates():
    cfg = AIConfig(provider="google", model="gemini-2.5-pro")
    spec = ModelRouter(cfg).resolve("exploitability")   # unknown task -> default tier
    assert spec.provider == "google" and spec.model == "gemini-2.5-pro"


def test_partial_override_inherits_default():
    cfg = AIConfig(model="claude-opus-4-8", effort="high",
                   tasks={"dedup": TaskModel(effort="medium")})
    spec = ModelRouter(cfg).resolve("dedup")
    assert spec.model == "claude-haiku-4-5"      # built-in
    assert spec.effort == "medium"               # overridden
    assert spec.provider == "anthropic"          # inherited
