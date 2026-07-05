"""Config loading with ${ENV_VAR} interpolation."""

from __future__ import annotations

import os
import re
from pathlib import Path
from typing import Any

import yaml
from pydantic import BaseModel

_ENV_PATTERN = re.compile(r"\$\{([^}]+)\}")


def _interpolate(value: Any) -> Any:
    if isinstance(value, str):
        def repl(m: re.Match[str]) -> str:
            return os.environ.get(m.group(1), "")
        return _ENV_PATTERN.sub(repl, value)
    if isinstance(value, dict):
        return {k: _interpolate(v) for k, v in value.items()}
    if isinstance(value, list):
        return [_interpolate(v) for v in value]
    return value


class TaskModel(BaseModel):
    """Per-task override of the default AI tier. Unset fields inherit."""

    model: str | None = None
    effort: str | None = None
    max_tokens: int | None = None


class AIConfig(BaseModel):
    # Default tier — used by any task without a more specific override.
    model: str = "claude-opus-4-8"
    effort: str = "high"
    max_tokens: int = 32000
    # Route individual tasks to cheaper/deeper models, e.g. dedup -> Haiku,
    # exploitability -> Opus/Fable. Built-in defaults live in llm.py.
    tasks: dict[str, TaskModel] = {}


class BitbucketConfig(BaseModel):
    base_url: str = ""
    token: str = ""
    projects: list[str] = []
    verify_tls: bool = True


class SnykConfig(BaseModel):
    api_url: str = ""
    token: str = ""
    org_id: str = ""
    verify_tls: bool = True


class XrayConfig(BaseModel):
    base_url: str = ""
    token: str = ""
    verify_tls: bool = True


class ServiceNowConfig(BaseModel):
    instance: str = ""
    user: str = ""
    password: str = ""
    push: bool = False
    import_table: str = "sn_vul_vulnerable_item"
    format: str = "json"                # json | csv (Import Set / CSV transform)


class EnrichmentConfig(BaseModel):
    kev_url: str = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
    epss_url: str = "https://api.first.org/data/v1/epss"
    # Toggle enrichers individually. Order is fixed (kev, epss, reachability, ai);
    # each is a pluggable BaseEnricher (see enrich/).
    kev_enabled: bool = True
    epss_enabled: bool = True
    reachability_enabled: bool = True
    ai_enabled: bool = False        # LLM remediation + tags (task "enrichment")


class ThreatModelConfig(BaseModel):
    # Off by default — it's an extra deep-tier call per service. Route via the
    # "threat_model" task in ai.tasks (defaults to the default tier).
    enabled: bool = False


class ScoringConfig(BaseModel):
    weights: dict[str, float] = {
        "severity": 0.30,
        "exploitability": 0.35,
        "exposure": 0.20,
        "chaining": 0.15,
    }
    kev_floor: float = 85.0


class Config(BaseModel):
    ai: AIConfig = AIConfig()
    bitbucket: BitbucketConfig = BitbucketConfig()
    snyk: SnykConfig = SnykConfig()
    xray: XrayConfig = XrayConfig()
    servicenow: ServiceNowConfig = ServiceNowConfig()
    enrichment: EnrichmentConfig = EnrichmentConfig()
    threat_model: ThreatModelConfig = ThreatModelConfig()
    scoring: ScoringConfig = ScoringConfig()

    @classmethod
    def load(cls, path: str | Path) -> "Config":
        raw = yaml.safe_load(Path(path).read_text(encoding="utf-8")) or {}
        return cls.model_validate(_interpolate(raw))
