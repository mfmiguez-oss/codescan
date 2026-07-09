"""Config loading with ${ENV_VAR} interpolation."""

from __future__ import annotations

import os
import re
from pathlib import Path
from typing import Any

import yaml
from pydantic import BaseModel, field_validator

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

    provider: str | None = None      # anthropic | openai | google
    model: str | None = None
    effort: str | None = None
    max_tokens: int | None = None


class AIConfig(BaseModel):
    # Default tier — used by any task without a more specific override.
    provider: str = "anthropic"      # anthropic | openai | google (per-supplier harness)
    model: str = "claude-opus-4-8"
    effort: str = "high"
    max_tokens: int = 32000
    # Route individual tasks to lower-cost or higher-capability models,
    # e.g. dedup -> Haiku, exploitability -> Opus/Fable. Built-in defaults live
    # in llm.py.
    tasks: dict[str, TaskModel] = {}


class BitbucketConfig(BaseModel):
    base_url: str = ""
    token: str = ""
    projects: list[str] = []
    verify_tls: bool = True


class GitHubConfig(BaseModel):
    api_url: str = "https://api.github.com"   # or GHES: https://ghe.internal/api/v3
    token: str = ""
    # Target scope, most specific first:
    repos: list[str] = []                     # explicit "owner/name" repos
    orgs: list[str] = []                      # whole orgs (used when repos is empty)
    verify_tls: bool = True                   # empty repos+orgs = all the token can see

    @field_validator("api_url")
    @classmethod
    def _default_api_url(cls, v: str) -> str:
        # An unset ${GITHUB_API_URL} interpolates to "" — fall back to public GitHub
        # so github.com users don't have to set it. GHES users provide their host.
        return v.strip() or "https://api.github.com"


class SourceConfig(BaseModel):
    """Which SCM provides the repo inventory (scan surface)."""

    provider: str = "bitbucket"               # bitbucket | github


class SnykConfig(BaseModel):
    api_url: str = ""
    token: str = ""
    org_id: str = ""
    verify_tls: bool = True


class XrayConfig(BaseModel):
    base_url: str = ""
    token: str = ""
    verify_tls: bool = True


class OpenHackConfig(BaseModel):
    """Ingest Hadrian OpenHack whitebox-review findings — from an existing run
    directory, or by invoking OpenHack automatically during a live scan."""

    enabled: bool = False       # ingest findings from `findings_dir`
    findings_dir: str = ""      # OpenHack run dir, or its finding-candidates/ folder
    repo: str = ""              # repo the findings belong to; empty = first scanned repo

    # --- automatic invocation (during a live scan) ---
    auto: bool = False          # run OpenHack, then ingest its output
    command: list[str] = []     # command to run; {repo_path} and {output_dir} are substituted
    workspace: str = ".openhack"  # dir to clone into and run under
    clone: bool = True          # git clone the target repo before running


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
    source: SourceConfig = SourceConfig()
    bitbucket: BitbucketConfig = BitbucketConfig()
    github: GitHubConfig = GitHubConfig()
    snyk: SnykConfig = SnykConfig()
    xray: XrayConfig = XrayConfig()
    openhack: OpenHackConfig = OpenHackConfig()
    servicenow: ServiceNowConfig = ServiceNowConfig()
    enrichment: EnrichmentConfig = EnrichmentConfig()
    threat_model: ThreatModelConfig = ThreatModelConfig()
    scoring: ScoringConfig = ScoringConfig()

    @classmethod
    def load(cls, path: str | Path) -> "Config":
        raw = yaml.safe_load(Path(path).read_text(encoding="utf-8")) or {}
        return cls.model_validate(_interpolate(raw))
