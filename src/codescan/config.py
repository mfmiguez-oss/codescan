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
    # Per-service AI calls (exploitability, threat modeling, enrichment, dedup) are
    # independent — run up to this many concurrently to cut wall-clock time on large
    # scans. Latency-only (same requests, same cost); 1 = sequential. Bounded to
    # stay within provider rate limits.
    max_concurrency: int = 4
    # Silent adaptive model selection: when true, each AI call is nudged up or down
    # an Anthropic capability ladder (Haiku→Sonnet→Opus→Fable) from its configured
    # tier based on how hard the work is — cheaper for trivial groups, stronger for
    # KEV/critical/large ones. Off by default (deterministic tiers); enabling it is
    # the operator's explicit opt-in. Only shifts Anthropic models on the ladder;
    # custom models and other suppliers are left exactly as configured.
    auto_route: bool = False
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
    """OpenHack whitebox source review — codescan's built-in engine (default), an
    external OpenHack `command`, or ingesting an existing run's findings dir."""

    enabled: bool = False       # ingest findings from `findings_dir`
    findings_dir: str = ""      # OpenHack run dir, or its finding-candidates/ folder
    repo: str = ""              # repo the findings belong to; empty = first scanned repo

    # --- automatic invocation (during a live scan) ---
    auto: bool = False          # run OpenHack, then ingest its output
    # command to run OpenHack externally; {repo_path} and {output_dir} are
    # substituted. Empty = use codescan's built-in in-process engine (needs AI on).
    command: list[str] = []
    workspace: str = ".openhack"  # dir to clone into and run under
    clone: bool = True          # git clone the target repo before running

    # --- built-in engine tuning (ignored when an external `command` is set) ---
    # Number of independent review passes over the source. AI source review is
    # non-deterministic, so >=2 passes raises recall (union of findings = fewer
    # vulnerabilities missed) and flags cross-pass agreement as a confidence signal.
    # 1 = single pass (cheapest); 2+ recommended. Each pass is another set of calls.
    passes: int = 2
    max_files: int = 60         # cap source files reviewed per repo (cost/latency)
    max_file_bytes: int = 60000  # skip files larger than this (bytes)
    batch_chars: int = 48000    # per-request source budget (chars) across files
    min_confidence: str = "low"  # drop candidates below this confidence: low|medium|high
    include_ext: list[str] = [] # source extensions to review; empty = built-in set


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
    # On by default (only runs when the AI stages are enabled). It's an extra
    # deep-tier call per service — set false to skip it, or route the
    # "threat_model" task in ai.tasks to a cheaper tier.
    enabled: bool = True


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
