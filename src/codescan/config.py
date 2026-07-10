"""Config loading with ${ENV_VAR} interpolation."""

from __future__ import annotations

import os
import re
from pathlib import Path
from typing import Any

import yaml
from pydantic import BaseModel, ConfigDict, field_validator

_ENV_PATTERN = re.compile(r"\$\{([^}]+)\}")


class _StrictModel(BaseModel):
    """Config base: reject unknown keys so a misspelled setting fails loudly
    (`ai.max_concurency`, `servicnow`, …) instead of being silently ignored."""

    model_config = ConfigDict(extra="forbid")


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


class TaskModel(_StrictModel):
    """Per-task override of the default AI tier. Unset fields inherit."""

    provider: str | None = None      # anthropic | openai | google
    model: str | None = None
    effort: str | None = None
    max_tokens: int | None = None


class AIConfig(_StrictModel):
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
    # Submit each AI stage's per-service requests via the Anthropic Message
    # Batches API — ~50% cheaper, but asynchronous (the scan blocks polling for up
    # to batch_max_wait_seconds). Best for scheduled/overnight runs, not interactive
    # use. Off = the synchronous concurrent path. Fable (needs refusal fallbacks,
    # which Batches rejects) and non-Anthropic tasks fall back to synchronous.
    batch: bool = False
    batch_poll_seconds: int = 30
    batch_max_wait_seconds: int = 3600
    # Route individual tasks to lower-cost or higher-capability models,
    # e.g. dedup -> Haiku, exploitability -> Opus/Fable. Built-in defaults live
    # in llm.py.
    tasks: dict[str, TaskModel] = {}


class BitbucketConfig(_StrictModel):
    base_url: str = ""
    token: str = ""
    projects: list[str] = []
    verify_tls: bool = True


class GitHubConfig(_StrictModel):
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


class SourceConfig(_StrictModel):
    """Which SCM provides the repo inventory (scan surface)."""

    provider: str = "bitbucket"               # bitbucket | github


class SnykConfig(_StrictModel):
    api_url: str = ""
    token: str = ""
    org_id: str = ""
    verify_tls: bool = True


class XrayConfig(_StrictModel):
    base_url: str = ""
    token: str = ""
    verify_tls: bool = True


class OpenHackConfig(_StrictModel):
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
    # Route each pass to a different supplier/model for independent coverage —
    # different vendors miss different things, so diverse passes catch more and a
    # cross-supplier agreement is a stronger confidence signal. Pass i uses
    # pass_models[i % len]; unset fields inherit the `openhack` task routing. Empty
    # = every pass uses the same routed model. e.g.:
    #   pass_models:
    #     - { provider: anthropic, model: claude-opus-4-8 }
    #     - { provider: openai,    model: gpt-5 }
    #     - { provider: google,    model: gemini-2.5-pro }
    pass_models: list[TaskModel] = []
    max_files: int = 60         # cap source files reviewed per repo (cost/latency)
    max_file_bytes: int = 60000  # skip files larger than this (bytes)
    batch_chars: int = 48000    # per-request source budget (chars) across files
    min_confidence: str = "low"  # drop candidates below this confidence: low|medium|high
    include_ext: list[str] = [] # source extensions to review; empty = built-in set


class ServiceNowConfig(_StrictModel):
    instance: str = ""
    user: str = ""
    password: str = ""
    push: bool = False
    import_table: str = "sn_vul_vulnerable_item"
    format: str = "json"                # json | csv (Import Set / CSV transform)


class EnrichmentConfig(_StrictModel):
    kev_url: str = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
    epss_url: str = "https://api.first.org/data/v1/epss"
    # Toggle enrichers individually. Order is fixed (kev, epss, reachability, ai);
    # each is a pluggable BaseEnricher (see enrich/).
    kev_enabled: bool = True
    epss_enabled: bool = True
    reachability_enabled: bool = True
    ai_enabled: bool = False        # LLM remediation + tags (task "enrichment")


class ThreatModelConfig(_StrictModel):
    # On by default (only runs when the AI stages are enabled). It's an extra
    # deep-tier call per service — set false to skip it, or route the
    # "threat_model" task in ai.tasks to a cheaper tier.
    enabled: bool = True


class VaultConfig(_StrictModel):
    """Optional HashiCorp Vault secret source (see `vault.py`). When enabled, KV
    secrets are pulled into the environment before config interpolation, so the
    rest of the config resolves from Vault via the same `${ENV}` seam."""

    enabled: bool = False
    address: str = ""            # Vault URL; empty -> hvac uses VAULT_ADDR
    namespace: str = ""          # Vault Enterprise namespace (optional)
    auth: str = "token"          # token | approle
    token: str = ""              # empty -> hvac uses VAULT_TOKEN
    role_id: str = ""            # approle
    secret_id: str = ""          # approle
    kv_mount: str = "secret"     # KV secrets-engine mount point
    kv_version: int = 2          # 1 | 2
    paths: list[str] = []        # secret paths under the mount; keys become env vars
    override_env: bool = False   # false = an already-set env var wins
    verify_tls: bool = True


class StorageConfig(_StrictModel):
    """Where the validation-state store persists. `file` (default) = local JSON,
    right for a single instance. `sql` = a shared database (Postgres/SQLite) so
    multiple replicas / concurrent runners share one durable store (HA)."""

    backend: str = "file"        # file | sql
    # SQLAlchemy URL for backend=sql, e.g.
    #   postgresql+psycopg://user:pass@host:5432/codescan   or   sqlite:///data/state.db
    # Interpolate secrets from the environment: dsn: ${STATE_DB_DSN}
    dsn: str = ""


class FeedbackConfig(_StrictModel):
    """Learn from analysts' persisted confirm / false-positive decisions to nudge
    the risk score of new, similar findings (same weakness family or component).
    Bounded and explainable; no-op until there's manual feedback history."""

    enabled: bool = True
    max_adjust: float = 15.0     # cap the +/- score nudge (points on the 0-100 scale)
    min_evidence: int = 2        # need at least this many prior manual decisions for a key


class AuditConfig(_StrictModel):
    """Append-only audit log of key events (scan runs, config + validation-state
    changes) with actor + timestamp, one JSON object per line (JSONL)."""

    enabled: bool = True
    # File path; relative paths resolve next to the run's other artifacts
    # (the ServiceNow export dir, e.g. /data in the container).
    path: str = "audit.jsonl"


class ScoringConfig(_StrictModel):
    weights: dict[str, float] = {
        "severity": 0.30,
        "exploitability": 0.35,
        "exposure": 0.20,
        "chaining": 0.15,
    }
    kev_floor: float = 85.0


class Config(_StrictModel):
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
    feedback: FeedbackConfig = FeedbackConfig()
    storage: StorageConfig = StorageConfig()
    vault: VaultConfig = VaultConfig()
    audit: AuditConfig = AuditConfig()

    @classmethod
    def load(cls, path: str | Path) -> "Config":
        raw = yaml.safe_load(Path(path).read_text(encoding="utf-8")) or {}
        # Vault first: pull secrets into the environment so the rest of the config
        # resolves them via ${ENV} below. The vault section's own bootstrap creds
        # (address/token/role) come from the environment, so interpolate it first.
        _maybe_load_vault(raw.get("vault"))
        return cls.model_validate(_interpolate(raw))


def _maybe_load_vault(raw_vault: Any) -> None:
    if not isinstance(raw_vault, dict) or not raw_vault.get("enabled"):
        return
    cfg = VaultConfig.model_validate(_interpolate(raw_vault))
    from .vault import load_secrets_into_env  # lazy: only import hvac path when used

    load_secrets_into_env(cfg)
