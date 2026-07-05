"""End-to-end orchestration.

    ingest -> dedup -> enrich -> AI exploitability/chaining -> score
    -> validation states -> ServiceNow export

Runs in two modes:
  * live     - pulls from Bitbucket / Snyk / Xray using configured credentials
  * fixtures - loads scanner exports from a directory (offline: demos, CI, tests)

The AI stage is optional (`use_ai=False`) so the deterministic pipeline still
produces scored, ServiceNow-ready output when no Anthropic key is available.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path

from .config import Config
from .connectors import BitbucketConnector, SnykConnector, XrayConnector
from .dedup import deduplicate
from .dedup_ai import SemanticDeduper
from .enrich import build_enrichers, run_enrichment
from .exploitability import ExploitabilityEngine
from .llm import LLMClient, ModelRouter
from .models import Finding, Repo, ThreatModel
from .scoring import Scorer
from .servicenow import ServiceNowExporter
from .threatmodel import ThreatModelEngine, apply_threat_influence
from .validation import StateStore, assign_states


@dataclass
class PipelineResult:
    repos: list[Repo] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)
    chains: list[dict] = field(default_factory=list)
    threat_models: list[ThreatModel] = field(default_factory=list)
    servicenow_items: list[dict] = field(default_factory=list)

    def summary(self) -> dict:
        by_state: dict[str, int] = {}
        by_sev: dict[str, int] = {}
        for f in self.findings:
            by_state[f.validation_state.value] = by_state.get(f.validation_state.value, 0) + 1
            by_sev[f.severity.value] = by_sev.get(f.severity.value, 0) + 1
        return {
            "repos": len(self.repos),
            "findings": len(self.findings),
            "chains": len(self.chains),
            "threats": sum(len(tm.threats) for tm in self.threat_models),
            "threat_models": len(self.threat_models),
            "kev": sum(1 for f in self.findings if f.exploitability.in_kev),
            "by_severity": by_sev,
            "by_validation_state": by_state,
            "top_risk": [
                {"id": f.id, "title": f.title, "score": f.risk_score,
                 "state": f.validation_state.value}
                for f in sorted(self.findings, key=lambda x: x.risk_score, reverse=True)[:10]
            ],
        }


class Pipeline:
    def __init__(self, cfg: Config, *, offline: bool = False, use_ai: bool = True) -> None:
        self.cfg = cfg
        self.offline = offline
        self.use_ai = use_ai

    # --- ingestion --------------------------------------------------------
    def _ingest_live(self) -> tuple[list[Repo], list[Finding]]:
        repos = BitbucketConnector(self.cfg.bitbucket).list_repos()
        # Map scanner project/build names back to repo full names.
        repo_by_name = {r.slug: r.full_name for r in repos}
        snyk = SnykConnector(self.cfg.snyk).fetch(repo_by_name)
        xray = XrayConnector(self.cfg.xray).fetch(repo_by_name)
        return repos, [*snyk, *xray]

    def _ingest_fixtures(self, fixtures: Path) -> tuple[list[Repo], list[Finding]]:
        """Load `<repo>.snyk.json` / `<repo>.xray.json` files from a directory.

        File naming: PROJECT__slug.snyk.json  (double underscore = '/').
        """
        findings: list[Finding] = []
        repos: dict[str, Repo] = {}
        snyk = SnykConnector(self.cfg.snyk)
        xray = XrayConnector(self.cfg.xray)
        for path in sorted(fixtures.glob("*.json")):
            stem = path.name
            repo_full = stem.split(".")[0].replace("__", "/")
            proj, _, slug = repo_full.partition("/")
            repos.setdefault(repo_full, Repo(project_key=proj, slug=slug or proj,
                                             name=slug or proj, clone_url=""))
            if ".snyk." in stem:
                findings.extend(snyk.from_file(path, repo_full))
            elif ".xray." in stem:
                findings.extend(xray.from_file(path, repo_full))
        return list(repos.values()), findings

    # --- run --------------------------------------------------------------
    def run(
        self,
        *,
        fixtures: str | Path | None = None,
        out_path: str | Path = "servicenow_import.json",
        state_path: str | Path | None = "validation_state.json",
    ) -> PipelineResult:
        if fixtures:
            repos, raw = self._ingest_fixtures(Path(fixtures))
        else:
            repos, raw = self._ingest_live()

        # Build one shared LLM client + task router for every AI stage.
        llm = LLMClient(ModelRouter(self.cfg.ai)) if self.use_ai else None

        findings = deduplicate(raw)                     # deterministic (free)
        if llm:
            findings = SemanticDeduper(llm).refine(findings)  # cheap tier (Haiku)

        enrichers = build_enrichers(self.cfg.enrichment, llm=llm, offline=self.offline)
        run_enrichment(findings, enrichers)

        chains: list[dict] = []
        if llm:
            chains = ExploitabilityEngine(llm).assess(findings)  # deep tier

        # Threat modeling runs before scoring so it can feed back in: it enriches
        # each cited finding's exploitability, which the scorer then reflects.
        threat_models: list[ThreatModel] = []
        if llm and self.cfg.threat_model.enabled:
            threat_models = ThreatModelEngine(llm).build(findings, chains)  # deep tier
            apply_threat_influence(findings, threat_models)
            Path(out_path).with_name("threat_models.json").write_text(
                json.dumps([tm.model_dump() for tm in threat_models], indent=2),
                encoding="utf-8",
            )

        Scorer(self.cfg.scoring).score(findings, chains)

        store = StateStore(state_path)
        assign_states(findings, store)
        store.save()

        exporter = ServiceNowExporter(self.cfg.servicenow)
        items = exporter.export(findings, chains, out_path)

        return PipelineResult(repos=repos, findings=findings, chains=chains,
                              threat_models=threat_models, servicenow_items=items)
