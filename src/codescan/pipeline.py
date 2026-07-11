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
import logging
import time
import uuid
from contextlib import contextmanager
from dataclasses import dataclass, field
from pathlib import Path

from .audit import AuditLog
from .calibration import calibration_report, drift_alerts
from .config import Config
from .connectors import (
    BitbucketConnector, GitHubConnector, OpenHackConnector, SnykConnector, XrayConnector,
)
from .dedup import deduplicate
from .dedup_ai import SemanticDeduper
from .enrich import build_enrichers, run_enrichment
from .exploitability import ExploitabilityEngine
from .feedback import TriageHistory, apply_feedback
from .llm import LLMClient, ModelRouter
from .models import Finding, Repo, ThreatModel
from .openhack_runner import OpenHackRunner
from .scoring import Scorer
from .servicenow import ServiceNowExporter
from .threatmodel import ThreatModelEngine, apply_threat_influence
from .validation import active_chains, annotate_chain_states, assign_states, open_state_store

logger = logging.getLogger(__name__)


@contextmanager
def _stage(run_id: str, name: str):
    """Time a pipeline stage and log its duration at INFO."""
    t0 = time.perf_counter()
    yield
    logger.info("scan %s: %s done in %.2fs", run_id, name, time.perf_counter() - t0)


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
    def _repo_connector(self):
        """The SCM connector that supplies the repo inventory."""
        if self.cfg.source.provider == "github":
            return GitHubConnector(self.cfg.github)
        return BitbucketConnector(self.cfg.bitbucket)

    def _ingest_live(self, llm: LLMClient | None = None) -> tuple[list[Repo], list[Finding]]:
        repos = self._repo_connector().list_repos()
        # Map scanner project/build names back to repo full names.
        repo_by_name = {r.slug: r.full_name for r in repos}
        # Skip an unconfigured finding source rather than erroring on it, so a
        # scan can run on the sources that *are* wired up — e.g. a whitebox-only
        # GitHub + OpenHack scan with no Snyk/Xray account.
        findings: list[Finding] = []
        for name, conn in (("snyk", SnykConnector(self.cfg.snyk)),
                           ("xray", XrayConnector(self.cfg.xray))):
            if conn.configured:
                findings.extend(conn.fetch(repo_by_name))
            else:
                logger.info("scan: %s not configured — skipping that source", name)
        # OpenHack whitebox findings — covers repos the SCA/CVE scanners missed.
        oh = self.cfg.openhack
        if oh.auto and repos:
            # Run OpenHack (built-in engine, or external command) for the target
            # repo, then ingest its output.
            target = next((r for r in repos if r.full_name == oh.repo), repos[0])
            out_dir = OpenHackRunner(oh, llm=llm).run(target)
            findings.extend(OpenHackConnector().from_dir(out_dir, target.full_name))
        elif oh.enabled and oh.findings_dir:
            oh_repo = oh.repo or (repos[0].full_name if repos else "openhack")
            findings.extend(OpenHackConnector().from_dir(oh.findings_dir, oh_repo))
        return repos, findings

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
            elif ".openhack." in stem:
                findings.extend(OpenHackConnector().from_file(path, repo_full))
        return list(repos.values()), findings

    # --- run --------------------------------------------------------------
    def run(
        self,
        *,
        fixtures: str | Path | None = None,
        out_path: str | Path = "servicenow_import.json",
        state_path: str | Path | None = "validation_state.json",
        actor: str = "cli",
    ) -> PipelineResult:
        run_id = uuid.uuid4().hex[:8]
        t0 = time.perf_counter()
        mode = "fixtures" if fixtures else "live"
        audit = AuditLog(self.cfg.audit, base_dir=Path(out_path).parent)
        logger.info("scan %s start: mode=%s ai=%s offline=%s",
                    run_id, mode, self.use_ai, self.offline)
        audit.record("scan.started", actor=actor, run_id=run_id, mode=mode,
                     ai=self.use_ai, offline=self.offline)

        # Build one shared LLM client + task router for every AI stage — up front,
        # so live ingest can hand it to the built-in OpenHack review engine.
        llm = LLMClient(ModelRouter(self.cfg.ai)) if self.use_ai else None

        with _stage(run_id, "ingest"):
            if fixtures:
                repos, raw = self._ingest_fixtures(Path(fixtures))
            else:
                repos, raw = self._ingest_live(llm)
        logger.info("scan %s: ingested %d repos, %d raw findings", run_id, len(repos), len(raw))

        with _stage(run_id, "dedup"):
            findings = deduplicate(raw)                     # deterministic (free)
            if llm:
                findings = SemanticDeduper(llm).refine(findings)  # lower-cost tier (Haiku)
        logger.info("scan %s: %d findings after dedup", run_id, len(findings))

        # Bound the cost of a single scan (OWASP LLM04/10). If a run exceeds the
        # ceiling, keep the highest-severity findings — a truncated scan must not
        # silently drop the worst issues — and record the truncation for audit.
        cap = self.cfg.server.max_findings_per_scan
        n_dropped = 0
        if cap and len(findings) > cap:
            findings.sort(key=lambda f: (f.cvss_score or 0, f.severity.rank), reverse=True)
            n_dropped = len(findings) - cap
            findings = findings[:cap]
            logger.warning("scan %s: capped at %d findings (%d dropped by "
                           "server.max_findings_per_scan)", run_id, cap, n_dropped)
            audit.record("scan.truncated", actor=actor, run_id=run_id,
                         cap=cap, dropped=n_dropped)

        with _stage(run_id, "enrich"):
            enrichers = build_enrichers(self.cfg.enrichment, llm=llm, offline=self.offline)
            run_enrichment(findings, enrichers)

        # Opened before the AI stage so the org's triage history can inform the
        # model's reasoning; the same store later feeds the score prior and
        # persists this run's states.
        store = open_state_store(self.cfg.storage, state_path)

        chains: list[dict] = []
        if llm:
            history = (TriageHistory(store)
                       if self.cfg.feedback.enabled and self.cfg.feedback.prompt_history
                       else None)
            with _stage(run_id, "exploitability"):
                chains = ExploitabilityEngine(llm, history=history).assess(findings)  # deep tier
            # Re-apply persisted analyst chain decisions (keyed by finding-set
            # fingerprint): a dismissed chain stays visible but stops counting.
            annotate_chain_states(chains, store)
            logger.info("scan %s: %d attack chains (%d active)",
                        run_id, len(chains), len(active_chains(chains)))

        # Dismissed chains stay in the result for the UI but stop influencing
        # downstream stages: threat models, scoring, and the export.
        counted = active_chains(chains)

        # Threat modeling runs before scoring so it can feed back in: it enriches
        # each cited finding's exploitability, which the scorer then reflects.
        threat_models: list[ThreatModel] = []
        if llm and self.cfg.threat_model.enabled:
            with _stage(run_id, "threat_model"):
                threat_models = ThreatModelEngine(llm).build(findings, counted)  # deep tier
                apply_threat_influence(findings, threat_models)
                Path(out_path).with_name("threat_models.json").write_text(
                    json.dumps([tm.model_dump() for tm in threat_models], indent=2),
                    encoding="utf-8",
                )

        Scorer(self.cfg.scoring).score(findings, counted)

        # Calibrate scores from the org's accumulated confirm/false-positive history
        # (built from the store as loaded, i.e. prior decisions) before this run's
        # states are recorded.
        n_feedback = apply_feedback(findings, store, self.cfg.feedback, self.cfg.scoring.kev_floor)
        assign_states(findings, store)
        store.save()

        # Continuous calibration monitoring: grade the accumulated predictions
        # against analyst outcomes and raise drift as audit events (which fan
        # out to the SIEM sinks), so degradation raises an alert instead of
        # waiting to be noticed in the report.
        for alert in drift_alerts(calibration_report(store), self.cfg.calibration):
            logger.warning("scan %s: calibration drift — %s", run_id, alert)
            audit.record("calibration.drift", actor=actor, run_id=run_id, alert=alert)

        exporter = ServiceNowExporter(self.cfg.servicenow)
        items = exporter.export(findings, counted, out_path)

        kev = sum(1 for f in findings if f.exploitability.in_kev)
        duration = round(time.perf_counter() - t0, 2)
        logger.info(
            "scan %s done in %.2fs: %d findings, %d chains, %d threat models, "
            "%d KEV, %d exported",
            run_id, duration, len(findings), len(chains), len(threat_models), kev, len(items),
        )
        audit.record("scan.completed", actor=actor, run_id=run_id, mode=mode,
                     repos=len(repos), findings=len(findings), chains=len(chains),
                     threat_models=len(threat_models), kev=kev,
                     feedback_adjusted=n_feedback, duration_s=duration)
        return PipelineResult(repos=repos, findings=findings, chains=chains,
                              threat_models=threat_models, servicenow_items=items)
