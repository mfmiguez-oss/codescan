"""GitHub-native alert sources — Dependabot and secret scanning.

Both ride the token and repo inventory the GitHub SCM source already has, so
enabling them is one config toggle each (`github.dependabot_alerts` /
`github.secret_scanning_alerts`, off by default). A repo where the feature is
disabled or the token lacks the scope answers 403/404 — that repo is logged and
skipped, not fatal, so a mixed estate still yields what it can.

Dependabot alerts are SCA findings (advisory + vulnerable dependency) — a
strong corroboration partner for Snyk. Secret-scanning alerts become findings
for exposed credentials; the secret value itself is never copied into the
finding, only the secret's type and location.
"""

from __future__ import annotations

import logging

from ..config import GitHubConfig
from ..models import Component, Finding, Location, Repo, Severity, Source
from .github import github_http, github_paged

logger = logging.getLogger(__name__)

_SEV = {"critical": Severity.critical, "high": Severity.high,
        "medium": Severity.medium, "low": Severity.low}


class _GitHubAlerts:
    """Shared plumbing: per-repo paged alert fetch with per-repo isolation."""

    name = "github-alerts"
    path = ""                    # /repos/{full_name}<path>

    def __init__(self, cfg: GitHubConfig) -> None:
        self.cfg = cfg
        self.http = github_http(cfg)

    def fetch(self, repos: list[Repo]) -> list[Finding]:
        findings: list[Finding] = []
        for repo in repos:
            full = repo.name
            try:
                alerts = github_paged(self.http, f"/repos/{full}{self.path}", state="open")
            except RuntimeError as exc:
                # Feature disabled on the repo, or token lacks the scope.
                logger.info("scan: %s unavailable for %s (%s) — skipping that repo",
                            self.name, full, exc)
                continue
            findings.extend(self._to_finding(a, full) for a in alerts)
        return findings

    def _to_finding(self, alert: dict, repo: str) -> Finding:  # pragma: no cover - interface
        raise NotImplementedError


class DependabotConnector(_GitHubAlerts):
    name = "dependabot"
    path = "/dependabot/alerts"

    @property
    def configured(self) -> bool:
        return bool(self.cfg.token and self.cfg.dependabot_alerts)

    def _to_finding(self, alert: dict, repo: str) -> Finding:
        adv = alert.get("security_advisory") or {}
        vuln = alert.get("security_vulnerability") or {}
        dep = alert.get("dependency") or {}
        pkg = (dep.get("package") or vuln.get("package") or {})
        cvss = (adv.get("cvss") or {}).get("score")
        fixed = ((vuln.get("first_patched_version") or {}).get("identifier"))
        cves = [i["value"] for i in adv.get("identifiers", [])
                if i.get("type") == "CVE" and i.get("value")]
        rng = vuln.get("vulnerable_version_range", "")
        description = adv.get("description", "")
        if rng:
            description = f"{description}\n\nVulnerable range: {rng}".strip()
        return Finding(
            source=Source.dependabot,
            source_ref=str(alert.get("number", "")),
            title=adv.get("summary", "Dependabot alert"),
            cve_ids=cves,
            cwe_ids=[c["cwe_id"] for c in adv.get("cwes", []) if c.get("cwe_id")],
            severity=_SEV.get((adv.get("severity") or "").lower(), Severity.from_cvss(cvss)),
            cvss_score=cvss,
            cvss_vector=(adv.get("cvss") or {}).get("vector_string"),
            component=Component(name=pkg.get("name", "unknown"),
                                ecosystem=pkg.get("ecosystem")),
            location=Location(repo=repo, path=dep.get("manifest_path")),
            fixed_in=[fixed] if fixed else [],
            description=description,
            references=[r["url"] for r in adv.get("references", []) if r.get("url")],
            tags=["dependabot"],
        )


class SecretScanningConnector(_GitHubAlerts):
    name = "secret-scanning"
    path = "/secret-scanning/alerts"

    @property
    def configured(self) -> bool:
        return bool(self.cfg.token and self.cfg.secret_scanning_alerts)

    def _to_finding(self, alert: dict, repo: str) -> Finding:
        # The secret VALUE is deliberately never read — type + location only.
        kind = alert.get("secret_type_display_name") or alert.get("secret_type", "secret")
        validity = (alert.get("validity") or "unknown").lower()
        path, line = self._first_location(alert)
        description = (
            f"GitHub secret scanning found an exposed {kind} "
            f"(validity: {validity}). Rotate the credential and purge it from history."
        )
        return Finding(
            source=Source.secret_scanning,
            source_ref=str(alert.get("number", "")),
            title=f"Exposed secret: {kind}",
            cwe_ids=["CWE-798"],
            # A credential the provider verified as live is critical by definition.
            severity=Severity.critical if validity == "active" else Severity.high,
            component=Component(name=path or repo, ecosystem="source"),
            location=Location(repo=repo, path=path, start_line=line),
            description=description,
            references=[alert["html_url"]] if alert.get("html_url") else [],
            tags=[t for t in ("secret-scanning", str(alert.get("secret_type") or "")) if t],
        )

    def _first_location(self, alert: dict) -> tuple[str | None, int | None]:
        """First commit-type location of the alert (extra call; best-effort)."""
        url = alert.get("locations_url")
        if not url:
            return None, None
        try:
            for loc in self.http.get(url).json():
                details = loc.get("details") or {}
                if details.get("path"):
                    return details["path"], details.get("start_line")
        except (RuntimeError, ValueError) as exc:
            logger.debug("secret-scanning locations unavailable (%s)", exc)
        return None, None
