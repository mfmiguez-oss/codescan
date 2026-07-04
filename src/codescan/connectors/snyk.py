"""Snyk connector — pulls issues and normalizes them to `Finding`.

Supports both a live API pull and loading a Snyk JSON export (`snyk test
--json` / API aggregated-issues payload) so the pipeline runs offline for
demos and CI fixtures. Snyk projects are mapped back to Bitbucket repos by
matching the project's `target`/name against the repo full name.
"""

from __future__ import annotations

import json
from pathlib import Path

from ..config import SnykConfig
from ..models import Component, Finding, Location, Severity, Source
from .base import HttpClient


class SnykConnector:
    def __init__(self, cfg: SnykConfig) -> None:
        self.cfg = cfg
        self.http = HttpClient(cfg.api_url, cfg.token, auth_scheme="token", verify_tls=cfg.verify_tls)

    # --- live API ---------------------------------------------------------
    def fetch(self, repo_by_target: dict[str, str]) -> list[Finding]:
        """Fetch aggregated issues for every project in the org.

        `repo_by_target` maps a Snyk project target name -> Bitbucket repo
        full name so findings anchor to the right repo.
        """
        findings: list[Finding] = []
        projects = self.http.get(
            f"/v1/org/{self.cfg.org_id}/projects"
        ).json().get("projects", [])
        for proj in projects:
            repo = repo_by_target.get(proj.get("name", ""), proj.get("name", "unknown"))
            body = {"filters": {"severities": ["critical", "high", "medium", "low"]}}
            issues = self.http.post(
                f"/v1/org/{self.cfg.org_id}/project/{proj['id']}/aggregated-issues",
                json=body,
            ).json().get("issues", [])
            for issue in issues:
                findings.append(self._to_finding(issue, repo, proj.get("name", "")))
        return findings

    # --- offline fixture --------------------------------------------------
    def from_file(self, path: str | Path, repo: str) -> list[Finding]:
        data = json.loads(Path(path).read_text(encoding="utf-8"))
        issues = data.get("issues", data if isinstance(data, list) else [])
        return [self._to_finding(i, repo, data.get("projectName", repo)) for i in issues]

    # --- normalization ----------------------------------------------------
    def _to_finding(self, issue: dict, repo: str, manifest: str) -> Finding:
        data = issue.get("issueData", issue)
        ids = data.get("identifiers", {})
        cvss = data.get("cvssScore")
        pkg = issue.get("pkgName") or data.get("package", "unknown")
        versions = issue.get("pkgVersions") or ([data["version"]] if data.get("version") else [])
        return Finding(
            source=Source.snyk,
            source_ref=str(data.get("id", issue.get("id", ""))),
            title=data.get("title", "Snyk issue"),
            cve_ids=[c for c in ids.get("CVE", []) if c],
            cwe_ids=[c for c in ids.get("CWE", []) if c],
            severity=Severity(data.get("severity", "low")) if data.get("severity") in
            {s.value for s in Severity} else Severity.from_cvss(cvss),
            cvss_score=cvss,
            cvss_vector=data.get("CVSSv3"),
            component=Component(
                name=pkg,
                version=versions[0] if versions else None,
                ecosystem=data.get("language") or data.get("packageManager"),
                purl=_purl(data.get("packageManager"), pkg, versions[0] if versions else None),
            ),
            location=Location(repo=repo, path=manifest),
            fixed_in=data.get("fixedIn", []) or (issue.get("fixInfo", {}) or {}).get("fixedIn", []),
            description=data.get("description", ""),
            references=[r.get("url", "") for r in data.get("references", []) if r.get("url")],
        )


def _purl(ecosystem: str | None, name: str, version: str | None) -> str | None:
    if not ecosystem or not name:
        return None
    eco = {"maven": "maven", "npm": "npm", "pip": "pypi", "pypi": "pypi",
           "nuget": "nuget", "gomodules": "golang", "composer": "composer"}.get(ecosystem, ecosystem)
    v = f"@{version}" if version else ""
    return f"pkg:{eco}/{name}{v}"
