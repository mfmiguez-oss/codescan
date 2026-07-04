"""JFrog Xray connector — pulls violations and normalizes to `Finding`.

Xray reports at the artifact/build level. We map builds back to Bitbucket
repos via a caller-supplied `repo_by_build` map (build name -> repo full name),
so Xray CVEs land on the same repo as the Snyk findings and can be deduped.
"""

from __future__ import annotations

import json
from pathlib import Path

from ..config import XrayConfig
from ..models import Component, Finding, Location, Severity, Source
from .base import HttpClient


class XrayConnector:
    def __init__(self, cfg: XrayConfig) -> None:
        self.cfg = cfg
        self.http = HttpClient(cfg.base_url, cfg.token, verify_tls=cfg.verify_tls)

    def fetch(self, repo_by_build: dict[str, str]) -> list[Finding]:
        findings: list[Finding] = []
        page = 1
        while True:
            body = {
                "filters": {"violation_type": "security", "min_severity": "Low"},
                "pagination": {"order_by": "created", "limit": 100, "offset": page},
            }
            data = self.http.post("/api/v1/violations", json=body).json()
            violations = data.get("violations", [])
            for v in violations:
                repo = repo_by_build.get(v.get("build_name", ""), v.get("impacted_artifact", "unknown"))
                findings.append(self._to_finding(v, repo))
            if len(violations) < 100:
                break
            page += 1
        return findings

    def from_file(self, path: str | Path, repo: str) -> list[Finding]:
        data = json.loads(Path(path).read_text(encoding="utf-8"))
        violations = data.get("violations", data if isinstance(data, list) else [])
        return [self._to_finding(v, repo) for v in violations]

    def _to_finding(self, v: dict, repo: str) -> Finding:
        cves = v.get("cve_ids") or [c.get("cve") for c in v.get("cves", []) if c.get("cve")]
        cvss = _first_cvss(v.get("cves", []))
        comp = v.get("impacted_artifact") or v.get("component", "unknown")
        # Coordinates are "group:artifact:version" (maven) or "name:version".
        # Split on the LAST colon so maven group:artifact stays intact as the name.
        name, _, version = comp.rpartition(":")
        if not name:            # no colon at all
            name, version = comp, ""
        return Finding(
            source=Source.xray,
            source_ref=str(v.get("issue_id") or v.get("id", "")),
            title=v.get("summary", "Xray violation"),
            cve_ids=[c for c in cves if c],
            cwe_ids=v.get("cwe", []) or [],
            severity=_xray_severity(v.get("severity")),
            cvss_score=cvss,
            cvss_vector=_first_vector(v.get("cves", [])),
            component=Component(
                name=name or comp,
                version=version or None,
                ecosystem=v.get("package_type"),
                purl=v.get("purl"),
            ),
            location=Location(repo=repo, path=v.get("impacted_artifact")),
            fixed_in=v.get("fixed_versions", []),
            description=v.get("description", v.get("summary", "")),
            references=v.get("references", []),
        )


def _xray_severity(s: str | None) -> Severity:
    return {
        "critical": Severity.critical, "high": Severity.high,
        "medium": Severity.medium, "low": Severity.low,
    }.get((s or "").lower(), Severity.info)


def _first_cvss(cves: list[dict]) -> float | None:
    for c in cves:
        for key in ("cvss_v3_score", "cvss_v3", "cvss_v2_score"):
            if c.get(key) is not None:
                try:
                    return float(c[key])
                except (TypeError, ValueError):
                    continue
    return None


def _first_vector(cves: list[dict]) -> str | None:
    for c in cves:
        if c.get("cvss_v3_vector"):
            return c["cvss_v3_vector"]
    return None
