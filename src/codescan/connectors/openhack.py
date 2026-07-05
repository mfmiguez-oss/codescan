"""OpenHack connector — ingest Hadrian OpenHack whitebox-review findings.

OpenHack (https://github.com/hadriansecurity/openhack) is an agentic, source-guided
security review tool. It runs externally (its own LLM agents + human phase gates)
and writes file-based artifacts to a run directory:

    runs/<target>/<run-id>/
      finding-candidates/   S###-F###.json   <- structured, what we parse
      findings/             *.md             <- final markdown reports

This connector reads the finding-candidate JSON (conforms to OpenHack's
finding-candidate-schema: a candidate envelope with a nested `finding` object)
and normalizes each to a codescan `Finding`. Unlike Snyk/Xray (SCA/CVE), OpenHack
findings are first-party source issues with no CVE — dedup keys on the title +
affected path instead. This gives codescan findings for repos the scanners
haven't covered.
"""

from __future__ import annotations

import json
from pathlib import Path

from ..models import Component, Finding, Location, Severity, Source

_SEV = {
    "critical": Severity.critical, "high": Severity.high, "medium": Severity.medium,
    "low": Severity.low, "informational": Severity.info, "unknown": Severity.info,
}


class OpenHackConnector:
    """Stateless — reads OpenHack output files, no network."""

    def from_dir(self, run_dir: str | Path, repo: str) -> list[Finding]:
        """Ingest a run dir (or its finding-candidates/ folder)."""
        root = Path(run_dir)
        src = root / "finding-candidates"
        src = src if src.is_dir() else root
        findings: list[Finding] = []
        for path in sorted(src.glob("*.json")):
            findings.extend(self.from_file(path, repo))
        return findings

    def from_file(self, path: str | Path, repo: str) -> list[Finding]:
        data = json.loads(Path(path).read_text(encoding="utf-8"))
        if isinstance(data, list):
            items = data
        elif "candidates" in data or "findings" in data:
            items = data.get("candidates") or data.get("findings") or []
        else:
            items = [data]                       # a single candidate/finding object
        return [self._to_finding(it, repo) for it in items]

    def _to_finding(self, item: dict, repo: str) -> Finding:
        # A candidate wraps the finding; a bare finding object is also accepted.
        f = item.get("finding", item)
        vclass = item.get("primary_vulnerability_class") or f.get("primary_vulnerability_class", "")
        expert = item.get("expert", "")
        path = f.get("target_path")

        desc = f.get("summary") or f.get("non_technical_summary") or ""
        if f.get("impact"):
            desc = f"{desc}\n\nImpact: {f['impact']}".strip()
        if f.get("example_attack"):
            desc = f"{desc}\n\nExample: {f['example_attack']}".strip()

        return Finding(
            source=Source.openhack,
            source_ref=str(item.get("candidate_id") or f.get("title", "")),
            title=f.get("title", "OpenHack finding"),
            severity=_SEV.get((f.get("severity") or "unknown").lower(), Severity.info),
            component=Component(name=path or repo, ecosystem="source"),
            location=Location(repo=repo, path=path),
            description=desc,
            remediation=f.get("recommended_fix", ""),
            tags=list(dict.fromkeys(t for t in ["openhack", vclass, expert] if t)),
        )
