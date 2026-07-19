"""SARIF connector — ingest findings from any SARIF-emitting scanner.

SARIF 2.1.0 is the interchange format nearly every modern scanner writes —
CodeQL, Semgrep, Trivy, Checkov, Gitleaks, Bandit, and dozens more — so one
file-based connector onboards that whole ecosystem without per-vendor work.
Point `sarif.paths` at files or directories of `*.sarif` / `*.sarif.json`
exports (fixtures mode picks up `<repo>.sarif[.json]` files automatically).

Severity comes from the rule's GitHub-convention `security-severity` property
(a CVSS-like score) when present, else the SARIF `level`; CWE ids are pulled
from rule tags like `external/cwe/cwe-079`.
"""

from __future__ import annotations

import json
import re
from pathlib import Path

from ..models import Component, Finding, Location, Severity, Source

_LEVEL_SEV = {"error": Severity.high, "warning": Severity.medium,
              "note": Severity.low, "none": Severity.info}
_CWE_TAG = re.compile(r"cwe[-/](\d+)", re.IGNORECASE)


def _text(obj: dict | None) -> str:
    return (obj or {}).get("text", "") or ""


class SarifConnector:
    """Stateless — reads SARIF files, no network."""

    def from_paths(self, paths: list[str], default_repo: str) -> list[Finding]:
        """Ingest files and/or directories of SARIF exports.

        A file named `OWNER__name.sarif[.json]` anchors to that repo (the same
        `__` = `/` convention as fixtures); anything else uses `default_repo`.
        """
        findings: list[Finding] = []
        for entry in paths:
            p = Path(entry)
            files = (sorted(set(p.glob("*.sarif")) | set(p.glob("*.sarif.json")))
                     if p.is_dir() else [p])
            for f in files:
                stem = f.name.split(".")[0]
                repo = stem.replace("__", "/") if "__" in stem else default_repo
                findings.extend(self.from_file(f, repo))
        return findings

    def from_file(self, path: str | Path, repo: str) -> list[Finding]:
        data = json.loads(Path(path).read_text(encoding="utf-8"))
        findings: list[Finding] = []
        for run in data.get("runs", []):
            driver = (run.get("tool") or {}).get("driver") or {}
            tool = driver.get("name", "sarif")
            rules = {r.get("id"): r for r in driver.get("rules", []) if r.get("id")}
            for result in run.get("results", []):
                findings.append(self._to_finding(result, rules, tool, repo))
        return findings

    def _to_finding(self, result: dict, rules: dict, tool: str, repo: str) -> Finding:
        rule_id = result.get("ruleId", "")
        rule = rules.get(rule_id, {})
        props = rule.get("properties") or {}

        # GitHub-convention security-severity (CVSS-like) beats the coarse level.
        cvss: float | None = None
        raw_sev = props.get("security-severity")
        if raw_sev is not None:
            try:
                cvss = float(raw_sev)
            except (TypeError, ValueError):
                pass
        level = (result.get("level")
                 or (rule.get("defaultConfiguration") or {}).get("level") or "warning")
        severity = (Severity.from_cvss(cvss) if cvss is not None
                    else _LEVEL_SEV.get(level, Severity.medium))

        cwes = list(dict.fromkeys(
            f"CWE-{m.group(1).lstrip('0') or '0'}"
            for tag in props.get("tags", [])
            if (m := _CWE_TAG.search(str(tag)))
        ))

        phys = ((result.get("locations") or [{}])[0].get("physicalLocation") or {})
        file_path = (phys.get("artifactLocation") or {}).get("uri")
        line = (phys.get("region") or {}).get("startLine")

        message = _text(result.get("message"))
        first_line = message.splitlines()[0][:120] if message else ""
        title = _text(rule.get("shortDescription")) or first_line or rule_id or "SARIF finding"
        description = message
        if (full := _text(rule.get("fullDescription"))) and full not in description:
            description = f"{description}\n\n{full}".strip()

        return Finding(
            source=Source.sarif,
            source_ref=f"{tool}/{rule_id}@{file_path or ''}:{line or 0}",
            title=title,
            severity=severity,
            cvss_score=cvss,
            cwe_ids=cwes,
            component=Component(name=file_path or repo, ecosystem="source"),
            location=Location(repo=repo, path=file_path, start_line=line),
            description=description,
            tags=list(dict.fromkeys(t for t in ("sarif", tool.lower()) if t)),
        )
