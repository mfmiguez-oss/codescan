"""SBOM connector — ingest CycloneDX / SPDX SBOMs as a findings source.

An SBOM lists components, not vulnerabilities, so this connector works in two
layers:

* **Embedded vulnerabilities** — a CycloneDX SBOM may carry a `vulnerabilities`
  array (VEX/VDR). Those are ingested directly, fully offline.
* **OSV matching** — component purls are matched against OSV.dev (free, no
  account): one `POST /v1/querybatch` for the whole SBOM, then each distinct
  vulnerability's details fetched once from `GET /v1/vulns/{id}`. Skipped on
  `--offline` scans (`sbom.osv` turns it off entirely).

Findings carry CVE + component name@version + repo, so the cross-scanner dedup
merges and corroborates them with Snyk / Xray / Dependabot findings naturally.
"""

from __future__ import annotations

import json
import logging
from pathlib import Path

from ..config import SbomConfig
from ..models import Component, Finding, Location, Severity, Source
from .base import HttpClient

logger = logging.getLogger(__name__)

_SEV = {"critical": Severity.critical, "high": Severity.high,
        "moderate": Severity.medium, "medium": Severity.medium, "low": Severity.low}
_OSV_BATCH = 500                 # querybatch limit is 1000; stay comfortably under
_SBOM_GLOBS = ("*.cdx.json", "*.spdx.json", "*.sbom.json")


def _severity(label: str | None, cvss: float | None) -> Severity:
    return _SEV.get((label or "").lower(), Severity.from_cvss(cvss))


class SbomConnector:
    def __init__(self, cfg: SbomConfig) -> None:
        self.cfg = cfg
        self.http = HttpClient(cfg.osv_url, token="")

    def from_paths(self, paths: list[str], default_repo: str, *,
                   offline: bool = False) -> list[Finding]:
        """Ingest SBOM files and/or directories of them.

        A file named `OWNER__name.<ext>` anchors to that repo (the fixtures
        `__` = `/` convention); anything else uses `default_repo`.
        """
        findings: list[Finding] = []
        for entry in paths:
            p = Path(entry)
            files = (sorted({f for g in _SBOM_GLOBS for f in p.glob(g)})
                     if p.is_dir() else [p])
            for f in files:
                stem = f.name.split(".")[0]
                repo = stem.replace("__", "/") if "__" in stem else default_repo
                findings.extend(self.from_file(f, repo, offline=offline))
        return findings

    def from_file(self, path: str | Path, repo: str, *,
                  offline: bool = False) -> list[Finding]:
        doc = json.loads(Path(path).read_text(encoding="utf-8"))
        components = _parse_components(doc)
        findings = [self._embedded_to_finding(v, components, repo)
                    for v in doc.get("vulnerabilities", [])]
        if self.cfg.osv and not offline:
            findings.extend(self._match_osv(components, repo))
        elif self.cfg.osv:
            logger.info("sbom: offline — skipping OSV matching for %s", path)
        return findings

    # --- embedded CycloneDX vulnerabilities (offline) ---------------------
    def _embedded_to_finding(self, vuln: dict, components: list[dict],
                             repo: str) -> Finding:
        by_ref = {c["bom-ref"]: c for c in components if c.get("bom-ref")}
        affected = next((by_ref[a["ref"]] for a in vuln.get("affects", [])
                         if a.get("ref") in by_ref), {})
        ratings = vuln.get("ratings", [])
        cvss = next((r["score"] for r in ratings
                     if isinstance(r.get("score"), (int, float))), None)
        label = next((r["severity"] for r in ratings if r.get("severity")), None)
        vid = vuln.get("id", "")
        return Finding(
            source=Source.sbom,
            source_ref=vid,
            title=vuln.get("description", "").split("\n")[0][:120] or vid or "SBOM vulnerability",
            cve_ids=[vid] if vid.startswith("CVE-") else [],
            cwe_ids=[f"CWE-{c}" for c in vuln.get("cwes", [])],
            severity=_severity(label, cvss),
            cvss_score=float(cvss) if cvss is not None else None,
            component=Component(name=affected.get("name", "unknown"),
                                version=affected.get("version"),
                                purl=affected.get("purl")),
            location=Location(repo=repo),
            description=vuln.get("detail") or vuln.get("description", ""),
            remediation=vuln.get("recommendation", ""),
            references=[a["url"] for a in vuln.get("advisories", []) if a.get("url")],
            tags=["sbom"],
        )

    # --- OSV.dev matching (network) ---------------------------------------
    def _match_osv(self, components: list[dict], repo: str) -> list[Finding]:
        with_purl = [c for c in components if c.get("purl")]
        # vuln id -> the components it affects (one finding per component).
        hits: dict[str, list[dict]] = {}
        for i in range(0, len(with_purl), _OSV_BATCH):
            batch = with_purl[i:i + _OSV_BATCH]
            queries = [{"package": {"purl": c["purl"]}} for c in batch]
            results = self.http.post("/v1/querybatch",
                                     json={"queries": queries}).json().get("results", [])
            for comp, res in zip(batch, results):
                for v in (res or {}).get("vulns", []):
                    if v.get("id"):
                        hits.setdefault(v["id"], []).append(comp)

        findings: list[Finding] = []
        for vid in sorted(hits):
            try:
                vuln = self.http.get(f"/v1/vulns/{vid}").json()
            except RuntimeError as exc:
                logger.warning("sbom: OSV details unavailable for %s (%s)", vid, exc)
                continue
            findings.extend(self._osv_to_finding(vuln, comp, repo) for comp in hits[vid])
        return findings

    def _osv_to_finding(self, vuln: dict, comp: dict, repo: str) -> Finding:
        vid = vuln.get("id", "")
        aliases = vuln.get("aliases", [])
        cves = sorted({i for i in (vid, *aliases) if i.startswith("CVE-")})
        vector = next((s["score"] for s in vuln.get("severity", [])
                       if isinstance(s.get("score"), str)), None)
        # OSV severity entries are CVSS vectors, not numbers; the human label
        # lives in database_specific (GHSA-sourced entries).
        label = (vuln.get("database_specific") or {}).get("severity")
        fixed = sorted({
            e["fixed"]
            for aff in vuln.get("affected", [])
            for rng in aff.get("ranges", [])
            for e in rng.get("events", [])
            if e.get("fixed")
        })
        return Finding(
            source=Source.sbom,
            source_ref=vid,
            title=vuln.get("summary") or f"{vid} in {comp.get('name', 'component')}",
            cve_ids=cves,
            severity=_severity(label, None),
            cvss_vector=vector,
            component=Component(name=comp.get("name", "unknown"),
                                version=comp.get("version"), purl=comp.get("purl")),
            location=Location(repo=repo),
            fixed_in=fixed,
            description=(vuln.get("details") or vuln.get("summary") or "")[:4000],
            references=[r["url"] for r in vuln.get("references", [])[:10] if r.get("url")],
            tags=["sbom", "osv"],
        )


def _parse_components(doc: dict) -> list[dict]:
    """Component dicts (name/version/purl/bom-ref) from CycloneDX or SPDX JSON."""
    if doc.get("bomFormat") == "CycloneDX" or "components" in doc:
        return [
            {"name": c.get("name", "unknown"), "version": c.get("version"),
             "purl": c.get("purl"), "bom-ref": c.get("bom-ref")}
            for c in doc.get("components", [])
        ]
    if "spdxVersion" in doc:
        out = []
        for pkg in doc.get("packages", []):
            purl = next((r["referenceLocator"] for r in pkg.get("externalRefs", [])
                         if r.get("referenceType") == "purl" and r.get("referenceLocator")),
                        None)
            out.append({"name": pkg.get("name", "unknown"),
                        "version": pkg.get("versionInfo"), "purl": purl, "bom-ref": None})
        return out
    return []
