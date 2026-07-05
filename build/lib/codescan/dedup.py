"""Deduplication: collapse Snyk + Xray reports of the same weakness.

Two findings merge when their fingerprints match (same vuln id + package +
repo path — see `Finding.fingerprint`). The merged record keeps the richest
value for each field and records provenance from every contributing scanner,
so a CVE seen by both tools becomes one ServiceNow item, not two.
"""

from __future__ import annotations

from .models import Finding, Severity, Source


def deduplicate(findings: list[Finding]) -> list[Finding]:
    merged: dict[str, Finding] = {}
    for f in findings:
        f.ensure_id()
        if f.id not in merged:
            merged[f.id] = f
        else:
            merged[f.id] = _merge(merged[f.id], f)
    return list(merged.values())


def _merge(a: Finding, b: Finding) -> Finding:
    """Combine two findings with the same fingerprint into the stronger one."""
    # Keep whichever reported the higher severity as the primary record.
    primary, secondary = (a, b) if a.severity.rank >= b.severity.rank else (b, a)

    sources = list(dict.fromkeys([*primary.merged_sources, *secondary.merged_sources]))
    primary.merged_sources = sources

    primary.cve_ids = sorted(set(primary.cve_ids) | set(secondary.cve_ids))
    primary.cwe_ids = sorted(set(primary.cwe_ids) | set(secondary.cwe_ids))
    primary.references = list(dict.fromkeys([*primary.references, *secondary.references]))
    primary.fixed_in = list(dict.fromkeys([*primary.fixed_in, *secondary.fixed_in]))

    # Prefer a present CVSS score/vector and a non-empty description.
    primary.cvss_score = primary.cvss_score if primary.cvss_score is not None else secondary.cvss_score
    primary.cvss_vector = primary.cvss_vector or secondary.cvss_vector
    if len(secondary.description) > len(primary.description):
        primary.description = secondary.description

    # Recompute severity from the (possibly newly available) CVSS score.
    if primary.severity == Severity.info and primary.cvss_score:
        primary.severity = Severity.from_cvss(primary.cvss_score)

    primary.first_seen = min(primary.first_seen, secondary.first_seen)
    return primary


def corroboration_bonus(finding: Finding) -> float:
    """Small confidence bump (0-1) when multiple scanners agree."""
    return 1.0 if {Source.snyk, Source.xray}.issubset(set(finding.merged_sources)) else 0.0
