"""Semantic deduplication (lower-cost tier — Haiku).

Deterministic dedup (`dedup.py`) merges findings with identical fingerprints.
It misses cross-scanner duplicates that describe the *same* weakness with
*different* identifiers — e.g. Snyk reports a CVE while Xray reports the same
issue by CWE + summary with no CVE, so their fingerprints diverge.

This pass catches those. It's mechanical judgement ("are these the same
vulnerability?"), not deep reasoning, so it runs on a lower-cost tier via the
model router. It is deliberately conservative: it only compares findings in the
same repo + same component, and only merges what the model marks as clearly the
same underlying vulnerability.
"""

from __future__ import annotations

from collections import defaultdict
from functools import reduce

from .dedup import _merge
from .llm import BatchItem, LLMClient
from .models import Finding, finding_component_label, size_difficulty

_SCHEMA = {
    "type": "object",
    "additionalProperties": False,
    "properties": {
        "merge_groups": {
            "type": "array",
            "items": {
                "type": "object",
                "additionalProperties": False,
                "properties": {
                    "finding_ids": {"type": "array", "items": {"type": "string"}},
                    "same_vulnerability": {"type": "boolean"},
                    "reason": {"type": "string"},
                },
                "required": ["finding_ids", "same_vulnerability", "reason"],
            },
        }
    },
    "required": ["merge_groups"],
}

_SYSTEM = """You deduplicate software-vulnerability findings. You are given several \
findings that affect the SAME component in the SAME repository but were not merged \
automatically because their identifiers differ. Decide which findings describe the \
SAME underlying vulnerability and should be merged.

Rules:
- Different CVEs affecting the same package are usually DIFFERENT vulnerabilities. \
Only group them if the titles/descriptions make clear they are the same issue.
- A finding with a CVE and one with only a CWE/title can be the same vulnerability \
if the weakness and description match.
- When uncertain, do NOT group. Precision matters more than recall here.
Return only groups you are confident about; set same_vulnerability=false for groups \
you are unsure about."""


def _digest(f: Finding) -> dict:
    return {
        "finding_id": f.id,
        "title": f.title,
        "cves": f.cve_ids,
        "cwes": f.cwe_ids,
        "component": finding_component_label(f),
        "sources": [s.value for s in f.merged_sources],
        "description": f.description[:300],
    }


class SemanticDeduper:
    def __init__(self, llm: LLMClient) -> None:
        self.llm = llm

    def refine(self, findings: list[Finding]) -> list[Finding]:
        survivors: dict[str, Finding] = {f.id: f for f in findings}

        # Candidate clusters: same repo + same component, more than one finding.
        clusters: dict[tuple[str, str], list[Finding]] = defaultdict(list)
        for f in findings:
            clusters[(f.location.repo, f.component.name.lower())].append(f)

        candidates = {
            f"{repo}\x00{comp}": (repo, comp, c)
            for (repo, comp), c in clusters.items() if len(c) >= 2
        }
        # One request per cluster (concurrent, or one batch); apply merges
        # sequentially afterwards so `survivors` is mutated in one place.
        items = [
            BatchItem(custom_id=key, system=_SYSTEM, user=self._user(repo, comp, cluster),
                      difficulty=size_difficulty(len(cluster)))
            for key, (repo, comp, cluster) in candidates.items()
        ]
        results = self.llm.complete_json_many("dedup", items, _SCHEMA)

        for key in candidates:                    # deterministic order
            result = results.get(key)
            if not result:
                continue
            for group in _merge_groups(result):
                members = [survivors[i] for i in group if i in survivors]
                if len(members) < 2:
                    continue
                merged = reduce(_merge, members)
                for m in members:
                    survivors.pop(m.id, None)
                survivors[merged.id] = merged

        return list(survivors.values())

    @staticmethod
    def _user(repo: str, component: str, cluster: list[Finding]) -> str:
        return (
            f"Repository: {repo}\nComponent: {component}\n\n"
            "Findings:\n"
            + "\n".join(str(_digest(f)) for f in cluster)
        )


def _merge_groups(result: dict) -> list[list[str]]:
    return [
        g["finding_ids"]
        for g in result.get("merge_groups", [])
        if g.get("same_vulnerability") and len(g.get("finding_ids", [])) > 1
    ]
