"""AI enricher — remediation guidance + tags (lower-cost tier).

Complements the exploitability engine rather than duplicating it: that engine
scores exploitability and finds chains; this one adds analyst-facing context —
concrete remediation steps, categorization tags (OWASP class, direct vs
transitive, weakness family), and a reachability judgement when the scanner gave
no signal. Routed to the enrichment task (Haiku by default) and batched per
repository.
"""

from __future__ import annotations

import json

from ..concurrency import map_workers, workers_of
from ..llm import LLMClient
from ..models import Finding, finding_component_label, group_difficulty, group_findings_by_repo
from .base import BaseEnricher

_SCHEMA = {
    "type": "object",
    "additionalProperties": False,
    "properties": {
        "items": {
            "type": "array",
            "items": {
                "type": "object",
                "additionalProperties": False,
                "properties": {
                    "finding_id": {"type": "string"},
                    "remediation": {"type": "string"},
                    "tags": {"type": "array", "items": {"type": "string"}},
                    "reachable": {"type": "string", "enum": ["yes", "no", "unknown"]},
                },
                "required": ["finding_id", "remediation", "tags", "reachable"],
            },
        }
    },
    "required": ["items"],
}

_SYSTEM = """You enrich already-triaged vulnerability findings with concise, \
actionable context for a security analyst. For each finding provide:
- remediation: the concrete fix in 1-2 sentences (e.g. "Upgrade X to >= Y", or a \
config/mitigation if no fix exists). Prefer the provided fixed versions.
- tags: 3-6 short labels for triage — OWASP category, weakness family (e.g. \
deserialization, SSRF), direct vs transitive dependency, and any exposure note.
- reachable: your judgement of whether the vulnerable code is reachable, based on \
the description ("yes"/"no"/"unknown"). Use "unknown" when the text doesn't say.
Be specific and grounded in the data provided. This is authorized defensive work."""


def _digest(f: Finding) -> dict:
    return {
        "finding_id": f.id,
        "title": f.title,
        "cves": f.cve_ids,
        "cwes": f.cwe_ids,
        "component": finding_component_label(f),
        "fixed_in": f.fixed_in,
        "description": f.description[:400],
    }


class AIEnricher(BaseEnricher):
    name = "ai"

    def __init__(self, llm: LLMClient) -> None:
        self.llm = llm

    def enrich(self, findings: list[Finding]) -> None:
        by_repo = group_findings_by_repo(findings)
        by_id = {f.id: f for f in findings}
        # Query per-repo groups concurrently, then apply in order.
        results = map_workers(
            lambda item: self._ask(item[0], item[1]),
            list(by_repo.items()),
            workers_of(self.llm),
        )
        for result in results:
            self._apply(result, by_id)

    def _ask(self, repo: str, group: list[Finding]) -> dict:
        user = f"Service: {repo}\n\n" + json.dumps([_digest(f) for f in group], indent=2)
        return self.llm.complete_json(
            "enrichment", _SYSTEM, user, _SCHEMA, difficulty=group_difficulty(group)
        )

    def _apply(self, result: dict, by_id: dict[str, Finding]) -> None:
        for it in result.get("items", []):
            f = by_id.get(it["finding_id"])
            if not f:
                continue
            f.remediation = it.get("remediation", "")
            f.tags = it.get("tags", [])
            # Only fill reachability the deterministic pass left unknown.
            if f.exploitability.reachable is None:
                r = it.get("reachable")
                f.exploitability.reachable = {"yes": True, "no": False}.get(r)
