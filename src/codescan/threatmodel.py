"""Threat-modeling engine (deep tier).

The exploitability engine works bottom-up: per-finding scores and concrete attack
chains. Threat modeling is the top-down counterpart — for each service it names
the assets worth protecting, the entry points / trust boundaries, and the STRIDE
threats that the findings and chains actually enable, then gives an overall
posture and prioritized recommendations. Threats link back to the finding IDs and
chain IDs that evidence them, so the model is grounded, not generic.

Optional and per-service (like exploitability), routed to the "threat_model" task
(the default deep tier unless overridden in config).
"""

from __future__ import annotations

import json
from collections import defaultdict

from .llm import LLMClient
from .models import Asset, EntryPoint, Finding, Severity, Stride, Threat, ThreatModel

_STRIDE = [s.value for s in Stride]

_SCHEMA = {
    "type": "object",
    "additionalProperties": False,
    "properties": {
        "assets": {
            "type": "array",
            "items": {
                "type": "object", "additionalProperties": False,
                "properties": {"name": {"type": "string"}, "sensitivity": {"type": "string"}},
                "required": ["name", "sensitivity"],
            },
        },
        "entry_points": {
            "type": "array",
            "items": {
                "type": "object", "additionalProperties": False,
                "properties": {"name": {"type": "string"}, "description": {"type": "string"}},
                "required": ["name", "description"],
            },
        },
        "trust_boundaries": {"type": "array", "items": {"type": "string"}},
        "threats": {
            "type": "array",
            "items": {
                "type": "object", "additionalProperties": False,
                "properties": {
                    "id": {"type": "string"},
                    "title": {"type": "string"},
                    "stride": {"type": "string", "enum": _STRIDE},
                    "description": {"type": "string"},
                    "likelihood": {"type": "string", "enum": ["high", "medium", "low"]},
                    "impact": {"type": "string"},
                    "related_finding_ids": {"type": "array", "items": {"type": "string"}},
                    "related_chain_ids": {"type": "array", "items": {"type": "string"}},
                    "mitigations": {"type": "array", "items": {"type": "string"}},
                },
                "required": [
                    "id", "title", "stride", "description", "likelihood",
                    "impact", "related_finding_ids", "related_chain_ids", "mitigations",
                ],
            },
        },
        "posture_summary": {"type": "string"},
        "risk_level": {"type": "string", "enum": ["critical", "high", "medium", "low"]},
        "recommendations": {"type": "array", "items": {"type": "string"}},
    },
    "required": [
        "assets", "entry_points", "trust_boundaries", "threats",
        "posture_summary", "risk_level", "recommendations",
    ],
}

_SYSTEM = """You are a senior application-security engineer building a STRIDE threat \
model for one service, grounded in its verified scanner findings and the attack \
chains already identified for it. Do not invent vulnerabilities beyond what the \
findings and chains support.

Produce:
- assets: what an attacker would target in this service (data, credentials, \
functionality), with a sensitivity note.
- entry_points and trust_boundaries: the attack surface implied by the components \
and findings.
- threats: concrete STRIDE-categorized threats this service faces. Each must cite \
the related_finding_ids and related_chain_ids that evidence it, a likelihood, an \
impact, and specific mitigations. Prefer fewer, well-grounded threats over many \
generic ones.
- posture_summary, risk_level, and prioritized recommendations.

This is authorized defensive security work for the organization that owns the code."""


def _finding_digest(f: Finding) -> dict:
    ex = f.exploitability
    return {
        "finding_id": f.id,
        "title": f.title,
        "cves": f.cve_ids,
        "cwes": f.cwe_ids,
        "severity": f.severity.value,
        "component": f"{f.component.name}@{f.component.version}",
        "exploitability": ex.score,
        "in_kev": ex.in_kev,
        "reachable": ex.reachable,
        "chain_ids": ex.chain_ids,
        "tags": f.tags,
    }


class ThreatModelEngine:
    TASK = "threat_model"

    def __init__(self, llm: LLMClient) -> None:
        self.llm = llm

    def build(self, findings: list[Finding], chains: list[dict]) -> list[ThreatModel]:
        by_repo: dict[str, list[Finding]] = defaultdict(list)
        for f in findings:
            by_repo[f.location.repo].append(f)

        models: list[ThreatModel] = []
        for repo, group in by_repo.items():
            repo_fids = {f.id for f in group}
            repo_chains = [
                c for c in chains
                if any(fid in repo_fids for fid in c.get("finding_ids", []))
            ]
            models.append(self._build_one(repo, group, repo_chains))
        return models

    def _build_one(self, repo: str, group: list[Finding], chains: list[dict]) -> ThreatModel:
        payload = {
            "service": repo,
            "findings": [_finding_digest(f) for f in group],
            "attack_chains": chains,
        }
        user = ("Build a STRIDE threat model for this service.\n\n"
                + json.dumps(payload, indent=2))
        result = self.llm.complete_json(self.TASK, _SYSTEM, user, _SCHEMA)
        return self._parse(repo, result)

    @staticmethod
    def _parse(repo: str, r: dict) -> ThreatModel:
        return ThreatModel(
            service=repo,
            assets=[Asset(**a) for a in r.get("assets", [])],
            entry_points=[EntryPoint(**e) for e in r.get("entry_points", [])],
            trust_boundaries=r.get("trust_boundaries", []),
            threats=[
                Threat(
                    id=t["id"], title=t["title"], stride=Stride(t["stride"]),
                    description=t.get("description", ""), likelihood=t.get("likelihood", ""),
                    impact=t.get("impact", ""),
                    related_finding_ids=t.get("related_finding_ids", []),
                    related_chain_ids=t.get("related_chain_ids", []),
                    mitigations=t.get("mitigations", []),
                )
                for t in r.get("threats", [])
            ],
            posture_summary=r.get("posture_summary", ""),
            risk_level=r.get("risk_level", ""),
            recommendations=r.get("recommendations", []),
        )


_LIKELIHOOD = {"high": 100.0, "medium": 60.0, "low": 30.0}


def apply_threat_influence(
    findings: list[Finding], threat_models: list[ThreatModel]
) -> dict[str, str]:
    """Feed threat-model results back onto findings, and return per-service risk.

    For each finding cited by a threat: record the threat IDs, derive a
    `threat_signal` (0-100) from the strongest citing threat's likelihood, and
    *enrich exploitability* by raising the categorical level (and noting why in
    the rationale) when the threat implies more than the isolated assessment did.
    The returned `{service: risk_level}` map feeds the scorer's threat boost.
    """
    by_fid: dict[str, list[Threat]] = defaultdict(list)
    service_risk: dict[str, str] = {}
    for tm in threat_models:
        service_risk[tm.service] = tm.risk_level
        for t in tm.threats:
            for fid in t.related_finding_ids:
                by_fid[fid].append(t)

    for f in findings:
        threats = by_fid.get(f.id, [])
        if not threats:
            continue
        ex = f.exploitability
        ex.threat_ids = [t.id for t in threats]
        ex.threat_signal = max(_LIKELIHOOD.get(t.likelihood, 40.0) for t in threats)
        implied = (Severity.high if ex.threat_signal >= 80
                   else Severity.medium if ex.threat_signal >= 50 else Severity.low)
        if implied.rank > ex.level.rank:
            ex.level = implied
            note = f" Elevated by threat model (cited in {len(threats)} threat(s))."
            ex.rationale = (ex.rationale + note).strip()
    return service_risk


def service_risk_score(risk_level: str) -> float:
    return {"critical": 100.0, "high": 75.0, "medium": 45.0, "low": 20.0}.get(risk_level, 0.0)
