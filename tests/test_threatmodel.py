"""Threat-modeling engine tests — a fake LLM, no network or API key."""

from __future__ import annotations

from codescan.models import Component, Finding, Location, Severity, Source
from codescan.threatmodel import (
    ThreatModelEngine, apply_threat_influence, service_risk_score,
)


class FakeLLM:
    """Duck-typed LLMClient: returns a canned structured result."""

    def __init__(self, payload: dict) -> None:
        self.payload = payload
        self.calls: list[str] = []

    def complete_json(self, task, system, user, schema):
        self.calls.append(task)
        return self.payload


def _finding(repo: str) -> Finding:
    return Finding(
        source=Source.snyk, source_ref="r", title="Log4Shell",
        cve_ids=["CVE-2021-44228"],
        component=Component(name="log4j", version="2.14.1"),
        location=Location(repo=repo),
    ).ensure_id()


def test_threat_model_parsed_and_linked():
    f = _finding("PAY/checkout")
    payload = {
        "assets": [{"name": "cardholder data", "sensitivity": "high"}],
        "entry_points": [{"name": "payment-callback", "description": "user-supplied URLs"}],
        "trust_boundaries": ["internet -> checkout service"],
        "threats": [{
            "id": "T1", "title": "RCE via Log4Shell",
            "stride": "elevation_of_privilege", "description": "JNDI injection",
            "likelihood": "high", "impact": "full service compromise",
            "related_finding_ids": [f.id], "related_chain_ids": [],
            "mitigations": ["upgrade log4j to 2.15.0+"],
        }],
        "posture_summary": "high risk", "risk_level": "critical",
        "recommendations": ["patch log4j immediately"],
    }
    tms = ThreatModelEngine(FakeLLM(payload)).build([f], [])
    assert len(tms) == 1
    tm = tms[0]
    assert tm.service == "PAY/checkout"
    assert tm.risk_level == "critical"
    assert tm.assets[0].name == "cardholder data"
    assert tm.threats[0].stride.value == "elevation_of_privilege"
    assert f.id in tm.threats[0].related_finding_ids


def test_per_service_grouping():
    fa, fb = _finding("A/one"), _finding("B/two")
    empty = {"assets": [], "entry_points": [], "trust_boundaries": [], "threats": [],
             "posture_summary": "", "risk_level": "low", "recommendations": []}
    llm = FakeLLM(empty)
    tms = llm and ThreatModelEngine(llm).build(
        [fa, fb], [{"chain_id": "c1", "finding_ids": [fa.id], "chain_score": 50}])
    assert {tm.service for tm in tms} == {"A/one", "B/two"}
    assert llm.calls == ["threat_model", "threat_model"]   # one call per service


def test_apply_threat_influence_enriches_exploitability():
    f = _finding("PAY/checkout")
    f.exploitability.level = Severity.low          # isolated assessment was low
    payload = {
        "assets": [], "entry_points": [], "trust_boundaries": [],
        "threats": [{
            "id": "T1", "title": "RCE", "stride": "elevation_of_privilege",
            "description": "", "likelihood": "high", "impact": "compromise",
            "related_finding_ids": [f.id], "related_chain_ids": [], "mitigations": [],
        }],
        "posture_summary": "", "risk_level": "critical", "recommendations": [],
    }
    tms = ThreatModelEngine(FakeLLM(payload)).build([f], [])

    service_risk = apply_threat_influence([f], tms)
    assert service_risk == {"PAY/checkout": "critical"}
    ex = f.exploitability
    assert ex.threat_ids == ["T1"]
    assert ex.threat_signal == 100.0               # high likelihood
    assert ex.level == Severity.high               # elevated from low
    assert "Elevated by threat model" in ex.rationale


def test_service_risk_score():
    assert service_risk_score("critical") == 100.0
    assert service_risk_score("low") == 20.0
    assert service_risk_score("") == 0.0

