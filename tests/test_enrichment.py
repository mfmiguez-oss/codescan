"""Enrichment framework tests — pure logic, no network or API key."""

from __future__ import annotations

from codescan.config import EnrichmentConfig
from codescan.enrich import ReachabilityEnricher, build_enrichers
from codescan.models import Component, Finding, Location, Source


def _finding(desc: str) -> Finding:
    return Finding(
        source=Source.snyk, source_ref="x", title="t",
        component=Component(name="p", version="1"),
        location=Location(repo="A/b"), description=desc,
    ).ensure_id()


def test_offline_skips_network_enrichers():
    e = build_enrichers(EnrichmentConfig(), llm=None, offline=True)
    assert [x.name for x in e] == ["reachability"]


def test_online_default_enrichers():
    e = build_enrichers(EnrichmentConfig(), llm=None, offline=False)
    assert [x.name for x in e] == ["kev", "epss", "reachability"]


def test_toggles_disable_enrichers():
    cfg = EnrichmentConfig(kev_enabled=False, epss_enabled=False)
    e = build_enrichers(cfg, llm=None, offline=False)
    assert [x.name for x in e] == ["reachability"]


def test_ai_enricher_requires_llm():
    # ai_enabled but no llm -> AI enricher is not added.
    cfg = EnrichmentConfig(ai_enabled=True)
    assert [x.name for x in build_enrichers(cfg, llm=None, offline=True)] == ["reachability"]


def test_reachability_hint():
    r = ReachabilityEnricher()
    f_yes = _finding("reachable from the checkout controller")
    f_no = _finding("not reachable from any exported handler")
    f_unknown = _finding("a vulnerability with no reachability info")
    r.enrich([f_yes, f_no, f_unknown])
    assert f_yes.exploitability.reachable is True
    assert f_no.exploitability.reachable is False
    assert f_unknown.exploitability.reachable is None
