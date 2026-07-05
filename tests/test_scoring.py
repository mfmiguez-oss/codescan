"""Scoring tests — threat influence enters once, via exploitability."""

from __future__ import annotations

from codescan.config import ScoringConfig
from codescan.models import Component, Finding, Location, Source
from codescan.scoring import Scorer


def _finding() -> Finding:
    return Finding(
        source=Source.snyk, source_ref="r", title="t", cvss_score=5.0,
        component=Component(name="p", version="1"), location=Location(repo="A/b"),
    ).ensure_id()


def test_threat_signal_raises_score_via_exploitability():
    base = _finding()
    threatened = _finding()
    threatened.exploitability.threat_signal = 90.0     # enriched by a threat model

    Scorer(ScoringConfig()).score([base, threatened], [])

    # The threat signal lifts the exploitability dimension, so the threatened
    # finding scores higher — and it's the only place threat is counted.
    assert threatened.risk_score > base.risk_score
