"""Offline pipeline tests — no network, no Anthropic key required.

Runs the deterministic pipeline over the sample fixtures and asserts the
load-bearing behaviors: cross-scanner dedup, corroboration, reachability-driven
scoring, validation states, and ServiceNow record shape.
"""

from __future__ import annotations

from pathlib import Path

from codescan.config import Config
from codescan.models import Source
from codescan.pipeline import Pipeline

ROOT = Path(__file__).resolve().parents[1]
FIXTURES = ROOT / "fixtures"
CONFIG = ROOT / "config" / "config.example.yaml"


def _run(tmp_path):
    cfg = Config.load(CONFIG)
    pipe = Pipeline(cfg, offline=True, use_ai=False)
    return pipe.run(
        fixtures=FIXTURES,
        out_path=tmp_path / "sn.json",
        state_path=tmp_path / "state.json",
    )


def test_cross_scanner_dedup(tmp_path):
    result = _run(tmp_path)
    # Log4Shell is reported by both Snyk and Xray -> one finding, both sources.
    log4shell = [f for f in result.findings if "CVE-2021-44228" in f.cve_ids]
    assert len(log4shell) == 1
    assert set(log4shell[0].merged_sources) == {Source.snyk, Source.xray}


def test_finding_count(tmp_path):
    result = _run(tmp_path)
    # 5 scanner findings (2 snyk + 2 xray in PAY, 1 snyk in PLATFORM) with
    # Log4Shell collapsing -> 4 unique, plus 2 OpenHack whitebox findings -> 6.
    assert len(result.findings) == 6


def test_openhack_findings_ingested(tmp_path):
    result = _run(tmp_path)
    from codescan.models import Source
    oh = [f for f in result.findings if Source.openhack in f.merged_sources]
    assert len(oh) == 2
    titles = {f.title for f in oh}
    assert "SQL injection in order lookup" in titles
    # No CVE, but carries remediation + tags from OpenHack.
    sqli = next(f for f in oh if f.title.startswith("SQL injection"))
    assert sqli.cve_ids == [] and sqli.remediation
    assert "openhack" in sqli.tags and "injection" in sqli.tags


def test_reachability_scoring(tmp_path):
    result = _run(tmp_path)
    by_cve = {f.cve_ids[0]: f for f in result.findings if f.cve_ids}
    log4shell = by_cve["CVE-2021-44228"]        # reachable, critical
    lodash = by_cve["CVE-2020-8203"]            # not reachable, medium
    assert log4shell.exploitability.reachable is True
    assert lodash.exploitability.reachable is False
    # Reachability + severity separate the two clearly.
    assert log4shell.risk_score > lodash.risk_score


def test_validation_states(tmp_path):
    result = _run(tmp_path)
    by_cve = {f.cve_ids[0]: f for f in result.findings if f.cve_ids}
    # Unreachable, low-exploitability medium -> flagged for investigation (candidate FP).
    assert by_cve["CVE-2020-8203"].validation_state.value == "under_investigation"


def test_servicenow_records(tmp_path):
    result = _run(tmp_path)
    items = result.servicenow_items
    assert len(items) == len(result.findings)
    # Records are highest-risk-first and carry an idempotent upsert key.
    scores = [r["risk_score"] for r in items]
    assert scores == sorted(scores, reverse=True)
    assert all(r["correlation_id"] for r in items)
    assert all(r["state"] for r in items)


def test_calibration_drift_raises_audit_event(tmp_path):
    """A store where high-scored predictions were mostly dismissed must surface
    a calibration.drift audit event on the next scan (the SIEM alert path)."""
    import json

    from codescan.models import Component, Finding, Location, Source, ValidationState
    from codescan.validation import StateStore

    store = StateStore(tmp_path / "state.json")
    for i in range(5):
        f = Finding(
            id=f"seed{i}", source=Source.snyk, source_ref="r", title="t",
            cwe_ids=["CWE-9999"], component=Component(name="seedpkg"),
            location=Location(repo="seed/repo"),
        )
        f.risk_score = 90.0
        f.validation_state = ValidationState.false_positive
        store.record(f, manual=True)
    store.save()

    _run(tmp_path)

    events = [json.loads(line)
              for line in (tmp_path / "audit.jsonl").read_text(encoding="utf-8").splitlines()]
    drift = [e for e in events if e["event"] == "calibration.drift"]
    assert drift and "high-score precision drift" in drift[0]["alert"]


def test_max_findings_per_scan_caps_and_keeps_worst(tmp_path):
    cfg = Config.load(CONFIG)
    cfg.server.max_findings_per_scan = 3        # fixtures have 6 findings
    cfg.audit.enabled = True
    import json

    result = Pipeline(cfg, offline=True, use_ai=False).run(
        fixtures=FIXTURES, out_path=tmp_path / "sn.json", state_path=tmp_path / "state.json",
    )
    assert len(result.findings) == 3
    # The cap keeps the highest-CVSS findings, never silently drops the worst.
    full = _run(tmp_path / "full")
    top3 = sorted((f.cvss_score or 0 for f in full.findings), reverse=True)[:3]
    assert sorted((f.cvss_score or 0 for f in result.findings), reverse=True) == top3
    # Truncation is audited.
    events = [json.loads(line) for line in
              (tmp_path / "audit.jsonl").read_text(encoding="utf-8").splitlines()]
    trunc = [e for e in events if e["event"] == "scan.truncated"]
    assert trunc and trunc[0]["dropped"] == 3


def test_persistent_state_survives_rerun(tmp_path):
    result = _run(tmp_path)
    state_file = tmp_path / "state.json"
    # Analyst closes one item as a false positive.
    import json
    states = json.loads(state_file.read_text())
    target = result.findings[0].id
    states[target] = "false_positive"
    state_file.write_text(json.dumps(states))

    rerun = _run(tmp_path)
    reran = next(f for f in rerun.findings if f.id == target)
    assert reran.validation_state.value == "false_positive"
