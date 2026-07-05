"""OpenHack connector — parse finding-candidate JSON into codescan findings."""

from __future__ import annotations

import json

from codescan.connectors import OpenHackConnector
from codescan.models import Severity, Source


def _write(dir_, name, obj):
    p = dir_ / name
    p.write_text(json.dumps(obj), encoding="utf-8")
    return p


def test_candidate_envelope_mapping(tmp_path):
    cand = {
        "candidate_id": "S001-F001", "expert": "injection",
        "primary_vulnerability_class": "injection",
        "finding": {
            "title": "SQL injection in order lookup", "severity": "high",
            "target_path": "src/OrderController.java",
            "summary": "Concatenates orderId into SQL.",
            "impact": "Read/modify orders.",
            "recommended_fix": "Use a prepared statement.",
        },
    }
    findings = OpenHackConnector().from_file(_write(tmp_path, "c.json", cand), "acme/checkout")
    assert len(findings) == 1
    f = findings[0].ensure_id()
    assert f.source == Source.openhack
    assert f.severity == Severity.high
    assert f.location.repo == "acme/checkout"
    assert f.location.path == "src/OrderController.java"
    assert f.cve_ids == []                        # whitebox: no CVE
    assert f.remediation == "Use a prepared statement."
    assert "openhack" in f.tags and "injection" in f.tags
    assert "Impact:" in f.description


def test_bare_finding_and_severity_mapping(tmp_path):
    # A bare finding object (no candidate envelope), informational -> info.
    obj = {"title": "Info leak", "severity": "informational", "target_path": "x.py"}
    f = OpenHackConnector().from_file(_write(tmp_path, "b.json", obj), "a/b")[0]
    assert f.severity == Severity.info
    assert f.title == "Info leak"


def test_from_dir_reads_finding_candidates(tmp_path):
    fc = tmp_path / "finding-candidates"
    fc.mkdir()
    _write(fc, "S001-F001.json", {"finding": {"title": "A", "severity": "low", "target_path": "a"}})
    _write(fc, "S002-F001.json", {"finding": {"title": "B", "severity": "medium", "target_path": "b"}})
    findings = OpenHackConnector().from_dir(tmp_path, "acme/repo")   # run dir, not the fc dir
    assert sorted(f.title for f in findings) == ["A", "B"]
