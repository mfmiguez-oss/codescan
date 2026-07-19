"""SARIF connector — file ingestion and normalization (no network)."""

from __future__ import annotations

import json

from codescan.connectors import SarifConnector
from codescan.models import Severity, Source


def _sarif(results: list[dict], rules: list[dict], tool: str = "CodeQL") -> dict:
    return {
        "version": "2.1.0",
        "runs": [{"tool": {"driver": {"name": tool, "rules": rules}}, "results": results}],
    }


_RULE = {
    "id": "js/sql-injection",
    "shortDescription": {"text": "Database query built from user-controlled sources"},
    "fullDescription": {"text": "Building a SQL query from user input allows injection."},
    "defaultConfiguration": {"level": "error"},
    "properties": {"security-severity": "8.8",
                   "tags": ["security", "external/cwe/cwe-089"]},
}

_RESULT = {
    "ruleId": "js/sql-injection",
    "level": "error",
    "message": {"text": "This query depends on a user-provided value."},
    "locations": [{"physicalLocation": {
        "artifactLocation": {"uri": "src/db.js"},
        "region": {"startLine": 42},
    }}],
}


def test_from_file_maps_a_codeql_result(tmp_path):
    path = tmp_path / "scan.sarif"
    path.write_text(json.dumps(_sarif([_RESULT], [_RULE])), encoding="utf-8")

    (f,) = SarifConnector().from_file(path, "acme/checkout")
    assert f.source == Source.sarif
    assert f.title == "Database query built from user-controlled sources"
    assert f.severity == Severity.high            # from security-severity 8.8
    assert f.cvss_score == 8.8
    assert f.cwe_ids == ["CWE-89"]
    assert f.location.repo == "acme/checkout"
    assert f.location.path == "src/db.js" and f.location.start_line == 42
    assert "user-provided value" in f.description
    assert "codeql" in f.tags and "sarif" in f.tags


def test_level_fallback_when_no_security_severity(tmp_path):
    rule = {"id": "r1", "defaultConfiguration": {"level": "note"}}
    result = {"ruleId": "r1", "message": {"text": "Style issue in helper."}}
    path = tmp_path / "scan.sarif"
    path.write_text(json.dumps(_sarif([result], [rule], tool="Semgrep")), encoding="utf-8")

    (f,) = SarifConnector().from_file(path, "a/b")
    assert f.severity == Severity.low             # rule default level: note
    assert f.title == "Style issue in helper."    # message fallback
    assert f.source_ref.startswith("Semgrep/r1@")


def test_from_paths_globs_dirs_and_reads_repo_from_filename(tmp_path):
    doc = json.dumps(_sarif([_RESULT], [_RULE]))
    (tmp_path / "acme__checkout.sarif").write_text(doc, encoding="utf-8")
    (tmp_path / "other.sarif.json").write_text(doc, encoding="utf-8")
    (tmp_path / "unrelated.json").write_text("{}", encoding="utf-8")   # ignored

    findings = SarifConnector().from_paths([str(tmp_path)], "default/repo")
    assert {f.location.repo for f in findings} == {"acme/checkout", "default/repo"}
    assert len(findings) == 2
