"""ServiceNow exporter tests — JSON vs CSV output."""

from __future__ import annotations

import csv

from codescan.config import ServiceNowConfig
from codescan.models import Component, Finding, Location, Source
from codescan.servicenow import ServiceNowExporter


def _finding() -> Finding:
    return Finding(
        source=Source.snyk, source_ref="r", title="Log4Shell",
        cve_ids=["CVE-2021-44228"],
        component=Component(name="log4j", version="2.14.1"),
        location=Location(repo="PAY/checkout"),
        description="line one\nline two",     # newlines must survive CSV quoting
    ).ensure_id()


def test_json_output_default(tmp_path):
    ServiceNowExporter(ServiceNowConfig()).export([_finding()], [], tmp_path / "out.json")
    assert (tmp_path / "out.json").exists()
    assert not (tmp_path / "out.csv").exists()


def test_csv_output(tmp_path):
    items = ServiceNowExporter(ServiceNowConfig(format="csv")).export(
        [_finding()], [], tmp_path / "out.json")
    csv_path = tmp_path / "out.csv"
    assert csv_path.exists()
    assert not (tmp_path / "out.json").exists()     # csv mode doesn't also write json

    header = csv_path.read_text(encoding="utf-8").splitlines()[0]
    assert "correlation_id" in header and "risk_score" in header

    # Round-trips as one row despite the multi-line work_notes.
    rows = list(csv.DictReader(csv_path.open(encoding="utf-8")))
    assert len(rows) == len(items) == 1
    assert rows[0]["vulnerability"] == "CVE-2021-44228"
    assert "line one" in rows[0]["description"]
