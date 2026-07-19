"""ServiceNow exporter tests — JSON vs CSV output."""

from __future__ import annotations

import csv

from codescan.config import ServiceNowConfig
from codescan.models import Component, Finding, Location, Severity, Source
from codescan.servicenow import ServiceNowExporter


def _finding() -> Finding:
    return Finding(
        source=Source.snyk, source_ref="r", title="Log4Shell",
        cve_ids=["CVE-2021-44228"],
        component=Component(name="log4j", version="2.14.1"),
        location=Location(repo="PAY/checkout"),
        description="line one\nline two",     # newlines must survive CSV quoting
    ).ensure_id()


def test_csv_output_is_the_default(tmp_path):
    # CSV (ServiceNow CSV Import Set) is the default format — a `.json` out path
    # is written as its `.csv` sibling, and no JSON is produced.
    exporter = ServiceNowExporter(ServiceNowConfig())
    items = exporter.export([_finding()], [], tmp_path / "out.json")
    csv_path = tmp_path / "out.csv"
    assert csv_path.exists()
    assert not (tmp_path / "out.json").exists()
    assert exporter.output_path(tmp_path / "out.json") == csv_path

    header = csv_path.read_text(encoding="utf-8").splitlines()[0]
    assert "correlation_id" in header and "risk_score" in header

    # Round-trips as one row despite the multi-line work_notes.
    rows = list(csv.DictReader(csv_path.open(encoding="utf-8")))
    assert len(rows) == len(items) == 1
    assert rows[0]["vulnerability"] == "CVE-2021-44228"
    assert "line one" in rows[0]["description"]


def test_record_carries_fielded_detail(tmp_path):
    # The judgement signals must be fielded (filterable in VR), not only prose
    # in the work notes.
    f = _finding()
    f.severity = Severity.high
    f.remediation = "Upgrade log4j to 2.17.1."
    f.tags = ["sca", "corroborated"]
    f.location.start_line = 12
    f.component.ecosystem = "maven"
    (item,) = ServiceNowExporter(ServiceNowConfig()).build([f], [])

    assert item["severity"] == "high"
    assert item["reported_by"] == "snyk"
    assert item["exploitability_level"] == "info" and item["exploitability_score"] == 0.0
    assert item["remediation"] == "Upgrade log4j to 2.17.1."
    assert item["tags"] == "sca, corroborated"
    assert item["line"] == 12 and item["ecosystem"] == "maven"
    assert item["first_seen"]                     # ISO timestamp present
    assert "Remediation: Upgrade log4j" in item["work_notes"]


def test_csv_rows_have_no_blank_lines_between_them(tmp_path):
    # The writer emits RFC 4180 \r\n row endings; the file must carry them
    # unmodified. Text-mode newline translation on Windows would double them to
    # \r\r\n — rendering a blank row after every record in Excel/ServiceNow.
    ServiceNowExporter(ServiceNowConfig()).export(
        [_finding(), _finding()], [], tmp_path / "out.json")

    raw = (tmp_path / "out.csv").read_bytes()
    assert b"\r\r\n" not in raw
    assert raw.count(b"\r\n") == 3          # header + 2 records, nothing between
    # And no parser-visible empty rows.
    lines = raw.decode("utf-8").split("\r\n")
    assert all(line for line in lines[:-1]) and lines[-1] == ""


def test_json_output_when_configured(tmp_path):
    exporter = ServiceNowExporter(ServiceNowConfig(format="json"))
    exporter.export([_finding()], [], tmp_path / "out.json")
    assert (tmp_path / "out.json").exists()
    assert not (tmp_path / "out.csv").exists()
    assert exporter.output_path(tmp_path / "out.json") == tmp_path / "out.json"


class _FakeHttp:
    """Records posts; no network. Mirrors HttpClient's surface used by _push."""

    def __init__(self, *a, **k):
        self.session = type("S", (), {"auth": None, "headers": {}})()
        self.posts: list[tuple[str, dict]] = []

    def post(self, path, json=None, **kw):
        self.posts.append((path, json))


def test_push_posts_each_record(tmp_path, monkeypatch):
    fake = _FakeHttp()
    monkeypatch.setattr("codescan.servicenow.HttpClient", lambda *a, **k: fake)

    cfg = ServiceNowConfig(push=True, instance="https://acme.service-now.com",
                           user="svc", password="pw", import_table="sn_vul_vulnerable_item")
    items = ServiceNowExporter(cfg).export([_finding()], [], tmp_path / "out.json")

    # The push path actually runs (regression: _push was dead code) and targets
    # the configured Table API import table with the built record.
    assert len(fake.posts) == len(items) == 1
    path, body = fake.posts[0]
    assert path == "/api/now/table/sn_vul_vulnerable_item"
    assert body["correlation_id"] == items[0]["correlation_id"]
    assert fake.session.auth == ("svc", "pw")


def test_push_isolates_record_failures(tmp_path, monkeypatch):
    class Boom(_FakeHttp):
        def post(self, path, json=None, **kw):
            raise RuntimeError("500 boom")

    monkeypatch.setattr("codescan.servicenow.HttpClient", lambda *a, **k: Boom())
    cfg = ServiceNowConfig(push=True, user="u", password="p")
    # A failing push must not raise — the on-disk export still succeeds (CSV default).
    ServiceNowExporter(cfg).export([_finding()], [], tmp_path / "out.json")
    assert (tmp_path / "out.csv").exists()
