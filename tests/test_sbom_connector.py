"""SBOM connector — CycloneDX/SPDX parsing, embedded VEX, OSV matching (HTTP faked)."""

from __future__ import annotations

import json

from codescan.config import SbomConfig
from codescan.connectors import SbomConnector
from codescan.models import Severity, Source

_CYCLONEDX = {
    "bomFormat": "CycloneDX",
    "specVersion": "1.5",
    "components": [
        {"bom-ref": "pkg-lodash", "name": "lodash", "version": "4.17.20",
         "purl": "pkg:npm/lodash@4.17.20"},
    ],
    "vulnerabilities": [{
        "id": "CVE-2021-23337",
        "description": "Command injection via template.",
        "detail": "lodash versions before 4.17.21 are vulnerable.",
        "ratings": [{"severity": "high", "score": 7.2, "method": "CVSSv31"}],
        "cwes": [78],
        "affects": [{"ref": "pkg-lodash"}],
        "recommendation": "Upgrade to 4.17.21.",
        "advisories": [{"url": "https://example.test/advisory"}],
    }],
}

_SPDX = {
    "spdxVersion": "SPDX-2.3",
    "packages": [{
        "name": "requests", "versionInfo": "2.19.0",
        "externalRefs": [{"referenceCategory": "PACKAGE-MANAGER",
                          "referenceType": "purl",
                          "referenceLocator": "pkg:pypi/requests@2.19.0"}],
    }],
}

_OSV_VULN = {
    "id": "GHSA-x84v-xcm2-53pg",
    "aliases": ["CVE-2018-18074"],
    "summary": "Insufficiently protected credentials in requests",
    "details": "The Requests package sends HTTP Authorization headers to redirects.",
    "database_specific": {"severity": "MODERATE"},
    "severity": [{"type": "CVSS_V3", "score": "CVSS:3.0/AV:N/AC:L"}],
    "affected": [{"package": {"name": "requests", "ecosystem": "PyPI"},
                  "ranges": [{"type": "ECOSYSTEM",
                              "events": [{"introduced": "0"}, {"fixed": "2.20.0"}]}]}],
    "references": [{"type": "ADVISORY", "url": "https://example.test/ghsa"}],
}


class _Resp:
    def __init__(self, payload):
        self.payload = payload

    def json(self):
        return self.payload


class _FakeHttp:
    def __init__(self, routes):
        self.routes = routes
        self.calls = []

    def get(self, path, **kw):
        return self._route("GET", path)

    def post(self, path, **kw):
        return self._route("POST", path)

    def _route(self, method, path):
        self.calls.append(f"{method} {path}")
        for needle, payload in self.routes.items():
            if needle in path:
                return _Resp(payload)
        return _Resp({})


def _connector(routes=None, **cfg) -> SbomConnector:
    conn = SbomConnector(SbomConfig(**cfg))
    conn.http = _FakeHttp(routes or {})
    return conn


def test_embedded_cyclonedx_vulnerabilities_are_offline(tmp_path):
    path = tmp_path / "bom.cdx.json"
    path.write_text(json.dumps(_CYCLONEDX), encoding="utf-8")
    conn = _connector()
    (f,) = conn.from_file(path, "acme/checkout", offline=True)

    assert conn.http.calls == []                  # fully offline
    assert f.source == Source.sbom and f.source_ref == "CVE-2021-23337"
    assert f.cve_ids == ["CVE-2021-23337"] and f.cwe_ids == ["CWE-78"]
    assert f.severity == Severity.high and f.cvss_score == 7.2
    assert f.component.name == "lodash" and f.component.version == "4.17.20"
    assert f.remediation == "Upgrade to 4.17.21."
    assert f.references == ["https://example.test/advisory"]


def test_spdx_components_matched_against_osv(tmp_path):
    path = tmp_path / "bom.spdx.json"
    path.write_text(json.dumps(_SPDX), encoding="utf-8")
    conn = _connector(routes={
        "/v1/querybatch": {"results": [{"vulns": [{"id": "GHSA-x84v-xcm2-53pg"}]}]},
        "/v1/vulns/GHSA-x84v-xcm2-53pg": _OSV_VULN,
    })
    (f,) = conn.from_file(path, "acme/api")

    assert f.source == Source.sbom
    assert f.title == "Insufficiently protected credentials in requests"
    assert f.cve_ids == ["CVE-2018-18074"]
    assert f.severity == Severity.medium          # MODERATE
    assert f.cvss_vector == "CVSS:3.0/AV:N/AC:L"
    assert f.component.name == "requests" and f.component.version == "2.19.0"
    assert f.fixed_in == ["2.20.0"]
    assert "osv" in f.tags and "sbom" in f.tags


def test_offline_skips_osv_matching(tmp_path):
    path = tmp_path / "bom.spdx.json"
    path.write_text(json.dumps(_SPDX), encoding="utf-8")
    conn = _connector(routes={"/v1/querybatch": {"results": [{"vulns": [{"id": "X"}]}]}})
    assert conn.from_file(path, "a/b", offline=True) == []
    assert conn.http.calls == []


def test_osv_toggle_off_skips_matching(tmp_path):
    path = tmp_path / "bom.spdx.json"
    path.write_text(json.dumps(_SPDX), encoding="utf-8")
    conn = _connector(osv=False)
    assert conn.from_file(path, "a/b") == []
    assert conn.http.calls == []


def test_from_paths_globs_dirs_and_reads_repo_from_filename(tmp_path):
    (tmp_path / "acme__checkout.cdx.json").write_text(json.dumps(_CYCLONEDX), encoding="utf-8")
    (tmp_path / "notes.json").write_text("{}", encoding="utf-8")     # ignored
    conn = _connector()
    findings = conn.from_paths([str(tmp_path)], "default/repo", offline=True)
    assert [f.location.repo for f in findings] == ["acme/checkout"]
