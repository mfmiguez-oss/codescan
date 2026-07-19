"""GitHub Dependabot / secret-scanning connectors — HTTP faked, no network."""

from __future__ import annotations

import pytest

from codescan.config import GitHubConfig
from codescan.connectors import DependabotConnector, SecretScanningConnector
from codescan.models import Repo, Severity, Source

_DEPENDABOT_ALERT = {
    "number": 7,
    "dependency": {"package": {"name": "lodash", "ecosystem": "npm"},
                   "manifest_path": "package-lock.json"},
    "security_advisory": {
        "summary": "Prototype pollution in lodash",
        "description": "Versions before 4.17.21 are vulnerable.",
        "severity": "high",
        "identifiers": [{"type": "GHSA", "value": "GHSA-xxxx"},
                        {"type": "CVE", "value": "CVE-2021-23337"}],
        "cwes": [{"cwe_id": "CWE-1321", "name": "Prototype pollution"}],
        "cvss": {"score": 7.2, "vector_string": "CVSS:3.1/AV:N"},
        "references": [{"url": "https://example.test/advisory"}],
    },
    "security_vulnerability": {
        "package": {"name": "lodash", "ecosystem": "npm"},
        "vulnerable_version_range": "< 4.17.21",
        "first_patched_version": {"identifier": "4.17.21"},
    },
}

_SECRET_ALERT = {
    "number": 3,
    "secret_type": "github_personal_access_token",
    "secret_type_display_name": "GitHub Personal Access Token",
    "secret": "ghp_SHOULD_NEVER_APPEAR",
    "validity": "active",
    "html_url": "https://github.com/acme/checkout/security/secret-scanning/3",
    "locations_url": "https://api.github.com/repos/acme/checkout/secret-scanning/alerts/3/locations",
}


class _Resp:
    def __init__(self, payload):
        self.payload = payload

    def json(self):
        return self.payload


class _FakeHttp:
    """Duck-typed HttpClient: serves canned payloads by path substring."""

    def __init__(self, routes: dict[str, object]):
        self.routes = routes
        self.calls: list[str] = []

    def get(self, path, **kwargs):
        self.calls.append(path)
        for needle, payload in self.routes.items():
            if needle in path:
                if isinstance(payload, Exception):
                    raise payload
                return _Resp(payload)
        return _Resp([])


def _repo(full="acme/checkout"):
    owner, _, slug = full.partition("/")
    return Repo(project_key=owner, slug=slug, name=full, clone_url="")


def _connector(cls, routes, **cfg):
    conn = cls(GitHubConfig(token="t", **cfg))
    conn.http = _FakeHttp(routes)
    return conn


def test_configured_requires_token_and_toggle():
    assert not DependabotConnector(GitHubConfig(token="t")).configured
    assert not DependabotConnector(GitHubConfig(dependabot_alerts=True)).configured
    assert DependabotConnector(GitHubConfig(token="t", dependabot_alerts=True)).configured
    assert SecretScanningConnector(
        GitHubConfig(token="t", secret_scanning_alerts=True)).configured


def test_dependabot_alert_maps_to_finding():
    conn = _connector(DependabotConnector, {"/dependabot/alerts": [_DEPENDABOT_ALERT]},
                      dependabot_alerts=True)
    (f,) = conn.fetch([_repo()])
    assert f.source == Source.dependabot and f.source_ref == "7"
    assert f.title == "Prototype pollution in lodash"
    assert f.cve_ids == ["CVE-2021-23337"] and f.cwe_ids == ["CWE-1321"]
    assert f.severity == Severity.high and f.cvss_score == 7.2
    assert f.component.name == "lodash" and f.component.ecosystem == "npm"
    assert f.location.repo == "acme/checkout" and f.location.path == "package-lock.json"
    assert f.fixed_in == ["4.17.21"]
    assert "< 4.17.21" in f.description
    assert f.references == ["https://example.test/advisory"]


def test_repo_without_the_feature_is_skipped_not_fatal():
    conn = _connector(DependabotConnector, {
        "/repos/acme/legacy/": RuntimeError("GET ... -> 403 Forbidden"),
        "/repos/acme/checkout/": [_DEPENDABOT_ALERT],
    }, dependabot_alerts=True)
    findings = conn.fetch([_repo("acme/legacy"), _repo("acme/checkout")])
    assert [f.location.repo for f in findings] == ["acme/checkout"]


def test_secret_alert_maps_without_copying_the_secret():
    conn = _connector(SecretScanningConnector, {
        "/secret-scanning/alerts/3/locations": [
            {"type": "commit", "details": {"path": ".env.example", "start_line": 12}}],
        "/secret-scanning/alerts": [_SECRET_ALERT],
    }, secret_scanning_alerts=True)
    (f,) = conn.fetch([_repo()])
    assert f.source == Source.secret_scanning
    assert f.title == "Exposed secret: GitHub Personal Access Token"
    assert f.severity == Severity.critical        # provider-verified live credential
    assert f.cwe_ids == ["CWE-798"]
    assert f.location.path == ".env.example" and f.location.start_line == 12
    # The secret value must never reach the finding.
    dumped = f.model_dump_json()
    assert "ghp_SHOULD_NEVER_APPEAR" not in dumped


def test_inactive_secret_is_high_and_survives_missing_locations():
    alert = dict(_SECRET_ALERT, validity="inactive", locations_url="")
    conn = _connector(SecretScanningConnector, {"/secret-scanning/alerts": [alert]},
                      secret_scanning_alerts=True)
    (f,) = conn.fetch([_repo()])
    assert f.severity == Severity.high
    assert f.location.path is None


@pytest.mark.parametrize("cls", [DependabotConnector, SecretScanningConnector])
def test_all_repos_failing_yields_no_findings(cls):
    conn = _connector(cls, {"/repos/": RuntimeError("404 Not Found")},
                      dependabot_alerts=True, secret_scanning_alerts=True)
    assert conn.fetch([_repo()]) == []
