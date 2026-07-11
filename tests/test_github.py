"""GitHub source connector + provider selection — no network."""

from __future__ import annotations

import pytest

from codescan.config import Config, GitHubConfig
from codescan.connectors import BitbucketConnector, GitHubConnector
from codescan.pipeline import Pipeline


def test_github_api_url_defaults_when_blank():
    # An unset ${GITHUB_API_URL} interpolates to "" — must fall back to public GitHub.
    assert GitHubConfig(api_url="").api_url == "https://api.github.com"
    assert GitHubConfig(api_url="   ").api_url == "https://api.github.com"
    assert GitHubConfig(api_url="https://ghe.internal/api/v3").api_url == "https://ghe.internal/api/v3"


def test_github_repo_mapping():
    repo = GitHubConnector(GitHubConfig())._to_repo({
        "name": "checkout",
        "full_name": "acme/checkout",
        "owner": {"login": "acme"},
        "clone_url": "https://github.com/acme/checkout.git",
        "default_branch": "main",
    })
    assert repo.project_key == "acme"
    assert repo.slug == "checkout"
    assert repo.full_name == "acme/checkout"       # matches GitHub full_name
    assert repo.default_branch == "main"


def test_provider_selects_connector():
    cfg = Config()
    assert isinstance(Pipeline(cfg)._repo_connector(), BitbucketConnector)  # default
    cfg.source.provider = "github"
    assert isinstance(Pipeline(cfg)._repo_connector(), GitHubConnector)


def test_snyk_xray_configured_flags():
    from codescan.config import SnykConfig, XrayConfig
    from codescan.connectors import SnykConnector, XrayConnector

    # Blank creds (unset ${ENV} -> "") -> not configured, so a live scan skips them.
    assert not SnykConnector(SnykConfig()).configured
    assert not XrayConnector(XrayConfig()).configured
    # Fully wired -> configured.
    assert SnykConnector(SnykConfig(api_url="https://snyk", token="t", org_id="o")).configured
    assert XrayConnector(XrayConfig(base_url="https://xray", token="t")).configured
    # Partial creds are still "not configured" (won't half-run and error).
    assert not SnykConnector(SnykConfig(api_url="https://snyk", token="t")).configured  # no org_id


def test_live_scan_skips_unconfigured_sources(monkeypatch):
    from codescan.connectors import github as gh_mod
    from codescan.connectors import snyk as snyk_mod
    from codescan.connectors import xray as xray_mod
    from codescan.models import Repo

    cfg = Config()
    cfg.source.provider = "github"        # no Snyk/Xray creds -> both unconfigured
    monkeypatch.setattr(gh_mod.GitHubConnector, "list_repos",
                        lambda self: [Repo(project_key="o", slug="r", name="o/r", clone_url="")])

    def boom(self, mapping):
        raise AssertionError("an unconfigured finding source must not be fetched")

    monkeypatch.setattr(snyk_mod.SnykConnector, "fetch", boom)
    monkeypatch.setattr(xray_mod.XrayConnector, "fetch", boom)

    repos, findings = Pipeline(cfg, offline=True, use_ai=False)._ingest_live()
    assert len(repos) == 1 and findings == []      # skipped cleanly, no error


class _FakeResp:
    def __init__(self, data):
        self._data = data

    def json(self):
        return self._data


class _FakeHttp:
    def __init__(self, mapping):
        self.mapping = mapping
        self.calls: list[str] = []

    def get(self, path, **kwargs):
        self.calls.append(path)
        return _FakeResp(self.mapping[path])


class _RaisingHttp:
    def get(self, path, **kwargs):
        raise RuntimeError(f"GET https://api.github.com{path} -> 404 Not Found: {{}}")


def test_github_404_gives_private_repo_hint():
    conn = GitHubConnector(GitHubConfig(repos=["mfmiguez-oss/horizon-scanner"]))
    conn.http = _RaisingHttp()
    with pytest.raises(RuntimeError) as exc:
        conn.list_repos()
    msg = str(exc.value)
    assert "mfmiguez-oss/horizon-scanner" in msg
    assert "private" in msg.lower() and "GITHUB_TOKEN" in msg


def test_github_targets_specific_repos():
    conn = GitHubConnector(GitHubConfig(repos=["acme/checkout"]))
    conn.http = _FakeHttp({
        "/repos/acme/checkout": {
            "name": "checkout", "full_name": "acme/checkout",
            "owner": {"login": "acme"}, "default_branch": "main",
        }
    })
    repos = conn.list_repos()
    assert [r.full_name for r in repos] == ["acme/checkout"]
    # Hits the single-repo endpoint, not org/user enumeration.
    assert conn.http.calls == ["/repos/acme/checkout"]
