"""GitHub source connector + provider selection — no network."""

from __future__ import annotations

from codescan.config import Config, GitHubConfig
from codescan.connectors import BitbucketConnector, GitHubConnector
from codescan.pipeline import Pipeline


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
