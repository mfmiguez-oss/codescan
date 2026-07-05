"""GitHub connector — builds the repo inventory from github.com or GHES.

An alternative to Bitbucket as the SCM source (selected via `source.provider`).
Uses the REST API with a personal access token. Enumerates the configured
organizations, or — when none are listed — every repo the token can see.
Repo identity is `owner/name`, matching GitHub's `full_name`, so Snyk/Xray
findings anchor to the same repo regardless of SCM provider.
"""

from __future__ import annotations

from ..config import GitHubConfig
from ..models import Repo
from .base import HttpClient


class GitHubConnector:
    def __init__(self, cfg: GitHubConfig) -> None:
        self.cfg = cfg
        self.http = HttpClient(cfg.api_url, cfg.token, verify_tls=cfg.verify_tls)
        # GitHub-specific headers (works for api.github.com and GHES).
        self.http.session.headers["Accept"] = "application/vnd.github+json"
        self.http.session.headers["X-GitHub-Api-Version"] = "2022-11-28"

    def list_repos(self) -> list[Repo]:
        if self.cfg.orgs:
            repos: list[Repo] = []
            for org in self.cfg.orgs:
                repos.extend(self._to_repo(r) for r in self._paged(f"/orgs/{org}/repos"))
            return repos
        # No orgs configured: every repo the token can access.
        return [self._to_repo(r) for r in self._paged("/user/repos")]

    def _to_repo(self, r: dict) -> Repo:
        owner = (r.get("owner") or {}).get("login", "")
        return Repo(
            project_key=owner,
            slug=r["name"],
            name=r.get("full_name", r["name"]),
            clone_url=r.get("clone_url", ""),
            default_branch=r.get("default_branch", "main"),
        )

    def _paged(self, path: str) -> list[dict]:
        """Follow GitHub's page/per_page pagination."""
        out: list[dict] = []
        page = 1
        while True:
            data = self.http.get(path, params={"per_page": 100, "page": page}).json()
            if not isinstance(data, list) or not data:
                break
            out.extend(data)
            if len(data) < 100:
                break
            page += 1
        return out
