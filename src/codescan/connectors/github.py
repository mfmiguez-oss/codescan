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
        # Most specific scope wins: explicit repos, then orgs, then everything.
        if self.cfg.repos:
            return [self._get_repo(full) for full in self.cfg.repos]
        if self.cfg.orgs:
            repos: list[Repo] = []
            for org in self.cfg.orgs:
                repos.extend(self._to_repo(r) for r in self._paged(f"/orgs/{org}/repos"))
            return repos
        # No repos/orgs configured: every repo the token can access.
        return [self._to_repo(r) for r in self._paged("/user/repos")]

    def _get_repo(self, full_name: str) -> Repo:
        """Fetch a single 'owner/name' repo (GET /repos/{owner}/{name})."""
        try:
            return self._to_repo(self.http.get(f"/repos/{full_name}").json())
        except RuntimeError as exc:
            if "404" in str(exc):
                # GitHub returns 404 (not 403) for private repos you can't see.
                raise RuntimeError(
                    f"GitHub repo '{full_name}' not found or not accessible. "
                    "If it is private, set GITHUB_TOKEN with access to it "
                    "(classic PAT with the 'repo' scope, or a fine-grained PAT "
                    "granting this repo Metadata: Read + Contents: Read). "
                    "Otherwise verify the owner/name."
                ) from exc
            raise

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
