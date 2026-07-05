"""Bitbucket Data Center / Server connector — builds the repo inventory.

Uses the on-prem REST API (`/rest/api/1.0/...`) with an HTTP access token.
The repo inventory is the authoritative scan surface: Snyk/Xray findings are
only kept if they map back to a repo we actually own here.
"""

from __future__ import annotations

from ..config import BitbucketConfig
from ..models import Repo
from .base import HttpClient


class BitbucketConnector:
    def __init__(self, cfg: BitbucketConfig) -> None:
        self.cfg = cfg
        self.http = HttpClient(cfg.base_url, cfg.token, verify_tls=cfg.verify_tls)

    def list_repos(self) -> list[Repo]:
        projects = self.cfg.projects or [p["key"] for p in self._paged("/rest/api/1.0/projects")]
        repos: list[Repo] = []
        for key in projects:
            for r in self._paged(f"/rest/api/1.0/projects/{key}/repos"):
                repos.append(self._to_repo(key, r))
        return repos

    def _to_repo(self, project_key: str, r: dict) -> Repo:
        clone = ""
        for link in r.get("links", {}).get("clone", []):
            if link.get("name") == "http":
                clone = link.get("href", "")
                break
        return Repo(
            project_key=project_key,
            slug=r["slug"],
            name=r.get("name", r["slug"]),
            clone_url=clone,
            default_branch=(r.get("defaultBranch") or "refs/heads/main").split("/")[-1],
        )

    def _paged(self, path: str) -> list[dict]:
        """Follow Bitbucket's start/limit/isLastPage pagination."""
        out: list[dict] = []
        start = 0
        while True:
            resp = self.http.get(path, params={"start": start, "limit": 100})
            data = resp.json()
            out.extend(data.get("values", []))
            if data.get("isLastPage", True):
                break
            start = data.get("nextPageStart", start + 100)
        return out
