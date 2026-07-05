"""Shared HTTP plumbing for connectors."""

from __future__ import annotations

import time
from typing import Any

import requests


class HttpClient:
    """Thin requests wrapper with bearer auth, retries, and paging helpers."""

    def __init__(
        self,
        base_url: str,
        token: str,
        *,
        verify_tls: bool = True,
        auth_scheme: str = "Bearer",
        timeout: float = 30.0,
        max_retries: int = 3,
    ) -> None:
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout
        self.max_retries = max_retries
        self.session = requests.Session()
        self.session.verify = verify_tls
        if token:
            self.session.headers["Authorization"] = f"{auth_scheme} {token}".strip()
        self.session.headers["Accept"] = "application/json"

    def get(self, path: str, **kwargs: Any) -> requests.Response:
        return self._request("GET", path, **kwargs)

    def post(self, path: str, **kwargs: Any) -> requests.Response:
        return self._request("POST", path, **kwargs)

    def _request(self, method: str, path: str, **kwargs: Any) -> requests.Response:
        url = path if path.startswith("http") else f"{self.base_url}/{path.lstrip('/')}"
        last_exc: Exception | None = None
        for attempt in range(self.max_retries):
            try:
                resp = self.session.request(method, url, timeout=self.timeout, **kwargs)
                if resp.status_code in (429, 500, 502, 503, 504):
                    delay = float(resp.headers.get("Retry-After", 2**attempt))
                    time.sleep(min(delay, 30))
                    continue
                resp.raise_for_status()
                return resp
            except requests.RequestException as exc:  # network-level failure
                last_exc = exc
                time.sleep(2**attempt)
        raise RuntimeError(f"{method} {url} failed after {self.max_retries} attempts") from last_exc
