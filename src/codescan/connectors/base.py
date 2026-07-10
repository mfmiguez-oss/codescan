"""Shared HTTP plumbing for connectors."""

from __future__ import annotations

import logging
import time
from typing import Any

import requests

logger = logging.getLogger(__name__)


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
        if not url.lower().startswith(("http://", "https://")):
            # No base URL configured (e.g. an unset ${..._URL} env var). Fail fast
            # with a clear message instead of retrying a schemeless URL.
            raise RuntimeError(
                f"{method} {path}: no base URL configured (resolved to '{url}'). "
                "Set the connector's URL (e.g. GITHUB_API_URL / BITBUCKET_BASE_URL)."
            )
        last_exc: Exception | None = None
        for attempt in range(self.max_retries):
            try:
                resp = self.session.request(method, url, timeout=self.timeout, **kwargs)
                if resp.status_code in (429, 500, 502, 503, 504):
                    # Transient — back off and retry.
                    last_exc = RuntimeError(f"{resp.status_code} {resp.reason}")
                    delay = min(float(resp.headers.get("Retry-After", 2**attempt)), 30)
                    logger.warning("%s %s -> %s; retry %d/%d in %.0fs",
                                   method, url, resp.status_code, attempt + 1, self.max_retries, delay)
                    time.sleep(delay)
                    continue
                if resp.status_code >= 400:
                    # Client error (401/403/404/…) — not retryable. Fail fast with
                    # the real reason instead of an opaque "failed after N attempts".
                    detail = " ".join((resp.text or "").split())[:200]
                    raise RuntimeError(
                        f"{method} {url} -> {resp.status_code} {resp.reason}"
                        + (f": {detail}" if detail else "")
                    )
                return resp
            except requests.RequestException as exc:  # network-level failure
                last_exc = exc
                logger.warning("%s %s network error: %s; retry %d/%d",
                               method, url, exc, attempt + 1, self.max_retries)
                time.sleep(2**attempt)
        raise RuntimeError(f"{method} {url} failed after {self.max_retries} attempts ({last_exc})")
