"""FIRST EPSS (exploitation probability) enricher."""

from __future__ import annotations

import requests

from ..config import EnrichmentConfig
from ..models import Finding
from .base import BaseEnricher


class EpssEnricher(BaseEnricher):
    name = "epss"

    def __init__(self, cfg: EnrichmentConfig) -> None:
        self.cfg = cfg

    def enrich(self, findings: list[Finding]) -> None:
        cves = sorted({c for f in findings for c in f.cve_ids})
        scores = self._load(cves)
        for f in findings:
            vals = [scores[c] for c in f.cve_ids if c in scores]
            f.exploitability.epss = max(vals) if vals else None

    def _load(self, cves: list[str]) -> dict[str, float]:
        out: dict[str, float] = {}
        for i in range(0, len(cves), 100):          # batch to keep URLs sane
            chunk = cves[i : i + 100]
            try:
                resp = requests.get(
                    self.cfg.epss_url, params={"cve": ",".join(chunk)}, timeout=30
                ).json()
                for row in resp.get("data", []):
                    out[row["cve"]] = float(row["epss"])
            except Exception:
                continue
        return out
