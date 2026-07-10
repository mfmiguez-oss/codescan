"""CISA Known Exploited Vulnerabilities enricher."""

from __future__ import annotations

import logging

import requests

from ..config import EnrichmentConfig
from ..models import Finding
from .base import BaseEnricher

logger = logging.getLogger(__name__)


class KevEnricher(BaseEnricher):
    name = "kev"

    def __init__(self, cfg: EnrichmentConfig) -> None:
        self.cfg = cfg

    def enrich(self, findings: list[Finding]) -> None:
        kev = self._load()
        for f in findings:
            f.exploitability.in_kev = any(c in kev for c in f.cve_ids)

    def _load(self) -> set[str]:
        try:
            data = requests.get(self.cfg.kev_url, timeout=30).json()
            return {v["cveID"] for v in data.get("vulnerabilities", [])}
        except Exception as exc:  # noqa: BLE001 - degrade, don't fail the run
            logger.warning("KEV feed unavailable (%s); findings lose the KEV signal", exc)
            return set()
