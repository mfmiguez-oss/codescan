"""Enrichment framework: build the enabled enrichers and run them in order."""

from __future__ import annotations

from ..config import EnrichmentConfig
from ..llm import LLMClient
from ..models import Finding
from .ai import AIEnricher
from .base import BaseEnricher
from .epss import EpssEnricher
from .kev import KevEnricher
from .reachability import ReachabilityEnricher

__all__ = [
    "BaseEnricher", "KevEnricher", "EpssEnricher", "ReachabilityEnricher",
    "AIEnricher", "build_enrichers", "run_enrichment",
]


def build_enrichers(
    cfg: EnrichmentConfig,
    *,
    llm: LLMClient | None = None,
    offline: bool = False,
) -> list[BaseEnricher]:
    """Assemble the enabled enrichers. Network enrichers are skipped when offline."""
    enrichers: list[BaseEnricher] = []
    if cfg.kev_enabled and not offline:
        enrichers.append(KevEnricher(cfg))
    if cfg.epss_enabled and not offline:
        enrichers.append(EpssEnricher(cfg))
    if cfg.reachability_enabled:
        enrichers.append(ReachabilityEnricher())
    if cfg.ai_enabled and llm is not None:
        enrichers.append(AIEnricher(llm))
    return enrichers


def run_enrichment(findings: list[Finding], enrichers: list[BaseEnricher]) -> None:
    for enricher in enrichers:
        enricher.enrich(findings)
