"""Enricher framework.

An enricher attaches signals/context to findings in place. They run in sequence;
each is independent and toggleable via config. Adding a new source (VEX,
internal asset criticality, exploit-DB, another AI pass) is a new `BaseEnricher`
subclass registered in `build_enrichers`.
"""

from __future__ import annotations

from ..models import Finding


class BaseEnricher:
    name = "base"

    def enrich(self, findings: list[Finding]) -> None:  # pragma: no cover - interface
        raise NotImplementedError
