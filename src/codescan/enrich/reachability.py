"""Reachability enricher — best-effort signal from scanner metadata.

Snyk's reachable-vuln data, when surfaced in the description/references, is the
strongest signal. Absent that, reachability stays unknown (None) so scoring and
the AI stages treat it conservatively rather than assuming unreachable.
"""

from __future__ import annotations

from ..models import Finding
from .base import BaseEnricher


class ReachabilityEnricher(BaseEnricher):
    name = "reachability"

    def enrich(self, findings: list[Finding]) -> None:
        for f in findings:
            f.exploitability.reachable = self._hint(f)

    @staticmethod
    def _hint(f: Finding) -> bool | None:
        haystack = f"{f.description} {' '.join(f.references)}".lower()
        # Negative phrasing first — "not reachable" also contains "reachable".
        if any(p in haystack for p in ("not reachable", "no reachable path", "unreachable")):
            return False
        if "reachable" in haystack:
            return True
        return None
