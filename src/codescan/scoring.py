"""Composite risk scoring.

CVSS alone over-ranks unreachable theoretical CVEs and under-ranks chainable
mediums. The composite score blends four weighted dimensions:

  severity        - base CVSS-derived impact
  exploitability  - AI judgement, floored/raised by KEV and EPSS
  exposure        - network reachability of the vulnerable path
  chaining        - membership in a multi-step attack chain

Findings in the CISA KEV catalog are floored to `kev_floor` regardless of the
blended value, because "actively exploited in the wild" outweighs modelling.
"""

from __future__ import annotations

from .config import ScoringConfig
from .dedup import corroboration_bonus
from .models import Finding


class Scorer:
    def __init__(self, cfg: ScoringConfig) -> None:
        self.cfg = cfg
        total = sum(cfg.weights.values())
        # Normalize weights so the score stays 0-100 even if they don't sum to 1.
        self.w = {k: v / total for k, v in cfg.weights.items()} if total else cfg.weights

    def score(self, findings: list[Finding], chains: list[dict]) -> None:
        chain_score_by_id: dict[str, float] = {}
        for c in chains:
            cs = float(c.get("chain_score", 0))
            for fid in c.get("finding_ids", []):
                chain_score_by_id[fid] = max(chain_score_by_id.get(fid, 0.0), cs)

        for f in findings:
            f.risk_score = self._score_one(f, chain_score_by_id.get(f.id, 0.0))

    def _score_one(self, f: Finding, chain_score: float) -> float:
        severity = (f.cvss_score * 10) if f.cvss_score else (f.severity.rank / 4 * 100)
        exploit = self._exploit_component(f)
        exposure = self._exposure_component(f)

        blended = (
            self.w.get("severity", 0) * severity
            + self.w.get("exploitability", 0) * exploit
            + self.w.get("exposure", 0) * exposure
            + self.w.get("chaining", 0) * chain_score
        )
        # Multi-scanner agreement adds a small confidence bump.
        blended += 2.0 * corroboration_bonus(f)

        if f.exploitability.in_kev:
            blended = max(blended, self.cfg.kev_floor)

        return round(min(blended, 100.0), 1)

    @staticmethod
    def _exploit_component(f: Finding) -> float:
        ex = f.exploitability
        parts: list[float] = []
        if ex.score:
            parts.append(ex.score)                    # AI judgement (0-100)
        if ex.epss is not None:
            parts.append(ex.epss * 100)               # EPSS probability
        if ex.in_kev:
            parts.append(100.0)
        if not parts:
            parts.append(f.severity.rank / 4 * 100)   # fall back to severity
        return sum(parts) / len(parts)

    @staticmethod
    def _exposure_component(f: Finding) -> float:
        network = bool(f.cvss_vector and "AV:N" in f.cvss_vector)
        if f.exploitability.reachable is True:
            return 100.0 if network else 70.0
        if f.exploitability.reachable is False:
            return 10.0
        # Unknown reachability: infer from attack vector, stay conservative.
        return 60.0 if network else 35.0
