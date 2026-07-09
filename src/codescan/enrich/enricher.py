"""Deterministic exploitability signals: CISA KEV, FIRST EPSS, reachability.

These run before the AI engine and feed it. They are authoritative and
provide the model with grounded facts (is this CVE actively exploited in the
wild? how likely is exploitation? is the vulnerable code reachable?) instead of
asking it to infer them.
"""

from __future__ import annotations

import requests

from ..config import EnrichmentConfig
from ..models import Finding


def _is_reachable_signal(text: str) -> bool | None:
    normalized = text.lower()
    if any(p in normalized for p in ("not reachable", "no reachable path", "unreachable")):
        return False
    if "reachable" in normalized:
        return True
    return None


class Enricher:
    def __init__(self, cfg: EnrichmentConfig, *, offline: bool = False) -> None:
        self.cfg = cfg
        self.offline = offline
        self._kev: set[str] | None = None
        self._epss_cache: dict[str, float] = {}

    def enrich(self, findings: list[Finding]) -> None:
        kev = self._load_kev()
        cves = sorted({c for f in findings for c in f.cve_ids})
        epss = self._load_epss(cves)
        for f in findings:
            in_kev = any(c in kev for c in f.cve_ids)
            f.exploitability.in_kev = in_kev
            scores = [epss[c] for c in f.cve_ids if c in epss]
            f.exploitability.epss = max(scores) if scores else None
            f.exploitability.reachable = self._reachability_hint(f)

    # --- CISA Known Exploited Vulnerabilities ----------------------------
    def _load_kev(self) -> set[str]:
        if self._kev is not None:
            return self._kev
        if self.offline:
            self._kev = set()
            return self._kev
        try:
            data = requests.get(self.cfg.kev_url, timeout=30).json()
            self._kev = {v["cveID"] for v in data.get("vulnerabilities", [])}
        except Exception:  # KEV feed unavailable -> treat as empty, don't fail the run
            self._kev = set()
        return self._kev

    # --- FIRST EPSS -------------------------------------------------------
    def _load_epss(self, cves: list[str]) -> dict[str, float]:
        if self.offline or not cves:
            return {}
        out: dict[str, float] = {}
        # EPSS API accepts a comma-separated batch; chunk to keep URLs sane.
        for i in range(0, len(cves), 100):
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

    # --- reachability -----------------------------------------------------
    @staticmethod
    def _reachability_hint(f: Finding) -> bool | None:
        """Best-effort reachability signal.

        Snyk's reachable-vuln data, when present in the finding references or
        description, is the strongest signal. Absent that, leave it unknown
        (None) so the AI engine and scoring treat it conservatively rather
        than assuming unreachable.
        """
        haystack = f"{f.description} {' '.join(f.references)}"
        return _is_reachable_signal(haystack)
