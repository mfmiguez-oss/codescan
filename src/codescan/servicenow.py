"""ServiceNow Vulnerability Response (VR) export.

Emits records shaped for the `sn_vul_vulnerable_item` import — one per deduped
finding — carrying our composite risk score, validation state, and (crucially)
the exploitability rationale and attack-chain context in the work notes so an
analyst sees *why* the tool ranked it where it did.

`correlation_id` is the finding fingerprint, which makes the import idempotent:
re-runs upsert the same VI instead of creating duplicates, and closed items
remain closed (see the persisted states in `validation.py`).
"""

from __future__ import annotations

import csv
import io
import json
import logging
from pathlib import Path

from .config import ServiceNowConfig
from .connectors.base import HttpClient
from .models import SERVICENOW_STATE, Finding

logger = logging.getLogger(__name__)


def _risk_rating(score: float) -> str:
    if score >= 85:
        return "Critical"
    if score >= 70:
        return "High"
    if score >= 40:
        return "Medium"
    if score > 0:
        return "Low"
    return "None"


def to_vulnerable_item(f: Finding, chains_by_id: dict[str, dict]) -> dict:
    ex = f.exploitability
    chain_notes = ""
    for cid in ex.chain_ids:
        c = chains_by_id.get(cid)
        if not c:
            continue
        chain_notes += (
            f"\n[Attack chain {cid}] (score {c.get('chain_score')}, "
            f"likelihood {c.get('likelihood')})\n"
            f"  {c.get('narrative', '')}\n"
            f"  Preconditions: {c.get('preconditions', '')}\n"
            f"  Impact: {c.get('impact', '')}\n"
            f"  MITRE ATT&CK: {', '.join(c.get('mitre_attack', []))}\n"
        )

    work_notes = (
        f"Composite risk score: {f.risk_score}/100 ({_risk_rating(f.risk_score)})\n"
        f"Reported by: {', '.join(s.value for s in f.merged_sources)}\n"
        f"CVSS: {f.cvss_score} ({f.cvss_vector or 'n/a'})\n"
        f"KEV: {ex.in_kev} | EPSS: {ex.epss} | reachable: {ex.reachable}\n"
        f"Exploitability ({ex.level.value}, {ex.score}/100): {ex.rationale}"
        f"{chain_notes}"
    )

    return {
        # Import-set / VI fields.
        "correlation_id": f.id,                         # idempotent upsert key
        "source": "codescan",
        "vulnerability": (f.cve_ids[0] if f.cve_ids else f.title),
        "cve_ids": ", ".join(f.cve_ids),
        "cwe_ids": ", ".join(f.cwe_ids),
        "short_description": f.title,
        "description": f.description[:4000],
        "state": SERVICENOW_STATE[f.validation_state],
        "codescan_validation_state": f.validation_state.value,
        "risk_score": f.risk_score,
        "risk_rating": _risk_rating(f.risk_score),
        "risk_score_source": "codescan_composite",
        "active_exploit": ex.in_kev,
        "epss_score": ex.epss,
        "cvss_base_score": f.cvss_score,
        # Asset / location — VR reconciles these to CMDB CIs.
        "repository": f.location.repo,
        "file": f.location.path,
        "component": f.component.name,
        "component_version": f.component.version,
        "package_url": f.component.purl,
        "fixed_versions": ", ".join(f.fixed_in),
        "attack_chain_ids": ", ".join(ex.chain_ids),
        "work_notes": work_notes,
        "references": " ".join(f.references[:10]),
    }


class ServiceNowExporter:
    def __init__(self, cfg: ServiceNowConfig) -> None:
        self.cfg = cfg

    def build(self, findings: list[Finding], chains: list[dict]) -> list[dict]:
        chains_by_id = {c["chain_id"]: c for c in chains}
        # Highest risk first — matches how analysts triage the VR queue.
        ordered = sorted(findings, key=lambda f: f.risk_score, reverse=True)
        return [to_vulnerable_item(f, chains_by_id) for f in ordered]

    def output_path(self, out_path: str | Path) -> Path:
        """The file `export` actually writes for the configured format —
        a `.csv` sibling for CSV (the default), else `out_path` as given."""
        p = Path(out_path)
        return p.with_suffix(".csv") if self._is_csv else p

    @property
    def _is_csv(self) -> bool:
        return (self.cfg.format or "csv").lower() == "csv"

    def export(
        self,
        findings: list[Finding],
        chains: list[dict],
        out_path: str | Path,
    ) -> list[dict]:
        items = self.build(findings, chains)
        dest = self.output_path(out_path)

        if self._is_csv:
            self._write_csv(items, dest)      # ServiceNow CSV Import Set transform
        else:
            dest.write_text(json.dumps({"records": items}, indent=2), encoding="utf-8")

        if self.cfg.push:
            self._push(items)
        return items

    @staticmethod
    def _write_csv(items: list[dict], path: Path) -> None:
        path.write_text(items_to_csv(items), encoding="utf-8")

    def _push(self, items: list[dict]) -> tuple[int, int]:
        """POST each record into the configured import table (Table API).

        Idempotent on `correlation_id`, so a failed record is safe to retry on the
        next run — we isolate per-record failures (log and continue) rather than
        aborting the whole push, and return `(ok, failed)` counts.
        """
        http = HttpClient(self.cfg.instance, token="")
        http.session.auth = (self.cfg.user, self.cfg.password)
        http.session.headers["Content-Type"] = "application/json"
        ok = failed = 0
        for item in items:
            try:
                http.post(f"/api/now/table/{self.cfg.import_table}", json=item)
                ok += 1
            except Exception as exc:  # noqa: BLE001 - isolate one bad record
                failed += 1
                logger.warning(
                    "ServiceNow push failed for %s: %s", item.get("correlation_id"), exc
                )
        (logger.error if failed else logger.info)(
            "ServiceNow push: %d ok, %d failed -> %s", ok, failed, self.cfg.import_table
        )
        return ok, failed


def items_to_csv(items: list[dict]) -> str:
    """Render vulnerable-item records as CSV (multi-line work notes are quoted)."""
    if not items:
        return ""
    # Every record shares the same keys (built by to_vulnerable_item).
    fieldnames = list(items[0].keys())
    buf = io.StringIO()
    writer = csv.DictWriter(buf, fieldnames=fieldnames, extrasaction="ignore")
    writer.writeheader()
    for item in items:
        writer.writerow({k: ("" if v is None else v) for k, v in item.items()})
    return buf.getvalue()
