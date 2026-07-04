"""Web UI backend (FastAPI).

Wraps the pipeline in a small HTTP API and serves the single-page analyst
dashboard. It holds the latest scan result in memory; the UI reads it, drills
into exploitability and attack chains, and changes validation states (which
persist to the state store so triage sticks across re-scans).

Defaults are offline + no-AI so `codescan serve` works against the sample
fixtures with no credentials. A scan can be re-triggered with different options
via POST /api/scan.
"""

from __future__ import annotations

import json
from pathlib import Path

from fastapi import FastAPI, HTTPException
from fastapi.responses import HTMLResponse
from pydantic import BaseModel

from .config import Config, TaskModel
from .models import SERVICENOW_STATE, Finding, ValidationState
from .pipeline import Pipeline, PipelineResult
from .servicenow import ServiceNowExporter
from .validation import StateStore

STATIC = Path(__file__).parent / "static"

# Surfaced to the config UI for dropdowns.
KNOWN_MODELS = [
    "claude-fable-5", "claude-opus-4-8", "claude-opus-4-7",
    "claude-sonnet-5", "claude-sonnet-4-6", "claude-haiku-4-5",
]
EFFORTS = ["low", "medium", "high", "xhigh", "max"]
ROUTED_TASKS = ["dedup", "exploitability", "enrichment", "threat_model"]


def _mask(secret: str) -> str:
    return "••••••••" if secret else ""


def sanitized_config(cfg: Config) -> dict:
    """Config for the UI — editable settings plus masked, read-only secrets."""
    return {
        "ai": {
            "model": cfg.ai.model,
            "effort": cfg.ai.effort,
            "max_tokens": cfg.ai.max_tokens,
            "tasks": {
                name: {
                    "model": (t.model or ""),
                    "effort": (t.effort or ""),
                    "max_tokens": t.max_tokens,
                }
                for name, t in cfg.ai.tasks.items()
            },
        },
        "scoring": {"weights": dict(cfg.scoring.weights), "kev_floor": cfg.scoring.kev_floor},
        "enrichment": {
            "kev_enabled": cfg.enrichment.kev_enabled,
            "epss_enabled": cfg.enrichment.epss_enabled,
            "reachability_enabled": cfg.enrichment.reachability_enabled,
            "ai_enabled": cfg.enrichment.ai_enabled,
        },
        "threat_model": {"enabled": cfg.threat_model.enabled},
        "servicenow": {
            "instance": cfg.servicenow.instance,
            "push": cfg.servicenow.push,
            "import_table": cfg.servicenow.import_table,
            "password": _mask(cfg.servicenow.password),
        },
        "connectors": {
            "bitbucket": {"base_url": cfg.bitbucket.base_url, "token": _mask(cfg.bitbucket.token)},
            "snyk": {"api_url": cfg.snyk.api_url, "token": _mask(cfg.snyk.token)},
            "xray": {"base_url": cfg.xray.base_url, "token": _mask(cfg.xray.token)},
        },
        "options": {"known_models": KNOWN_MODELS, "efforts": EFFORTS, "routed_tasks": ROUTED_TASKS},
    }


def apply_config(cfg: Config, update: dict) -> None:
    """Apply editable settings from the UI onto a Config, in place.

    Only non-secret fields are writable; secrets stay in env/base config.
    Raises ValueError on invalid input.
    """
    ai = update.get("ai", {})
    if "model" in ai and ai["model"]:
        cfg.ai.model = str(ai["model"])
    if ai.get("effort"):
        cfg.ai.effort = _valid_effort(ai["effort"])
    if ai.get("max_tokens"):
        cfg.ai.max_tokens = int(ai["max_tokens"])
    if "tasks" in ai:
        for name, t in ai["tasks"].items():
            spec = TaskModel(
                model=(t.get("model") or None),
                effort=(_valid_effort(t["effort"]) if t.get("effort") else None),
                max_tokens=(int(t["max_tokens"]) if t.get("max_tokens") else None),
            )
            if spec.model or spec.effort or spec.max_tokens:
                cfg.ai.tasks[name] = spec
            else:
                cfg.ai.tasks.pop(name, None)

    sc = update.get("scoring", {})
    if "weights" in sc:
        cfg.scoring.weights = {k: float(v) for k, v in sc["weights"].items()}
    if "kev_floor" in sc:
        cfg.scoring.kev_floor = float(sc["kev_floor"])

    en = update.get("enrichment", {})
    for key in ("kev_enabled", "epss_enabled", "reachability_enabled", "ai_enabled"):
        if key in en:
            setattr(cfg.enrichment, key, bool(en[key]))

    if "enabled" in update.get("threat_model", {}):
        cfg.threat_model.enabled = bool(update["threat_model"]["enabled"])

    if "push" in update.get("servicenow", {}):
        cfg.servicenow.push = bool(update["servicenow"]["push"])


def _valid_effort(v: str) -> str:
    if v not in EFFORTS:
        raise ValueError(f"invalid effort: {v}")
    return v


def _deep_merge(base: dict, update: dict) -> dict:
    for k, v in update.items():
        if isinstance(v, dict) and isinstance(base.get(k), dict):
            _deep_merge(base[k], v)
        else:
            base[k] = v
    return base


def finding_to_dict(f: Finding) -> dict:
    ex = f.exploitability
    return {
        "id": f.id,
        "title": f.title,
        "cve_ids": f.cve_ids,
        "cwe_ids": f.cwe_ids,
        "severity": f.severity.value,
        "cvss_score": f.cvss_score,
        "cvss_vector": f.cvss_vector,
        "component": f.component.name,
        "version": f.component.version,
        "purl": f.component.purl,
        "repo": f.location.repo,
        "path": f.location.path,
        "fixed_in": f.fixed_in,
        "description": f.description,
        "references": f.references,
        "risk_score": f.risk_score,
        "validation_state": f.validation_state.value,
        "servicenow_state": SERVICENOW_STATE[f.validation_state],
        "sources": [s.value for s in f.merged_sources],
        "remediation": f.remediation,
        "tags": f.tags,
        "exploitability": {
            "level": ex.level.value,
            "score": ex.score,
            "reachable": ex.reachable,
            "in_kev": ex.in_kev,
            "epss": ex.epss,
            "rationale": ex.rationale,
            "chain_ids": ex.chain_ids,
        },
    }


class ScanRequest(BaseModel):
    fixtures: str | None = None
    use_ai: bool | None = None
    offline: bool | None = None


class StateChange(BaseModel):
    state: str


class AppState:
    """Holds config + the latest pipeline result for the API."""

    def __init__(self, config_path, fixtures, use_ai, offline, out_path, state_path, overrides_path):
        self.cfg = Config.load(config_path)
        self.fixtures = fixtures
        self.use_ai = use_ai
        self.offline = offline
        self.out_path = out_path
        self.state_path = state_path
        self.overrides_path = Path(overrides_path) if overrides_path else None
        # Layer any UI-saved overrides on top of the base config.
        if self.overrides_path and self.overrides_path.exists():
            apply_config(self.cfg, json.loads(self.overrides_path.read_text(encoding="utf-8")))
        self.result: PipelineResult = PipelineResult()
        self.scan()

    def update_config(self, update: dict) -> dict:
        apply_config(self.cfg, update)                  # validate + apply (raises on bad)
        if self.overrides_path:
            merged = {}
            if self.overrides_path.exists():
                merged = json.loads(self.overrides_path.read_text(encoding="utf-8"))
            _deep_merge(merged, update)
            self.overrides_path.write_text(json.dumps(merged, indent=2), encoding="utf-8")
        return sanitized_config(self.cfg)

    def scan(self, fixtures=None, use_ai=None, offline=None) -> PipelineResult:
        fx = self.fixtures if fixtures is None else fixtures
        ai = self.use_ai if use_ai is None else use_ai
        off = self.offline if offline is None else offline
        self.result = Pipeline(self.cfg, offline=off, use_ai=ai).run(
            fixtures=fx, out_path=self.out_path, state_path=self.state_path
        )
        return self.result

    def set_state(self, fid: str, state: str) -> Finding:
        f = next((x for x in self.result.findings if x.id == fid), None)
        if f is None:
            raise KeyError(fid)
        f.validation_state = ValidationState(state)     # raises ValueError if invalid
        store = StateStore(self.state_path)             # merge into existing decisions
        store.record(f, manual=True)
        store.save()
        return f

    def servicenow_items(self) -> list[dict]:
        return ServiceNowExporter(self.cfg.servicenow).build(
            self.result.findings, self.result.chains
        )


def _payload(state: AppState) -> dict:
    r = state.result
    findings = sorted(r.findings, key=lambda x: x.risk_score, reverse=True)
    return {
        "summary": r.summary(),
        "findings": [finding_to_dict(f) for f in findings],
        "chains": r.chains,
        "threat_models": [tm.model_dump() for tm in r.threat_models],
        "states": [s.value for s in ValidationState],
        "mode": {"use_ai": state.use_ai, "offline": state.offline},
    }


def create_app(
    config_path: str = "config/config.example.yaml",
    fixtures: str | None = None,
    *,
    use_ai: bool = False,
    offline: bool = False,
    out_path: str = "servicenow_import.json",
    state_path: str = "validation_state.json",
    overrides_path: str = "config.overrides.json",
) -> FastAPI:
    state = AppState(config_path, fixtures, use_ai, offline, out_path, state_path, overrides_path)
    app = FastAPI(title="codescan", version="0.1.0")

    @app.get("/", response_class=HTMLResponse)
    def index() -> str:
        return (STATIC / "index.html").read_text(encoding="utf-8")

    @app.get("/api/state")
    def get_state() -> dict:
        return _payload(state)

    @app.post("/api/scan")
    def scan(req: ScanRequest) -> dict:
        state.scan(req.fixtures, req.use_ai, req.offline)
        return _payload(state)

    @app.post("/api/findings/{fid}/state")
    def set_state(fid: str, change: StateChange) -> dict:
        try:
            f = state.set_state(fid, change.state)
        except KeyError:
            raise HTTPException(status_code=404, detail="finding not found")
        except ValueError:
            raise HTTPException(status_code=400, detail="invalid validation state")
        return finding_to_dict(f)

    @app.get("/api/servicenow")
    def servicenow() -> dict:
        return {"records": state.servicenow_items()}

    @app.get("/api/config")
    def get_config() -> dict:
        return sanitized_config(state.cfg)

    @app.post("/api/config")
    def set_config(update: dict) -> dict:
        try:
            return state.update_config(update)
        except (ValueError, TypeError, KeyError) as exc:
            raise HTTPException(status_code=400, detail=f"invalid config: {exc}")

    return app
