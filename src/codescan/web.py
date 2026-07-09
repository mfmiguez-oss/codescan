"""Web UI backend (FastAPI).

Wraps the pipeline in a small HTTP API and serves the single-page analyst
dashboard. It holds the latest scan result in memory; the UI reads it, drills
into exploitability and attack chains, and changes validation states (which
persist to the state store so triage persists across rescans).

Defaults are offline + no-AI so `codescan serve` works against the sample
fixtures with no credentials. A scan can be re-triggered with different options
via POST /api/scan.
"""

from __future__ import annotations

import json
import shlex
from datetime import datetime, timezone
from pathlib import Path

from fastapi import FastAPI, HTTPException
from fastapi.responses import HTMLResponse, Response
from pydantic import BaseModel

from .config import Config, TaskModel
from .models import SERVICENOW_STATE, Finding, ValidationState
from .pipeline import Pipeline, PipelineResult
from .providers import PROVIDERS
from .servicenow import ServiceNowExporter, items_to_csv
from .validation import StateStore

STATIC = Path(__file__).parent / "static"

# Surfaced to the config UI for dropdowns.
KNOWN_MODELS = [
    "claude-fable-5", "claude-opus-4-8", "claude-opus-4-7",
    "claude-sonnet-5", "claude-sonnet-4-6", "claude-haiku-4-5",
]
EFFORTS = ["low", "medium", "high", "xhigh", "max"]
ROUTED_TASKS = ["dedup", "exploitability", "enrichment", "threat_model", "openhack"]
SCM_PROVIDERS = ["bitbucket", "github"]


def _mask(secret: str) -> str:
    return "••••••••" if secret else ""


def _set_bool(target: object, update: dict, field: str) -> None:
    if field in update:
        setattr(target, field, bool(update[field]))


def _set_str(target: object, update: dict, field: str, *, strip: bool = True) -> None:
    if field in update:
        value = update[field]
        if isinstance(value, str) and strip:
            value = value.strip()
        setattr(target, field, str(value))


def sanitized_config(cfg: Config) -> dict:
    """Config for the UI — editable settings plus masked, read-only secrets."""
    return {
        "ai": {
            "provider": cfg.ai.provider,
            "model": cfg.ai.model,
            "effort": cfg.ai.effort,
            "max_tokens": cfg.ai.max_tokens,
            "max_concurrency": cfg.ai.max_concurrency,
            "auto_route": cfg.ai.auto_route,
            "tasks": {
                name: {
                    "provider": (t.provider or ""),
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
        "openhack": {
            "enabled": cfg.openhack.enabled,
            "findings_dir": cfg.openhack.findings_dir,
            "repo": cfg.openhack.repo,
            "auto": cfg.openhack.auto,
            # Empty command = codescan's built-in in-process review engine.
            "command": " ".join(cfg.openhack.command),
            "engine": "external" if cfg.openhack.command else "built-in",
            "workspace": cfg.openhack.workspace,
            "clone": cfg.openhack.clone,
            "passes": cfg.openhack.passes,
            "max_files": cfg.openhack.max_files,
            "max_file_bytes": cfg.openhack.max_file_bytes,
            "min_confidence": cfg.openhack.min_confidence,
        },
        "servicenow": {
            "instance": cfg.servicenow.instance,
            "push": cfg.servicenow.push,
            "import_table": cfg.servicenow.import_table,
            "format": cfg.servicenow.format,
            "password": _mask(cfg.servicenow.password),
        },
        "source": {
            "provider": cfg.source.provider,
            "github_repos": cfg.github.repos,
            "github_orgs": cfg.github.orgs,
        },
        "connectors": {
            "bitbucket": {"base_url": cfg.bitbucket.base_url, "token": _mask(cfg.bitbucket.token)},
            "github": {"api_url": cfg.github.api_url, "token": _mask(cfg.github.token)},
            "snyk": {"api_url": cfg.snyk.api_url, "token": _mask(cfg.snyk.token)},
            "xray": {"base_url": cfg.xray.base_url, "token": _mask(cfg.xray.token)},
        },
        "options": {
            "known_models": KNOWN_MODELS, "efforts": EFFORTS,
            "routed_tasks": ROUTED_TASKS, "scm_providers": SCM_PROVIDERS,
            "ai_providers": PROVIDERS,
        },
    }


def apply_config(cfg: Config, update: dict) -> None:
    """Apply editable settings from the UI onto a Config, in place.

    Only non-secret fields are writable; secrets stay in env/base config.
    Raises ValueError on invalid input.
    """
    ai = update.get("ai", {})
    if ai.get("provider"):
        cfg.ai.provider = _valid_provider(ai["provider"])
    if "model" in ai and ai["model"]:
        cfg.ai.model = str(ai["model"])
    if ai.get("effort"):
        cfg.ai.effort = _valid_effort(ai["effort"])
    if ai.get("max_tokens"):
        cfg.ai.max_tokens = int(ai["max_tokens"])
    if ai.get("max_concurrency"):
        cfg.ai.max_concurrency = max(1, int(ai["max_concurrency"]))
    if "auto_route" in ai:
        cfg.ai.auto_route = bool(ai["auto_route"])
    if "tasks" in ai:
        for name, t in ai["tasks"].items():
            spec = TaskModel(
                provider=(_valid_provider(t["provider"]) if t.get("provider") else None),
                model=(t.get("model") or None),
                effort=(_valid_effort(t["effort"]) if t.get("effort") else None),
                max_tokens=(int(t["max_tokens"]) if t.get("max_tokens") else None),
            )
            if spec.provider or spec.model or spec.effort or spec.max_tokens:
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
        _set_bool(cfg.enrichment, en, key)

    threat_model = update.get("threat_model", {})
    if "enabled" in threat_model:
        cfg.threat_model.enabled = bool(threat_model["enabled"])

    oh = update.get("openhack", {})
    _set_bool(cfg.openhack, oh, "enabled")
    _set_str(cfg.openhack, oh, "findings_dir")
    _set_str(cfg.openhack, oh, "repo")
    _set_bool(cfg.openhack, oh, "auto")
    if "command" in oh:
        cmd = oh["command"]
        cfg.openhack.command = cmd if isinstance(cmd, list) else shlex.split(cmd or "")
    _set_str(cfg.openhack, oh, "workspace")
    if cfg.openhack.workspace == "":
        cfg.openhack.workspace = ".openhack"
    _set_bool(cfg.openhack, oh, "clone")
    # Built-in engine tuning.
    if oh.get("passes"):
        cfg.openhack.passes = max(1, int(oh["passes"]))
    if oh.get("max_files"):
        cfg.openhack.max_files = max(1, int(oh["max_files"]))
    if oh.get("max_file_bytes"):
        cfg.openhack.max_file_bytes = max(1, int(oh["max_file_bytes"]))
    if oh.get("min_confidence"):
        conf = str(oh["min_confidence"]).lower()
        if conf not in ("low", "medium", "high"):
            raise ValueError("openhack.min_confidence must be low, medium, or high")
        cfg.openhack.min_confidence = conf

    src = update.get("source", {})
    if "provider" in src:
        provider = str(src["provider"]).lower()
        if provider not in SCM_PROVIDERS:
            raise ValueError(f"source.provider must be one of {SCM_PROVIDERS}")
        cfg.source.provider = provider
    if "github_repos" in src:
        cfg.github.repos = [str(r).strip() for r in src["github_repos"] if str(r).strip()]
    if "github_orgs" in src:
        cfg.github.orgs = [str(o).strip() for o in src["github_orgs"] if str(o).strip()]

    sn = update.get("servicenow", {})
    _set_bool(cfg.servicenow, sn, "push")
    if "format" in sn:
        fmt = str(sn["format"]).lower()
        if fmt not in ("json", "csv"):
            raise ValueError("servicenow.format must be 'json' or 'csv'")
        cfg.servicenow.format = fmt


def _valid_effort(v: str) -> str:
    if v not in EFFORTS:
        raise ValueError(f"invalid effort: {v}")
    return v


def _valid_provider(v: str) -> str:
    if v not in PROVIDERS:
        raise ValueError(f"invalid AI provider: {v} (known: {PROVIDERS})")
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
            "threat_ids": ex.threat_ids,
            "threat_signal": ex.threat_signal,
        },
    }


class ScanRequest(BaseModel):
    use_ai: bool | None = None
    offline: bool | None = None
    live: bool | None = None       # scan live systems vs the configured fixtures


class StateChange(BaseModel):
    state: str


class AppState:
    """Holds config + the latest pipeline result for the API."""

    def __init__(self, config_path, fixtures, live, use_ai, offline, out_path, state_path, overrides_path):
        self.cfg = Config.load(config_path)
        self.fixtures = fixtures or "fixtures"   # always a path, for toggling live off
        self.live = live
        self.use_ai = use_ai
        self.offline = offline
        self.out_path = out_path
        self.state_path = state_path
        self.last_scan: str | None = None
        self.overrides_path = Path(overrides_path) if overrides_path else None
        # Layer any UI-saved overrides on top of the base config.
        if self.overrides_path and self.overrides_path.exists():
            apply_config(self.cfg, json.loads(self.overrides_path.read_text(encoding="utf-8")))
        self.result: PipelineResult = PipelineResult()
        self.startup_error: str | None = None
        # Avoid failing server startup if the initial scan fails (e.g. live mode
        # with missing credentials). Boot empty; the operator can fix config and
        # retry from the UI.
        try:
            self.scan()
        except Exception as exc:  # noqa: BLE001 - surface, don't fail startup
            self.startup_error = str(exc)

    def update_config(self, update: dict) -> dict:
        apply_config(self.cfg, update)                  # validate + apply (raises on bad)
        if self.overrides_path:
            merged = {}
            if self.overrides_path.exists():
                merged = json.loads(self.overrides_path.read_text(encoding="utf-8"))
            _deep_merge(merged, update)
            self.overrides_path.write_text(json.dumps(merged, indent=2), encoding="utf-8")
        return sanitized_config(self.cfg)

    def scan(self, use_ai=None, offline=None, live=None) -> PipelineResult:
        ai = self.use_ai if use_ai is None else use_ai
        off = self.offline if offline is None else offline
        lv = self.live if live is None else live
        fx = None if lv else self.fixtures       # None -> live ingest
        self.result = Pipeline(self.cfg, offline=off, use_ai=ai).run(
            fixtures=fx, out_path=self.out_path, state_path=self.state_path
        )
        # Remember what was actually run, so the UI reflects it.
        self.use_ai, self.offline, self.live = ai, off, lv
        self.startup_error = None
        self.last_scan = datetime.now(timezone.utc).isoformat(timespec="seconds")
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
        "mode": {
            "use_ai": state.use_ai, "offline": state.offline, "live": state.live,
            "source": state.cfg.source.provider,
        },
        "last_scan": state.last_scan,
        "startup_error": state.startup_error,
    }


def create_app(
    config_path: str = "config/config.example.yaml",
    fixtures: str | None = None,
    *,
    live: bool = False,
    use_ai: bool = False,
    offline: bool = False,
    out_path: str = "servicenow_import.json",
    state_path: str = "validation_state.json",
    overrides_path: str = "config.overrides.json",
) -> FastAPI:
    state = AppState(config_path, fixtures, live, use_ai, offline, out_path, state_path, overrides_path)
    app = FastAPI(title="codescan", version="0.1.0")

    @app.get("/", response_class=HTMLResponse)
    def index() -> str:
        return (STATIC / "index.html").read_text(encoding="utf-8")

    @app.get("/healthz")
    def healthz() -> dict:
        # Liveness/readiness probe — no scan performed.
        return {"status": "ok"}

    @app.get("/api/state")
    def get_state() -> dict:
        return _payload(state)

    @app.post("/api/scan")
    def scan(req: ScanRequest) -> dict:
        # Surface scan failures (e.g. live mode, invalid credentials) as an
        # error banner rather than a 500 response — the previous result stays
        # visible.
        try:
            state.scan(req.use_ai, req.offline, req.live)
        except Exception as exc:  # noqa: BLE001
            state.startup_error = str(exc)
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

    @app.get("/api/export")
    def export_file(format: str = "json") -> Response:
        """Download the ServiceNow import as a JSON or CSV attachment."""
        items = state.servicenow_items()
        if format.lower() == "csv":
            return Response(
                content=items_to_csv(items), media_type="text/csv",
                headers={"Content-Disposition": "attachment; filename=servicenow_import.csv"},
            )
        return Response(
            content=json.dumps({"records": items}, indent=2), media_type="application/json",
            headers={"Content-Disposition": "attachment; filename=servicenow_import.json"},
        )

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
