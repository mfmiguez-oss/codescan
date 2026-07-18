"""Live CLI smoke test — OPT-IN, makes real Microsoft Foundry calls.

The standard gate (plain ``pytest``) skips this module: it must stay offline.
Run it explicitly when you want to prove the CLI works end-to-end against the
configured Foundry resource:

    CODESCAN_LIVE_TEST=1 pytest tests/test_cli_live.py -s        # bash
    $env:CODESCAN_LIVE_TEST="1"; pytest tests/test_cli_live.py   # PowerShell

It loads credentials from ``.env`` (repo root), asks the resource which Claude
deployment it actually serves, routes every AI task to that deployment at a
modest tier, and runs the real ``codescan scan`` CLI over the bundled fixtures:
ingest → dedup → AI exploitability/chaining → threat models → scoring →
ServiceNow export. Expect a handful of model calls (a few cents) and one to a
few minutes of runtime.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[1]

pytestmark = pytest.mark.skipif(
    os.getenv("CODESCAN_LIVE_TEST") != "1",
    reason="live Foundry smoke test — set CODESCAN_LIVE_TEST=1 to run",
)


def _load_dotenv(env: dict[str, str]) -> None:
    """Merge .env into `env` (existing keys win). Strips quotes + inline comments."""
    path = ROOT / ".env"
    if not path.exists():
        pytest.skip(".env not found — it must hold the Foundry credentials")
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, val = line.partition("=")
        val = val.split(" #", 1)[0].split("\t#", 1)[0].strip().strip('"').strip("'")
        if val:
            env.setdefault(key.strip(), val)


def _pick_claude_deployment() -> str:
    """A Claude deployment that actually exists on the resource, best tier first."""
    from codescan.providers.foundry_provider import FoundryProvider

    deployments = FoundryProvider().list_deployments()
    for prefix in ("claude-opus", "claude-sonnet", "claude"):
        for name in deployments:
            if name.startswith(prefix):
                return name
    pytest.skip(f"no claude-* deployment on the Foundry resource (found: {deployments})")


def test_cli_scan_end_to_end_on_foundry(tmp_path):
    env = os.environ.copy()
    _load_dotenv(env)
    for key, val in env.items():           # the deployment picker runs in-process
        os.environ.setdefault(key, val)
    model = _pick_claude_deployment()

    # Route every AI task to the picked deployment at a modest tier — this test
    # proves the wiring, not maximum reasoning depth.
    cfg = yaml.safe_load((ROOT / "config" / "config.example.yaml").read_text(encoding="utf-8"))
    cfg["ai"]["model"] = model
    cfg["ai"]["effort"] = "low"
    cfg["ai"]["max_tokens"] = 8000
    cfg["ai"]["tasks"] = {
        task: {"model": model}
        for task in ("dedup", "enrichment", "exploitability", "threat_model")
    }
    cfg_path = tmp_path / "live.yaml"
    cfg_path.write_text(yaml.safe_dump(cfg), encoding="utf-8")

    out = tmp_path / "sn.json"
    state = tmp_path / "state.json"
    proc = subprocess.run(
        [sys.executable, "-m", "codescan.cli", "scan",
         "--config", str(cfg_path), "--fixtures", str(ROOT / "fixtures"),
         "--offline",                       # KEV/EPSS skipped; AI stages live
         "--out", str(out), "--state", str(state)],
        capture_output=True, text=True, env=env, cwd=str(ROOT), timeout=600,
    )

    assert proc.returncode == 0, (proc.stderr or proc.stdout)[-2000:]
    assert "findings" in proc.stdout and "ServiceNow import written" in proc.stdout

    records = json.loads(out.read_text(encoding="utf-8"))["records"]
    assert records, "scan produced no ServiceNow records"
    for record in records:
        assert isinstance(record["risk_score"], (int, float))
        assert record["short_description"]
    # The AI stages actually ran: at least one record carries model reasoning.
    assert any("exploitability" in json.dumps(r).lower() for r in records), \
        "no exploitability output found — did the AI stages run?"
    print(f"\nlive CLI smoke OK: model={model}, {len(records)} records, "
          f"state store at {state}")
