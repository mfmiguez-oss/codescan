# Working on codescan

Conventions for contributors (human or AI) working in this repo. For
architecture and rationale see [docs/DESIGN.md](docs/DESIGN.md); for the full
change/release procedure see [docs/RELEASING.md](docs/RELEASING.md).

## What this is

codescan is a vulnerability-triage **pipeline**: it ingests findings from Snyk +
Xray (and a built-in OpenHack whitebox engine) over a Bitbucket/GitHub repo
inventory → dedup → enrich (KEV/EPSS/reachability) → AI exploitability + attack
chains → composite score → validation states → ServiceNow export, with an
analyst web UI. It is an **LLM application over hosted models** (Anthropic /
OpenAI / Mistral model deployments, all served through Microsoft
Foundry) — not a trained model.

## The gate — run before every commit

All three must pass clean:

```bash
ruff check src tests
mypy                     # clean gate; the package ships py.typed
pytest -q                # offline, deterministic, no network, no API key
```

Add tests for every feature. Tests must keep running offline (the AI stages are
validated by contract/schema with fake clients, never live calls). The one
exception is opt-in and outside the gate: `CODESCAN_LIVE_TEST=1 pytest
tests/test_cli_live.py` runs the real CLI against the Foundry resource in
`.env` (skips otherwise).

## Change workflow

One change per branch → gate → **fast-forward merge** → push:

```bash
git checkout -b feat/short-name      # or fix/, docs/, chore/
# …edit, add tests, run the gate…
git commit                            # end the message with the Co-Authored-By trailer
git checkout main && git merge --ff-only feat/short-name
git branch -d feat/short-name && git push origin main
```

History stays linear; every commit on `main` passed the full gate.

## Keep docs in lockstep with code

A behavior change updates, in the **same commit**:

- `README.md` and `docs/DESIGN.md` — mirror edits into the docs so text and
  diagrams stay in sync.
- `config/config.example.yaml` for any new setting, and the web **Config tab**
  (`src/codescan/static/index.html`) for any new toggle.
- Diagram changes: edit `docs/architecture.svg` **and** `docs/make_diagram.py`
  in sync, then regenerate the PNG (`python docs/make_diagram.py`; needs the
  `docs` extra / matplotlib).

Security-relevant work also updates `docs/THREATMODEL.md`, `docs/GOVERNANCE.md`,
and `docs/SECURITY_FRAMEWORKS.md` as applicable.

## Never commit runtime artifacts

All gitignored — clean any strays before committing: `audit.jsonl`, `state.db`,
`servicenow_import.json`, `validation_state.json`, `threat_models.json`,
`threat_models.md`, `config.overrides.json`, `.env`. Secrets live in the
environment or Vault only.

## Running it

```bash
codescan serve                                   # offline demo UI (no creds) — http://127.0.0.1:8000
codescan scan --fixtures fixtures --no-ai --offline   # offline CLI demo
codescan scan --repo owner/name --whitebox       # whitebox source review (needs FOUNDRY_API_KEY + git)
```

For UI changes (`static/index.html`), verify in a browser against the running
dev server. The preview dev server needs the venv interpreter: point
`.claude/launch.json`'s `runtimeExecutable` at `.venv/Scripts/python.exe`
temporarily, then revert it to `"python"` before committing (don't commit the
machine path).

## LLM / provider code

codescan accesses all models through Microsoft Foundry via `providers/` +
`llm.py`. When touching model routing, the provider, model IDs, or
prompt/token behavior, consult the
`claude-api` reference — default to the latest Claude models. Model output is
always schema-constrained and treated as **data, never instructions** (see
`exploitability._apply` and `docs/THREATMODEL.md`).
