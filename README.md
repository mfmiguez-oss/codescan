# codescan

An enterprise code-scanning pipeline that ingests vulnerability findings from
**Snyk** and **JFrog Xray** across repositories in a **local Bitbucket**
(Data Center/Server) install, deduplicates them, uses **Claude** to assess
real-world exploitability and discover **multi-step attack chains**, scores
every finding, tracks **validation states**, and emits records ready for import
into **ServiceNow Vulnerability Response**.

```
Bitbucket (repo inventory)
        │
   Snyk + Xray  ──►  normalize ──►  deduplicate ──►  enrich (KEV/EPSS/reachability)
                                                            │
                                        AI exploitability & vulnerability chaining (Claude)
                                                            │
                                        composite risk scoring ──► validation states
                                                            │
                                        ServiceNow Vulnerable Item export
```

For architecture, design decisions, and rationale, see **[docs/DESIGN.md](docs/DESIGN.md)**
(or the Word edition [docs/DESIGN.docx](docs/DESIGN.docx)). The architecture
diagram is in [docs/architecture.svg](docs/architecture.svg) /
[`.png`](docs/architecture.png) — regenerate the graphic with
`python docs/make_diagram.py` and the Word doc with `node docs/build_docx.mjs`.

## How it maps to the requirements

| Requirement | Where it lives |
|---|---|
| Code in a local Bitbucket install | `connectors/bitbucket.py` — on-prem REST API builds the repo inventory (the scan surface). |
| Snyk + Xray available | `connectors/snyk.py`, `connectors/xray.py` — live API pull **or** offline export files, both normalized to one `Finding` model. |
| Output ready for ServiceNow Vulnerabilities | `servicenow.py` — `sn_vul_vulnerable_item` records with risk score, state, and reasoning; idempotent via `correlation_id`. |
| Validation states | `validation.py` + `models.py` — internal lifecycle (`new → under_investigation → confirmed / false_positive / risk_accepted / duplicate / resolved`) mapped to ServiceNow VR states, with a sticky **state store** so re-scans never re-open closed items. |
| Deduplication | `dedup.py` — cross-scanner merge on a `(vuln id, component, repo)` fingerprint; keeps provenance from every scanner. |
| Exploitability, incl. chaining, scored accordingly | `exploitability.py` (Claude) + `scoring.py` — per-finding exploitability and explicit attack chains feed a weighted composite score. |

## Exploitability & chaining

Enrichment is a **pluggable framework** (`enrich/`) — each source is a
`BaseEnricher`, toggleable in config and from the UI. Adding a source (VEX, asset
criticality, exploit-DB) is a new subclass. Built-in enrichers:

- **CISA KEV** — is the CVE in the Known Exploited Vulnerabilities catalog?
- **FIRST EPSS** — probability of exploitation in the wild.
- **Reachability** — is the vulnerable code path actually reachable?
- **AI enrichment** (optional, cheap tier) — remediation guidance + tags per
  finding; complements the exploitability engine rather than duplicating it.

The deterministic signals above answer *how dangerous is this CVE in general* and
ground the LLM stages.

Claude answers the judgement-heavy questions those signals can't:

- Is this exploitable **in our context**, or a theoretical CVE in dead code?
- Can several individually-lower findings be **chained** into a real attack path
  (e.g. an SSRF that reaches an internal service carrying an unauthenticated
  RCE)? Each chain gets a narrative, preconditions, MITRE ATT&CK mapping, a
  likelihood, and a chain score.

The model receives the deterministic signals as grounded facts, so it reasons
about *your* exposure rather than recalling CVE trivia. Chaining is scoped per
service/repo, which keeps each request tractable at enterprise scale and keeps
chains meaningful (components that actually talk to each other).

The engine defaults to **Claude Opus 4.8** (`config/config.example.yaml → ai.model`).
Set it to `claude-fable-5` for the hardest chaining analysis — the engine then
automatically enables server-side refusal fallbacks, because security tooling
can trip Fable's false-positive classifier refusals.

## Model routing by task

Not every AI task needs the same intelligence tier, and paying Opus rates for
mechanical work is wasteful. `llm.py` routes each task to a model:

| Task | Default tier | Why |
|---|---|---|
| `dedup` (semantic near-duplicate detection) | **Haiku 4.5** | Mechanical "are these the same vuln?" judgement — cheap and fast. |
| `exploitability` (per-finding + attack chains) | **Opus 4.8** | Deep, judgement-heavy reasoning. Bump to `claude-fable-5` for the hardest chaining. |

The default tier (`ai.model`) covers any task without a specific route. Override
per task in config — unset fields inherit:

```yaml
ai:
  model: claude-opus-4-8        # default tier
  effort: high
  tasks:
    dedup:
      model: claude-haiku-4-5
    exploitability:
      model: claude-opus-4-8    # or claude-fable-5
      effort: xhigh
```

The client adapts each request to the model's capabilities automatically —
Haiku doesn't take `effort` or adaptive thinking, Fable gets refusal fallbacks —
so callers just name a task and get the right model. Adding a new AI stage is a
one-liner: give it a task name and (optionally) a built-in tier.

Two dedup passes now run: the free deterministic fingerprint merge, then an
optional Haiku-backed **semantic** pass that catches cross-scanner duplicates
whose identifiers differ (same weakness, one has a CVE and the other only a CWE).
It's conservative — same repo + same component, and only merges what the model
is confident about.

## Threat modeling

Optional per-service **STRIDE threat model** (`threatmodel.py`, deep tier). Where
exploitability works bottom-up (per-finding scores, chains), threat modeling is
top-down: for each service it names the **assets**, **entry points / trust
boundaries**, and **STRIDE threats** the findings and chains actually enable —
each threat linked to its findings/chains, with likelihood, impact, and
mitigations — plus an overall posture and recommendations. Enable it in config
(`threat_model.enabled`) or the Config tab; it writes `threat_models.json` and
powers the Threats tab. Route it via the `threat_model` task (default deep tier;
`claude-fable-5` for the deepest analysis).

## Composite scoring

`scoring.py` blends four weighted dimensions into a 0–100 risk score (weights in
config):

| Dimension | Signal |
|---|---|
| severity | CVSS-derived base impact |
| exploitability | AI judgement, EPSS, KEV, **threat signal** |
| exposure | network reachability of the vulnerable path |
| chaining | membership in a scored attack chain |

Anything in the KEV catalog is floored to `kev_floor` — *actively exploited*
outweighs modelling. Multi-scanner agreement adds a small confidence bump. And
when threat modeling is on, findings implicated by a service's threats get an
additive **threat boost** (up to `threat_boost`, default 15) and their
exploitability is enriched — threat models feed the score, they don't just
report (see [Threat modeling](#threat-modeling)).

## Install

```bash
pip install -e .          # or: pip install -r requirements (see pyproject)
cp .env.example .env      # fill in tokens
```

## Web UI

An analyst triage dashboard ships with the tool:

```bash
codescan serve                 # http://127.0.0.1:8000 — offline demo, no key needed
codescan serve --ai            # enable AI exploitability/chaining (needs ANTHROPIC_API_KEY)
codescan serve --live          # scan Bitbucket/Snyk/Xray instead of fixtures
```

The dashboard shows the ServiceNow VR queue (findings ranked by composite risk),
with filters (search, severity, state, repo, min risk), signal badges (KEV,
attack-chain membership, EPSS, reporting scanners), and a **Run scan** button.
Click a finding for the detail drawer: CVSS vector, EPSS, reachability,
cross-scanner provenance, fix versions, the AI exploitability rationale, and any
attack chains it belongs to (narrative, preconditions, impact, MITRE ATT&CK).

Analysts **change the validation state inline** (confirm, mark false positive,
accept risk, …). Those decisions persist to the state store and are sticky — a
re-scan never overturns an analyst's call.

A **Threats** tab shows the per-service **STRIDE threat models** (see below):
threats linked to their findings and chains, assets, entry points, trust
boundaries, posture, and recommendations.

A **Config** tab manages non-secret settings live: the default AI tier, per-task
model routing, enrichment toggles, the threat-modeling toggle, scoring weights,
and the ServiceNow push flag. Secrets stay in the environment (shown masked,
read-only). Edits apply to the next scan and persist to `config.overrides.json`.

Backend is FastAPI (`web.py`); the frontend is a single dependency-free HTML page
(`static/index.html`) that talks to the same pipeline.

## Run (CLI)

**Offline demo** (no credentials, no network — uses the sample exports in
`fixtures/`, deterministic scoring only):

```bash
codescan scan --fixtures fixtures --no-ai --offline
```

**Full pipeline** with AI exploitability/chaining (needs `ANTHROPIC_API_KEY`):

```bash
codescan scan --fixtures fixtures            # AI on, KEV/EPSS enrichment on
```

**Live** against Bitbucket + Snyk + Xray, pushing to ServiceNow — set the env
vars in `.env`, set `servicenow.push: true` in the config, then:

```bash
codescan scan --config config/config.example.yaml
```

Flags: `--no-ai` (deterministic only), `--offline` (skip KEV/EPSS network calls),
`--out` (ServiceNow import path), `--state` (validation-state store path),
`--sn-format json|csv` (write a CSV for ServiceNow CSV Import Sets instead of
JSON — also settable in config/UI).

Inspect a produced import file:

```bash
codescan summary --out servicenow_import.json
```

## Layout

```
src/codescan/
  config.py            config loading with ${ENV} interpolation
  models.py            canonical Finding model + fingerprint + VR state map
  connectors/          bitbucket / snyk / xray
  llm.py               model router (task -> tier) + shared structured client
  dedup.py             deterministic cross-scanner merge
  dedup_ai.py          semantic near-duplicate merge (cheap tier / Haiku)
  enrich/              KEV, EPSS, reachability
  exploitability.py    Claude exploitability + chaining engine (deep tier)
  threatmodel.py       per-service STRIDE threat modeling (deep tier)
  scoring.py           composite risk score
  validation.py        validation-state machine + sticky state store
  servicenow.py        Vulnerable Item export (file or Table API push)
  web.py               FastAPI backend for the UI
  static/index.html    analyst triage dashboard (single-page, no build)
  pipeline.py          orchestration
  cli.py               `codescan` CLI (scan / serve / summary)
fixtures/              sample Snyk/Xray exports for the offline demo
tests/                 offline pipeline tests (no network / key needed)
```

## Tests

```bash
pytest
```

The suite runs the deterministic pipeline over the fixtures and asserts the
load-bearing behaviors: cross-scanner dedup, corroboration, reachability-driven
scoring, validation states, ServiceNow record shape, and sticky closures.

## Production notes

- **Repo mapping.** Snyk projects and Xray builds are mapped back to Bitbucket
  repos by name (`pipeline._ingest_live`). Wire this to your actual naming
  convention (project tags, build metadata) before trusting live runs.
- **Reachability.** The built-in reachability signal is a heuristic over scanner
  metadata. Feed Snyk's reachable-vuln data or your own call-graph analysis into
  `Exploitability.reachable` for higher fidelity.
- **ServiceNow.** Export targets the `sn_vul_vulnerable_item` import; adjust
  field names to match your VR integration/transform map. `correlation_id`
  (the finding fingerprint) makes imports idempotent.
- **Human in the loop.** The pipeline *proposes* validation states; analysts
  confirm/override in ServiceNow. Closed states (false positive, risk accepted,
  resolved) are sticky and survive re-scans.
