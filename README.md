# codescan

[![CI](https://github.com/mfmiguez-oss/codescan/actions/workflows/ci.yml/badge.svg)](https://github.com/mfmiguez-oss/codescan/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

An enterprise vulnerability-triage pipeline. It ingests findings from **Snyk**
and **JFrog Xray**, **SARIF** exports from any scanner (CodeQL, Semgrep, Trivy,
…), **CycloneDX/SPDX SBOMs** (embedded VEX + OSV.dev matching), **GitHub
Dependabot and secret-scanning alerts**, and its own built-in **whitebox
source-review engine** — across a **Bitbucket** (Data Center/Server) or
**GitHub/GHES** repo inventory. Findings are deduplicated and corroborated
across sources, enriched with KEV/EPSS/reachability, and assessed by AI models
on **Microsoft Foundry** (Claude / GPT / Mistral) for real-world
exploitability, **multi-step attack chains**, and per-service **STRIDE threat
models**. Every finding gets a composite risk score calibrated by the org's own
analyst decisions, a tracked **validation state**, and a record ready for
import into **ServiceNow Vulnerability Response** — all drivable from an
analyst web UI with an append-only, SIEM-shippable audit trail.

```
Bitbucket/GitHub (repo inventory)
        │
   Snyk + Xray + SARIF + SBOM/OSV
   + GitHub alerts + whitebox  ──►  normalize ──►  deduplicate ──►  enrich (KEV/EPSS/reachability)
                                                            │
                                        AI exploitability & vulnerability chaining (AI Model)
                                                            │
                                        composite risk scoring ──► validation states
                                                            │
                                        ServiceNow Vulnerable Item export
```

**At a glance:**

- **Six findings sources, one model.** Snyk, Xray, SARIF (any scanner), SBOM
  (CycloneDX/SPDX + OSV.dev), GitHub Dependabot / secret-scanning alerts, and
  the built-in OpenHack whitebox engine — all normalized to one `Finding`,
  deduplicated cross-scanner, with agreement surfaced as corroboration.
- **Whitebox review with cross-model agreement.** The in-process engine reviews
  first-party source over multiple passes routed to *different model families*;
  a finding confirmed by ≥2 models is tagged `multi-model`.
- **AI judgement, bounded and audited.** Exploitability + attack chains
  (batched for resilience), STRIDE threat models with attack-surface diagrams,
  semantic dedup, and remediation enrichment — every model call
  schema-constrained, clamped, and treated as data, never instructions.
  Deployment preflight pins model routing to what the Foundry resource actually
  serves (substitutions audited) instead of 404ing mid-scan.
- **A learning loop.** Analyst confirm/false-positive decisions feed the AI's
  prompts, nudge future scores (evidence-weighted, time-decayed), and are
  continuously graded — calibration drift raises audit events to the SIEM.
- **Operable.** Web UI for triage/config/scans, CSV/JSON ServiceNow import (or
  direct push), file/SQL state store, Vault secrets, rate limiting, Docker, and
  an offline fixtures mode that runs the whole pipeline with zero credentials.

For architecture, design decisions, and rationale, see **[docs/DESIGN.md](docs/DESIGN.md)**.
The architecture diagram is in [docs/architecture.svg](docs/architecture.svg) /
[`.png`](docs/architecture.png) — regenerate the graphic with
`python docs/make_diagram.py`.

Governance, security, and audit documentation:
**[docs/DATAFLOW.md](docs/DATAFLOW.md)** (formal context/logical/physical DFDs
with trust boundaries), **[docs/THREATMODEL.md](docs/THREATMODEL.md)**
(MITRE ATLAS-aligned adversarial threat model),
**[docs/SECURITY_FRAMEWORKS.md](docs/SECURITY_FRAMEWORKS.md)** (review against
NIST AI RMF, CSA AICM, ATLAS, OWASP LLM Top-10, IBM GenAI Controls, Google
SAIF), **[docs/GOVERNANCE.md](docs/GOVERNANCE.md)** (AI-governance controls
mapped to evidence), and **[docs/RELEASING.md](docs/RELEASING.md)** (change and
release procedure).

## How it maps to the requirements

| Requirement | Where it lives |
|---|---|
| Code in a local repository install | **Bitbucket** `connectors/bitbucket.py` — on-prem REST API builds the repo inventory (the scan surface). **GitHub/GHES** (`connectors/github.py`) is a selectable alternative via `source.provider`. |
| Snyk + Xray available | `connectors/snyk.py`, `connectors/xray.py` — live API pull **or** offline export files, both normalized to one `Finding` model. Hadrian **OpenHack** (`connectors/openhack.py`) is a third, whitebox source-review findings source. **SARIF** (`connectors/sarif.py`) ingests exports from any SARIF-emitting scanner (CodeQL, Semgrep, Trivy, Checkov, Gitleaks, …), **SBOMs** (`connectors/sbom.py`) ingest CycloneDX/SPDX with embedded VEX plus OSV.dev matching, and **GitHub Dependabot / secret-scanning alerts** (`connectors/github_alerts.py`, opt-in) ride the GitHub token and inventory. |
| Output ready for ServiceNow Vulnerabilities | `servicenow.py` — `sn_vul_vulnerable_item` records with risk score, state, and reasoning, plus fielded detail (severity, exploitability, reporting sources, remediation, file/line, tags) so VR filters and reports can use the signals directly; idempotent via `correlation_id`. |
| Validation states | `validation.py` + `models.py` — internal lifecycle (`new → under_investigation → confirmed / false_positive / risk_accepted / duplicate / resolved`) mapped to ServiceNow VR states, with a persistent **state store** so rescans never re-open closed items. |
| Deduplication | `dedup.py` — cross-scanner merge on a `(vuln id, component, repo)` fingerprint; keeps provenance from every scanner. |
| Exploitability, incl. chaining, scored accordingly | `exploitability.py` (Claude) + `scoring.py` — per-finding exploitability and explicit attack chains feed a weighted composite score. |

## Exploitability & chaining

Enrichment is a **pluggable framework** (`enrich/`) — each source is a
`BaseEnricher`, toggleable in config and from the UI. Adding a source (VEX, asset
criticality, exploit-DB) is a new subclass. Built-in enrichers:

- **CISA KEV** — is the CVE in the Known Exploited Vulnerabilities catalog?
- **FIRST EPSS** — probability of exploitation in the wild.
- **Reachability** — is the vulnerable code path actually reachable?
- **AI enrichment** (optional, lower-cost tier) — remediation guidance + tags per
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
automatically enables client-side refusal fallbacks, because security tooling
can trip Fable's false-positive classifier refusals.

## AI models via Microsoft Foundry

Every AI stage goes through the **Foundry provider** (`providers/`): all models
are served by one **Azure AI Foundry** resource, and the model name decides
which of the resource's two API surfaces a request uses — `claude-*`
deployments get Anthropic's **native Messages API** (structured outputs,
adaptive thinking, effort, client-side Fable refusal fallbacks), while any
other deployment (**OpenAI GPT, Mistral**, …) goes through the
resource's **OpenAI-compatible** endpoint with JSON mode + defensive parsing.
Both SDKs are optional (`pip install -e ".[providers]"`) and imported lazily.

Pick a model per task in config (or the Config tab) — the model is the
deployment name on your Foundry resource. The Config tab's model suggestions
are the **live deployment list from the resource itself** (cached for five
minutes; a curated static list when the resource isn't reachable):

```yaml
ai:
  provider: foundry            # the only provider
  model: claude-opus-4-8       # default tier
  tasks:
    dedup:          { model: claude-haiku-4-5 }    # lower-cost, mechanical
    exploitability: { model: gpt-5 }               # different model family
    enrichment:     { model: mistral-large-2411 }
```

Credentials come from the environment: `FOUNDRY_API_KEY` plus
`FOUNDRY_RESOURCE` (the resource name — required for claude-* models, and it
derives the OpenAI-compatible endpoint for the rest). `FOUNDRY_BASE_URL`
overrides the derived endpoint, and `FOUNDRY_API_VERSION` selects the classic
Azure OpenAI dialect; `AZURE_OPENAI_*` equivalents are honored. Adding a
supplier is a new `LLMProvider` subclass registered in
`providers/__init__.py`.

## Model routing by task

Not every AI task needs the same intelligence tier, and paying Opus rates for
mechanical work is wasteful. `llm.py` routes each task to a provider + model:

| Task | Default tier | Why |
|---|---|---|
| `dedup` (semantic near-duplicate detection) | **Haiku 4.5** | Mechanical "are these the same vulnerability?" judgement — cost-effective and fast. |
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
Haiku doesn't accept `effort` or adaptive thinking; Fable receives refusal
fallbacks — so callers just name a task and get the right model. Adding a new
AI stage is a one-liner: give it a task name and (optionally) a built-in tier.

Two dedup passes now run: the free deterministic fingerprint merge, then an
optional Haiku-backed **semantic** pass that catches cross-scanner duplicates
whose identifiers differ (same weakness, one has a CVE and the other only a CWE).
It's conservative — same repo + same component, and only merges what the model
is confident about.

## Efficiency & cost

The pipeline is I/O-bound on model API calls, and each judgement-heavy stage
(exploitability, threat modeling, AI enrichment, semantic dedup, OpenHack) issues
**one request per repo/service** — except exploitability, where a service with
more than `ai.exploitability_batch` findings (default 40) is **split into
batches**: a single oversized request would hold one streaming connection for
its entire generation (long enough for a provider to drop it) and lose the whole
stage on any failure, while batches run concurrently and confine a failure to
one slice. Chains form within a batch (same-file findings stay adjacent) and
batch chain ids are namespaced. Two levers keep large scans fast and affordable:

- **Concurrency (speed).** Those per-service requests are independent, so codescan
  runs up to `ai.max_concurrency` of them at once (default 4; also in the Config
  tab). Results are still applied in a deterministic order, so output is unchanged —
  only wall-clock time drops (≈N× on an N-repo scan, bounded by the setting). Set it
  to `1` for strictly sequential execution. It's a latency optimization: the same
  requests are made at the same cost.
- **Model routing (cost).** Pay Opus rates only where the reasoning needs it. Dedup
  and enrichment already default to **Haiku**. For cost-sensitive deployments, route
  the token-heavy stages to **Sonnet** (near-Opus quality on code at ~40% lower
  input/output cost) — the OpenHack source review and threat modeling are the usual
  candidates:

  ```yaml
  ai:
    tasks:
      openhack:     { model: claude-sonnet-5 }   # source review — token-heavy
      threat_model: { model: claude-sonnet-5 }
  ```

  These are opt-in; the default tier stays Opus 4.8. Both `openhack` and
  `threat_model` are routable tasks in the Config tab.
- **Auto-route (adaptive, silent).** Turn on `ai.auto_route` and codescan sizes the
  model to the work *per call*, with no per-task config: each AI request is nudged
  up or down the Claude ladder — **Haiku → Sonnet → Opus → Fable** — from its
  configured tier by a difficulty signal. A single low-severity finding downgrades
  (cheaper); an actively-exploited (KEV), multi-critical, or large group upgrades
  (stronger reasoning). It moves **relative to** your configured tier (so an
  `exploitability` baseline of Opus becomes Sonnet when trivial, Fable when hot),
  only shifts Claude models that sit on the ladder, and never touches a custom
  deployment name or another model family. Off by default — enabling it is the
  operator's explicit choice; once on it applies silently. Toggle in the Config tab.

  ```yaml
  ai:
    auto_route: true          # silent per-call downgrade/upgrade by difficulty
  ```

- **Deployment pinning (availability).** On by default (`ai.resolve_deployments`).
  At scan start codescan asks the Foundry resource which model deployments it
  actually serves and pins all routing to that list: a configured model that
  isn't deployed — the default tier, a task route, an auto-route ladder rung, or
  an OpenHack pass model — is substituted with its **nearest deployed family
  member** (e.g. `claude-opus-4-8` → a deployed `claude-opus-4-7`), logged and
  recorded as a `scan.model_remapped` audit event; a model with no deployed
  family member fails the scan up front with the deployment list in the error.
  Either way you find out at scan start, not as a 404 halfway through the AI
  stages. If the deployment list can't be fetched (no credentials, blocked
  endpoint), routing is left untouched. Toggle in the Config tab; set
  `resolve_deployments: false` to always send configured names as-is.

Prompt caching isn't used: the static system prompts are far below the model's
minimum cacheable-prefix size and each request's payload differs, so a cache
breakpoint would never hit — it's deliberately omitted rather than added as dead
weight.

## Enterprise deployment with Claude Fable 5

For security triage, model capability on the **judgement** tasks — exploitability,
attack chaining, threat modeling, whitebox review — converts directly into
outcomes: fewer false positives to work and fewer real, multi-step attacks missed.
So the enterprise profile routes those to **Claude Fable 5** (Anthropic's most
capable model) on the Foundry resource, keeps mechanical work (dedup, enrichment)
on cheap Haiku, and wires HA storage and SIEM audit. A ready profile ships at
[`config/config.enterprise.yaml`](config/config.enterprise.yaml):

```yaml
ai:
  tasks:
    dedup:          { model: claude-haiku-4-5 }              # mechanical -> cheap
    exploitability: { model: claude-fable-5, effort: xhigh } # deepest chaining
    threat_model:   { model: claude-fable-5, effort: xhigh }
    openhack:       { model: claude-fable-5, effort: xhigh } # deepest whitebox review
```

codescan already handles Fable's enterprise-specific behaviors:

- **Refusal classifiers.** Security content (exploit narratives, vuln descriptions)
  can trip Fable's false-positive refusal classifier — a real risk for a scanner.
  Foundry has no server-side fallback support, so the provider registers the
  Anthropic SDK's **client-side fallback to Opus 4.8** — a false-positive refusal
  is transparently re-served rather than failing.
- **Data retention & residency.** On Foundry these are governed by the platform
  and the **Azure region of the resource** — pick the region that satisfies your
  compliance requirements when creating it.
- **HA & audit.** The profile turns on the shared **SQL state store** and ships the
  **audit log to a SIEM** — see [Deployment & operations](#deployment--operations).

## Threat modeling

Per-service **STRIDE threat model** (`threatmodel.py`, deep tier). Where
exploitability works bottom-up (per-finding scores, chains), threat modeling is
top-down: for each service it names the **assets**, **entry points / trust
boundaries**, and **STRIDE threats** the findings and chains actually enable —
each threat linked to its findings/chains, with likelihood, impact, and
mitigations — plus an overall posture and recommendations. **On by default** when
the AI stages are enabled (`threat_model.enabled`; toggle in the Config tab, or
set false to skip the extra per-service call). It powers the Threats tab and
writes two artifacts next to the ServiceNow export: `threat_models.json` and a
human-readable **`threat_models.md`** — a Markdown report with a **Mermaid
attack-surface diagram per service** (external attacker → entry points → threats
crossing the trust boundary → assets, each threat a STRIDE-coloured node with its
likelihood). Mermaid renders on GitHub and most Markdown viewers, so you get the
diagram straight from a CLI run — no UI needed. Route it via the `threat_model`
task (default deep tier; `claude-fable-5` for the deepest analysis).

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
outweighs modelling. Multi-scanner agreement adds a small confidence bump. When
threat modeling is on, a threatened finding's **threat signal** enriches the
exploitability dimension above — so threat models feed the score (counted once,
not double-weighted) rather than just reporting (see
[Threat modeling](#threat-modeling)).

## Analyst feedback loop

The tool **learns from your triage**. Every confirm / false-positive decision is
persisted (`validation.py`), and on the next scan `feedback.py` turns that history
into a bounded, per-weakness/component **prior**: if analysts have repeatedly
dismissed a weakness family (CWE) or component as false positives, a new finding
sharing that trait is nudged **down**; a repeatedly-confirmed trait nudges **up**.
It closes the loop so the scanner adapts to *your* estate instead of scoring every
run identically.

It's deliberately conservative and **explainable**:

- **Bounded** — capped at `feedback.max_adjust` points (default 15) and requires
  `feedback.min_evidence` prior decisions, so a small number of decisions cannot
  move a score far.
- **Evidence-weighted** — decisions are weighted, not just counted: confidence
  grows with volume (`feedback.shrinkage` pseudo-count damping — two unanimous
  decisions move a score far less than twenty), old decisions lose weight over
  time (`feedback.half_life_days`, weight halves per half-life), and decisions
  made in the **same repo** as the new finding outweigh estate-wide precedent
  (`feedback.same_repo_boost`).
- **Transparent** — every adjusted finding gets a plain-language reason in its
  rationale ("score lowered 10 by analyst-feedback prior — 0 confirmed, 3
  false-positive on related weakness/component; recency- and repo-weighted"), a
  **`feedback-adjusted`** tag (a `feedback` badge in the queue), and a
  `feedback_adjusted` count in the scan's audit event.
- **Safe** — it only moves the *machine score*, never an analyst's validation
  state; a finding never counts toward adjusting itself; and an actively-exploited
  (KEV) finding is never pushed below `kev_floor`.
- **Self-activating** — a no-op until there's manual history; only `confirmed`
  (true positive) and `false_positive` decisions count (not `risk_accepted` /
  `resolved`, which are business/lifecycle outcomes, not accuracy signals).

On by default; toggle in the Config tab (`feedback.enabled`).

### Triage history in the AI prompt

The same history also feeds the model directly (`feedback.prompt_history`, on
by default): each finding sent to the exploitability engine carries
`prior_analyst_decisions` — how many similar findings (same CWE family or
component) this org's analysts confirmed vs dismissed, plus up to three of the
analysts' own recent notes explaining why. Where the score prior corrects the
output *after* the fact, this puts the ground truth *into* the reasoning: the
model can weigh the history where it transfers, explain in the rationale when
it influenced the judgement, and disregard it where the instance differs — and
it is instructed never to let history override grounded facts like KEV or
reachability.

When triaging (drawer → **Triage**), analysts can attach that optional
one-line note ("why") to a decision. It persists with the decision, appears in
the audit event, survives rescans and quick state changes, and is what turns
the history from bare counts into transferable reasoning for the model.

### Chain triage — judging the paths, not just the findings

Attack chains get the same treatment as findings: every chain card carries a
**confirm / dismiss** control. Decisions key on the chain's *finding-set
fingerprint* (model-assigned chain ids aren't stable across runs), so when a
rescan rediscovers the same path, the analyst's judgement re-applies. A
**dismissed** chain stays visible (dimmed, reversible) but stops counting: it
no longer boosts finding scores, feeds threat modeling, or reaches the
ServiceNow export. This closes the loop on the pipeline's most speculative
output — chaining — which previously had no feedback signal at all.

### Score calibration — measuring scoring accuracy

Every decision the store persists also freezes a **snapshot of what the machine
believed at that moment** (risk score, AI exploitability score, EPSS, KEV,
reachability, severity, repo — `validation.py`). Grading those predictions
against the analysts' outcomes answers the question no amount of modelling can:
*do our scores predict what analysts confirm?* The report (`calibration.py`)
shows:

- **Confirm rate by predicted-score bucket** (0–39 / 40–59 / 60–79 / 80–100) — a
  well-calibrated pipeline shows a rate that **rises with the bucket**; a flat or
  inverted curve means the scoring weights (or the AI stage) need attention.
- **Score separation** — mean predicted score of confirmed vs false-positive
  decisions; a bigger gap means the score carries real signal.
- **Noisiest weakness families / components** — the CWEs and packages analysts
  mostly dismiss: where triage time is going to false positives (and what the
  feedback prior is already adjusting down).

View it in the UI's **Calibration** tab (`GET /api/calibration`) or run
`codescan calibration`. It also makes model/provider changes measurable: change
`ai.model` (or a task route), let triage accumulate, and compare.

The report is also an **automated control**: every scan re-grades the
accumulated history and, when calibration degrades past the configured
thresholds (`calibration:` in config — high-bucket confirm rate, score
separation, each gated on a minimum evidence count), emits a
`calibration.drift` **audit event that fans out to the SIEM sinks**, logs a
warning, flags it in the Calibration tab, and prints it from the CLI. Drift
raises an alert instead of waiting to be noticed in a report.

## Install

```bash
pip install -e .          # or: pip install -r requirements (see pyproject)
cp .env.example .env      # fill in tokens
```

## Web UI

An analyst triage dashboard ships with the tool:

```bash
codescan serve                 # http://127.0.0.1:8000 — offline demo, no key needed
codescan serve --ai            # enable AI exploitability/chaining (needs FOUNDRY_API_KEY)
codescan serve --live          # scan the configured live sources instead of fixtures
```

The UI is a complete usage surface — no CLI needed. It opens on an **Overview**
landing page: run status (source, mode, last run), key metrics, a severity
breakdown, quick actions, an in-app usage guide, and **Download JSON / CSV**
buttons for the ServiceNow import (`GET /api/export`). The other tabs:

The **Findings** dashboard shows the ServiceNow VR queue (findings ranked by
composite risk), with filters (search, severity, state, repo, min risk) and
signal badges (KEV, attack-chain membership, EPSS, reporting scanners).
**Run scans from the UI**
with the header's **Run scan** button and the **AI / offline / live** toggles —
including on-demand **live** scans of every configured source. To scan specific
**GitHub repositories**, list them in the header field (`owner/name`,
comma-separated) — optionally with the **whitebox** toggle to also review their
source with the built-in OpenHack engine (needs AI) — and run: the targeting is
one-shot (the UI equivalent of `codescan scan --repo … --whitebox`) and doesn't
change the configured repo source. A "last run" chip
shows when it last ran; a failed run (e.g. live mode without credentials) keeps
the previous results and surfaces the error in a banner instead of crashing.
Click a finding for the detail drawer: CVSS vector, EPSS, reachability,
cross-scanner provenance, fix versions, the AI exploitability rationale, and any
attack chains it belongs to (narrative, preconditions, impact, MITRE ATT&CK).

Analysts **change the validation state inline** (confirm, mark false positive,
accept risk, …) — quick changes from the queue, or from the drawer's **Triage**
section, which also takes an optional one-line note explaining the decision
(persisted, audited, and shown to the AI on similar findings). A rescan never
overturns an analyst's call.

A **Threats** tab shows the per-service **STRIDE threat models** (see below).
Each opens with an **attack-surface diagram** — a dependency-free inline SVG:
the external attacker flows through the entry points, threats cross the trust
boundary as STRIDE-colored connectors (hue = category, thickness = likelihood,
hover for the threat), and land on the assets inside — above the full threat
list linked to its findings and chains, plus assets, entry points, trust
boundaries, posture, and recommendations.

A **Calibration** tab grades past risk scores against analysts' manual
confirm / false-positive decisions: confirm rate by predicted-score bucket,
score separation, and the noisiest weakness families (see
[Score calibration](#score-calibration--measuring-scoring-accuracy)).

A **Config** tab manages non-secret settings live: the **repo source**
(Bitbucket/GitHub) and **GitHub repo/org targets**, the GitHub
**Dependabot / secret-scanning alert** toggles, **SARIF** and **SBOM**
ingestion paths, the default AI tier, per-task model routing, auto-route,
deployment pinning, the exploitability batch size, the full **OpenHack**
whitebox settings (passes, per-pass models, confidence gate), enrichment
toggles, the threat-modeling toggle, feedback/calibration toggles, scoring
weights, and the ServiceNow push flag/format. Secrets stay in the environment
(shown masked, read-only). Edits apply to the next scan and persist to
`config.overrides.json`.

Backend is FastAPI (`web.py`); the frontend is a single dependency-free HTML page
(`static/index.html`) that talks to the same pipeline.

## Run (CLI)

**Offline demo** (no credentials, no network — uses the sample exports in
`fixtures/`, deterministic scoring only):

```bash
codescan scan --fixtures fixtures --no-ai --offline
```

**Full pipeline** with AI exploitability/chaining (needs `FOUNDRY_API_KEY` + `FOUNDRY_RESOURCE`):

```bash
codescan scan --fixtures fixtures            # AI on, KEV/EPSS enrichment on
```

**Live** against the configured sources (Bitbucket/GitHub inventory; Snyk,
Xray, GitHub alerts, SARIF/SBOM paths — whatever is wired up; unconfigured
sources are skipped, not fatal), pushing to ServiceNow — set the env vars in
`.env`, set `servicenow.push: true` in the config, then:

```bash
codescan scan --config config/config.example.yaml
```

Flags: `--no-ai` (deterministic only), `--offline` (skip KEV/EPSS network calls),
`--out` (ServiceNow import path), `--state` (validation-state store path),
`--sn-format csv|json` (output format — **CSV** for ServiceNow CSV Import Sets
is the default; `json` for a JSON file — also settable in config/UI),
`--repo owner/name` (scan specific GitHub
repo(s); implies GitHub source + a live scan; repeatable), `--whitebox` (review
the target repo's source with the built-in OpenHack AI engine; needs AI + git —
the Docker image includes git — skips uncredentialed Snyk/Xray — see below).

Scan a specific GitHub repo:

```bash
export GITHUB_TOKEN=ghp_...          # repo read access
export SNYK_TOKEN=… SNYK_ORG_ID=… XRAY_TOKEN=… XRAY_BASE_URL=…   # findings source
export FOUNDRY_API_KEY=…             # only if AI stages are enabled
export FOUNDRY_RESOURCE=…            # the Foundry resource serving the models
codescan scan --repo acme/checkout   # or several: --repo a/b --repo c/d
```

> codescan uses GitHub for the **repo inventory** (the scan surface) — the SCA/CVE
> **findings come from Snyk and Xray**. A repo those tools haven't scanned appears
> with zero SCA findings unless you also run the whitebox engine below. A finding
> source whose credentials aren't set is **skipped** (not an error), so you can
> run on whichever sources are wired up.

**Whitebox-only scan (no Snyk/Xray account).** To review a repo's *source* with
the built-in OpenHack AI engine — the way to scan a repo you don't have SCA
tooling for — add `--whitebox`. It clones the repo and reviews it with the model;
Snyk/Xray are skipped when uncredentialed, so all you need is Foundry credentials,
a GitHub token (optional for public repos, avoids rate limits), and `git`:

```bash
export FOUNDRY_API_KEY=…              # the whitebox engine is AI-driven
export FOUNDRY_RESOURCE=…
export GITHUB_TOKEN=ghp_...           # optional for public repos
codescan scan --repo mfmiguez-oss/codescan --whitebox --out out.json
```

You can also set the target repos without the CLI: in the **Config** tab, pick
`github` as the repo source and enter `owner/name` repos in **GitHub repos**,
then tick **live** and **Run scan** from the header.

### OpenHack (whitebox source review)

For a repo that Snyk/Xray haven't scanned, OpenHack-style
**[whitebox review](https://github.com/hadriansecurity/openhack)** generates
findings directly from source. codescan supports three ways to get them:

1. **Built-in engine (default auto).** codescan runs its own in-process review of
   the repo's source during a live scan — no external tool. See *Auto-run* below.
2. **External OpenHack.** Shell out to a separate OpenHack install. See *Auto-run*.
3. **Ingest an existing run.** Point codescan at output another OpenHack run wrote
   to `runs/<target>/<run-id>/finding-candidates/*.json`.

For (3), point codescan at that output — in the **Config** tab under **OpenHack**:
enable it, set **Findings dir** to the run dir (or its `finding-candidates/`), and
set **Repo** to `owner/name`; or in config:

```yaml
openhack:
  enabled: true
  findings_dir: runs/horizon-scanner/2026-07-05T12-00
  repo: mfmiguez-oss/horizon-scanner
```

codescan reads the finding-candidate JSON, normalizes each to a `Finding` (no
CVE; carries severity, target path, description, remediation, and OWASP/CWE-class
tags), then dedups, scores, and triages them alongside any Snyk/Xray findings.

**Auto-run — built-in engine (no external tool).** codescan ships its own
in-process whitebox review engine (`openhack_engine.py`), so a live scan can run
OpenHack-style source review with nothing to install. Set `openhack.auto` (and
keep `command` empty) and codescan clones the target repo, reviews its source
with the multi-provider LLM harness, writes OpenHack-schema `finding-candidates/`,
and ingests them — all in one scan:

```yaml
openhack:
  auto: true
  clone: true                 # git clone the target repo first
  workspace: .openhack
  # command left empty -> codescan's built-in engine (needs the AI stages enabled)
  max_files: 60               # cap source files reviewed per repo (cost/latency)
  max_file_bytes: 60000       # skip files larger than this
  min_confidence: low         # drop candidates below this confidence
```

The engine walks the repo, skips dependency/build/VCS dirs (`node_modules`,
`vendor`, `dist`, `.git`, …), reviews the security-relevant files first (auth,
handlers, queries, uploads, crypto), batches source within a character budget,
and asks the model for the code-grounded vulnerabilities it can point to
(injection, broken access control, SSRF, path traversal, deserialization,
hardcoded secrets, …). The prompt is **coverage-first** — report every plausible
finding with an honest `confidence`, since precision is filtered downstream
(`min_confidence`, scoring, analyst triage); this keeps recall high on
literal-following models that would otherwise self-filter to nothing. Route its
model/effort via the `openhack` task (defaults to the deep default tier; set
`claude-fable-5` for the deepest review).

**Multiple passes for recall.** AI source review is non-deterministic — a single
pass can miss a real issue. The engine runs `openhack.passes` **independent review
passes** (default **2**) and **unions** the results, so a vulnerability found in
*any* pass is reported: more passes → fewer missed. Duplicate findings across
passes are consolidated on file + **canonical vulnerability-class family** (models
word the class itself differently — "supply chain / ci security" and "ci/cd
supply-chain compromise" fold into one bucket), then grouped by **title
similarity** (so the same weakness worded differently across passes still merges,
while genuinely distinct same-class findings stay separate), keeping the strongest
severity/confidence seen and recording how many **distinct passes** agreed. That
agreement is a **confidence signal**: a finding seen in every pass is tagged
`corroborated`, one seen in a single pass `single-pass`, and the count ("identified
in 2 of 2 … passes") is noted on the finding. Set `passes: 1` for a single cheap
pass; each extra pass is another set of model calls, so it trades cost for recall.

**Different models per pass (stronger independence).** Because different model
families have different blind spots, you can route each pass to a **different
model** on the Foundry resource via `openhack.pass_models` — the passes then
disagree in useful ways, so the union is broader and agreement is more
meaningful. A finding confirmed by two different models is tagged
**`multi-model`** (and the note names them), the strongest confidence a review
can carry. Pass *i* uses `pass_models[i % len]` (cycling), unset fields inherit
the `openhack` tier, and a pass whose model deployment fails is skipped (not
fatal), so the union still benefits from the rest:

```yaml
openhack:
  passes: 3
  pass_models:
    - { model: claude-opus-4-8 }
    - { model: gpt-5 }
    - { model: mistral-large-2411 }
```

**Auto-run — external OpenHack.** To use a separate OpenHack install instead, set
`command` to your invocation; `{repo_path}` / `{output_dir}` are substituted and
the AI-provider env vars pass through to the subprocess:

```yaml
openhack:
  auto: true
  command: ["bash", "run_openhack.sh", "{repo_path}", "{output_dir}"]
```

codescan runs your invocation and reads the resulting `finding-candidates/`.
All of these fields are editable in the Config tab under **OpenHack**.

Inspect a produced import file (CSV or JSON — it resolves the sibling if the
exact path is absent):

```bash
codescan summary --out servicenow_import.csv
```

## Container deployment

Build and run the web UI in a container — offline demo, no key needed:

```bash
docker compose up --build          # -> http://localhost:8000
# or without compose:
docker build -t codescan .
docker run -p 8000:8000 -v codescan-data:/data codescan
```

Everything is environment-driven (no rebuild to reconfigure):

| Env var | Default | Purpose |
|---|---|---|
| `CODESCAN_AI` | `false` | Enable the AI stages (needs `FOUNDRY_API_KEY` + `FOUNDRY_RESOURCE`) |
| `CODESCAN_LIVE` | `false` | Scan the configured live sources instead of the bundled fixtures (needs creds) |
| `CODESCAN_PORT` | `8000` | Listen port |
| `CODESCAN_CONFIG` / `CODESCAN_FIXTURES` | baked-in | Override the config / fixtures paths |
| `CODESCAN_API_TOKEN` | — | If set, `/api/*` requires this token (defense-in-depth; see below) |
| `CODESCAN_LOG_LEVEL` | `INFO` | Log verbosity (`DEBUG` adds per-task model routing) |
| secrets | — | `FOUNDRY_API_KEY`, `FOUNDRY_RESOURCE`, `BITBUCKET_*`, `GITHUB_*`, `SNYK_*`, `XRAY_*`, `SERVICENOW_*` (see `.env.example`) |

For a live, AI-enabled deployment set `CODESCAN_AI=true` and `CODESCAN_LIVE=true`,
and provide the secrets — `docker run --env-file .env …`, or uncomment
`env_file: .env` in `docker-compose.yml`. Mount your own config over
`/app/config` to replace the default.

- Runs as a **non-root** user; the image holds **no secrets** (all via env).
- Runtime artifacts (ServiceNow export, validation state, config overrides,
  threat models) are written to **`/data`** — mount a volume to persist them.
- A **`/healthz`** endpoint backs the container `HEALTHCHECK`; a failed initial
  scan (e.g. missing live creds) is surfaced, not fatal — the UI still boots.
- Scan state is held **in memory**, so run a **single instance** (horizontal
  scale needs the shared datastore noted in the design doc).

## Deployment & operations

**Which path to use:**

| Goal | How |
|---|---|
| Evaluate / demo | `docker compose up --build` (offline, no key) — or `codescan serve`. |
| Try the AI stages | `codescan serve --ai` with `FOUNDRY_API_KEY` + `FOUNDRY_RESOURCE` set. |
| **Production** (live → ServiceNow) | The container with a production preset — see below. |

**Production — recommended.** A ready preset is shipped as
[`docker-compose.prod.yml`](docker-compose.prod.yml) (AI + live on, `env_file:
.env`, your config mounted, loopback-bound for a proxy in front):

```bash
cp .env.example .env                  # FOUNDRY_API_KEY + FOUNDRY_RESOURCE, GITHUB_*/BITBUCKET_*, SNYK_*, XRAY_*, SERVICENOW_*
cp config/config.example.yaml config/config.yaml   # set servicenow.push: true to POST
docker compose -f docker-compose.prod.yml up -d --build
```

**Operating it:**

- **Replicas & persistence.** Scan *results* are held in memory (re-derived by
  scanning), so run the web UI as a single replica behind your **SSO / reverse
  proxy**. The durable **validation-state store** is pluggable via `storage.backend`:
  `file` (default, local JSON on the `/data` volume — one writer) or **`sql`** (a
  shared Postgres/SQLite database via `storage.dsn`) so multiple replicas /
  concurrent scheduled runners share one store safely — a manual analyst decision
  is never clobbered by a machine proposal. `pip install 'codescan[sql]'` (+ a
  Postgres driver such as `psycopg`) for the SQL backend.
- **API token (defense in depth).** Set `CODESCAN_API_TOKEN` and every `/api/*`
  request must present it — via `Authorization: Bearer <token>`, an `X-API-Token`
  header, or by visiting `/?token=<token>` once (which sets a cookie the browser
  reuses). `/healthz` and the static page stay open. Unset = open (the SSO-fronted
  default). This is a guard for accidental exposure, not a replacement for the
  proxy.
- **Persist `/data`.** The ServiceNow export, validation-state store, config
  overrides, and `threat_models.json` live there. The state store is what makes
  rescans idempotent (via `correlation_id`) and keeps analyst decisions from being
  overturned — back it up.
- **Recurring scans.** Run the one-shot CLI on a schedule (cron / k8s CronJob / CI)
  rather than relying on the long-lived server: `codescan scan --config
  config/config.yaml`. Repeated imports are safe — no duplicate VR items, no
  re-opening closed ones.
- **Harden repo mapping before trusting live runs.** Snyk projects / Xray builds
  map back to repos by slug today (`pipeline._ingest_live`); wire this to your real
  naming convention (project tags, build metadata).
- **Secrets stay in the environment** — the image holds none; provide them via
  `--env-file` / your orchestrator's secret store, never baked into config or the
  image.
- **Audit log → SIEM.** Every scan run, config change, and validation-state change
  is recorded (with an **actor + UTC timestamp**) as an append-only decision trail,
  separate from the operational logs. It fans out to configurable **sinks**
  (`audit.*`): the local **JSONL file** (default; review in the UI's **Audit** tab
  or `GET /api/audit`, and tail-able by any forwarder), plus optional **syslog**
  (Splunk/QRadar/ArcSight/rsyslog) and **HTTP** (Splunk HEC / Elastic / Datadog /
  webhook) sinks for direct SIEM ingestion. Push delivery is best-effort — a SIEM
  outage is logged, never fatal — and the file remains the durable local record.
  Actor is taken from your SSO / reverse-proxy identity header (`X-Remote-User` /
  `X-Forwarded-User`) when present, so front codescan with an authenticating proxy
  to attribute decisions to real users. Persist `/data` to keep the local trail.

  ```yaml
  audit:
    http: { enabled: true, url: "https://splunk:8088/services/collector/event",
            token: ${AUDIT_HTTP_TOKEN}, token_prefix: "Splunk ", event_key: event }
  ```

**Secrets from HashiCorp Vault (built-in).** codescan can pull secrets straight
from Vault. Install the extra (`pip install 'codescan[vault]'`) and enable it in
config — at load, the listed KV secrets are fetched and injected into the
environment *before* interpolation, so every `${…}` token (and `FOUNDRY_API_KEY`)
resolves from Vault with no other change:

```yaml
vault:
  enabled: true
  address: ${VAULT_ADDR}
  auth: approle              # or token (uses VAULT_TOKEN)
  role_id: ${VAULT_ROLE_ID}
  secret_id: ${VAULT_SECRET_ID}
  kv_mount: secret
  paths: ["codescan"]        # secret/codescan's keys become env vars
```

Only Vault's own bootstrap creds come from the environment; the app secrets live
in Vault. An already-set env var wins unless `override_env: true`. For Vault's
short-lived **dynamic** secrets, prefer the per-run CLI (`codescan scan`) so each
run gets fresh credentials — the long-lived server reads secrets once at startup.
(You can equally keep zero code in the loop and use Vault Agent / the Secrets
Operator / `envconsul` to render env vars; the built-in path just saves the
sidecar.)

**Tuning for scale/cost** (all in config or the Config tab): `ai.max_concurrency`
(parallel per-service calls — latency), `ai.auto_route` (silent per-call tier
selection — cost), `ai.resolve_deployments` (pin routing to the resource's actual
deployments — availability), `ai.exploitability_batch` (findings per
exploitability request — resilience on finding-heavy services),
`ai.tasks.{openhack,threat_model}` → Sonnet (route the
token-heavy stages cheaper), and `openhack.passes` (recall vs. cost of the whitebox
review). See [Efficiency & cost](#efficiency--cost).

## Layout

```
src/codescan/
  config.py            config loading with ${ENV} interpolation
  vault.py             optional HashiCorp Vault secret source (env injection)
  models.py            canonical Finding model + fingerprint + VR state map
  connectors/          bitbucket / github (sources) · snyk / xray / openhack /
                       sarif / sbom / github_alerts (findings)
  openhack_engine.py   built-in in-process whitebox source-review engine (deep tier)
  openhack_runner.py   auto-run OpenHack (built-in engine or external command)
  llm.py               model router (task -> tier) + shared structured client
  concurrency.py       bounded parallel-map for the per-service AI calls
  dedup.py             deterministic cross-scanner merge
  dedup_ai.py          semantic near-duplicate merge (lower-cost tier / Haiku)
  enrich/              KEV, EPSS, reachability
  exploitability.py    Claude exploitability + chaining engine (deep tier)
  threatmodel.py       per-service STRIDE threat modeling (deep tier)
  scoring.py           composite risk score
  validation.py        validation-state machine + persistent state store
  servicenow.py        Vulnerable Item export (file or Table API push)
  web.py               FastAPI backend for the UI
  static/index.html    analyst triage dashboard (single-page, no build)
  pipeline.py          orchestration
  cli.py               `codescan` CLI (scan / serve / summary)
fixtures/              sample scanner exports for the offline demo (Snyk/Xray/
                       OpenHack; SARIF + SBOM fixture files also supported)
tests/                 offline pipeline tests (no network / key needed)
```

## Tests

```bash
pytest
```

The suite runs the deterministic pipeline over the fixtures and asserts the
load-bearing behaviors: cross-scanner dedup, corroboration, reachability-driven
scoring, validation states, ServiceNow record shape, and persisted closures.

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
  resolved) are persisted and survive rescans.

## License

Licensed under the [MIT License](LICENSE).
