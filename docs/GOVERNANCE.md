# codescan — AI Governance Control Mapping

Maps common AI-governance controls to the concrete evidence this project
provides, and states plainly where a control is (by nature) the adopting
organization's to operate. Companion documents:
[DATAFLOW.md](DATAFLOW.md) (formal DFD set), [THREATMODEL.md](THREATMODEL.md)
(ATLAS-aligned adversarial threat model), [SECURITY_FRAMEWORKS.md](SECURITY_FRAMEWORKS.md)
(framework-by-framework review), [DESIGN.md](DESIGN.md) (architecture and
rationale), [RELEASING.md](RELEASING.md) (change and release procedure).

## 0. Governance basics — ownership, intended use, incident response

| Element | Statement |
|---|---|
| **Accountable owner** | The **Application Security Engineering** function (the DESIGN.md document owner) is accountable for codescan's AI risk: model routing choices, scoring-weight and threshold changes, review of drift alerts, and sign-off on releases per [RELEASING.md](RELEASING.md). In a deploying organization this maps to the team that operates the vulnerability-management program. |
| **Intended use** | Aggregate, deduplicate, and **prioritize** vulnerability findings from existing scanners, and propose triage states, to feed a human-reviewed ServiceNow VR queue. It is a **decision-support** tool for security analysts. |
| **Out-of-scope use** | Not an autonomous remediation system, not a source-code SAST replacement, not a substitute for the scanners it aggregates, and **not an authority to auto-close findings** — every closure is a human decision. Outputs are advisory risk scores, not compliance attestations. |
| **AI-incident response** | An AI-specific failure — e.g. a `calibration.drift` alert, a spike in `scan.truncated`, or suspected model manipulation — is handled as: (1) the audit event reaches the SIEM; (2) the accountable owner reviews the calibration report and recent triage; (3) mitigation options are `--no-ai` (fall back to deterministic scoring, which always stands), pinning/rerouting the model (`ai.model` / per-task routing), or disabling OpenHack; (4) the change follows the [RELEASING.md](RELEASING.md) emergency path. The deterministic pipeline and human-in-the-loop mean an AI failure degrades gracefully rather than blocking triage. |
| **Bias / fairness** | The system scores **software vulnerabilities, not people**. No personal attributes enter any model input (verifiable in the [DATAFLOW.md](DATAFLOW.md) §3 data-out column). The only fairness-adjacent surface is uneven scoring quality *across weakness families or repos*; this is measured directly and continuously by the calibration report (per-CWE / per-component confirm rates and the noisy-keys list), so systematic mis-scoring of a category is detected rather than assumed absent. |

## 1. Dataflow diagrams and process flow documentation

| Control element | Evidence |
|---|---|
| Context / logical / physical DFDs | [DATAFLOW.md](DATAFLOW.md) — labeled level-0 context, level-1 logical, and physical DFDs with trust boundaries and a per-boundary crossing summary |
| Rendered architecture diagram | [architecture.svg](architecture.svg) / `.png`, regenerable from [make_diagram.py](make_diagram.py) |
| Multilevel process flows (collection, processing, enrichment, output) | DESIGN.md §5.1–§5.10 (one section per subprocess), §6 (scan sequence diagram) |
| How data is handled and used by the models | DESIGN.md §8 ("what leaves the environment": metadata-only digests vs. OpenHack source review), DATAFLOW.md §3 crossing table |

## 2. AI decision-making documentation

| Control element | Evidence |
|---|---|
| Explainability — how inputs become decisions | Composite scoring formula with weights (DESIGN.md §5.6); grounded-facts prompting design (§5.4); feedback-prior delta formula (§5.7a). Every AI judgement ships its *instance* explanation: per-finding rationale, chain narrative/preconditions/ATT&CK mapping, plain-language feedback-adjustment reasons appended to the rationale |
| Decision-process documentation | DESIGN.md §5.4 (exploitability), §5.6 (scoring), §5.7 (validation proposal rules), §5.7a/b (learning loop), plus the DFDs |
| End-user documentation | [README](../README.md), the in-app usage guide (Overview tab), and the finding drawer surfacing the "why" behind every score |
| Model documentation (architecture, training data, performance) | The models are served through Microsoft Foundry; their architecture/training documentation is the vendors': [Anthropic model overview](https://docs.claude.com/en/docs/about-claude/models), [OpenAI models](https://platform.openai.com/docs/models), [Mistral models](https://docs.mistral.ai/getting-started/models/). What codescan owns and documents: which model runs which task (§5.5 routing table, Config tab), and **measured in-context performance** — the calibration report grades each configured model's predictions against analyst outcomes |
| Performance expectations and measures | Calibration report (§5.7b): confirm rate by predicted-score bucket, score separation, noisy families; drift alerting thresholds in `calibration:` config |
| Adversarial robustness (threat model + testing) | [THREATMODEL.md](THREATMODEL.md) (ATLAS-aligned: prompt injection, evasion, feedback poisoning, exfiltration, DoS, excessive agency) with a guarding test per threat in `tests/test_security.py`, run in the offline gate |
| Framework alignment | [SECURITY_FRAMEWORKS.md](SECURITY_FRAMEWORKS.md) — review against NIST AI RMF, CSA AI Controls Matrix, MITRE ATLAS, OWASP LLM Top-10, IBM GenAI Controls, and Google SAIF |
| Compliance / safety / accountability | DESIGN.md §8 (security & privacy), §9 (failure modes), audit log with actor attribution; refusal handling documented (§8). Bias/fairness: the system scores *software vulnerabilities*, not people — no personal attributes enter any model input (see DATAFLOW.md §3 data-out column); the residual fairness surface (uneven scoring across weakness families) is exactly what the calibration report measures per-CWE |
| Licensing | MIT ([LICENSE](../LICENSE), `pyproject.toml` metadata) — permissive, widely accepted |
| Data management and traceability | Decision snapshots (machine belief frozen at decision time), `decided_at` timestamps, analyst notes, actor attribution from SSO headers, append-only audit → SIEM; data sourcing is org-owned scanner output (no third-party training data enters the system) |

## 3. Version control and version management

| Control element | Evidence |
|---|---|
| Version control | Git; disciplined branch → gate → ff-merge → push flow ([RELEASING.md](RELEASING.md)) |
| Data quality and validation | Strict pydantic config (`extra="forbid"` — misspelled settings fail loudly); all scanner input normalized through one typed `Finding` model; AI responses constrained by JSON Schema structured outputs; API inputs validated server-side (400 on bad input) |
| Reproducibility, testing | Full test suite runs offline and deterministic (no network, no API keys) against committed fixtures; CI runs it on every push across Python 3.10–3.12 |
| Environments / containerization | `Dockerfile`, `docker-compose.yml` (dev) and `docker-compose.prod.yml`; CI builds the image on every push |
| Automated tools | GitHub Actions ([ci.yml](../.github/workflows/ci.yml)): ruff + mypy (clean gate) + pytest + image build |
| Supply-chain security | CI runs a dependency vulnerability audit (`pip-audit`) and generates a **CycloneDX SBOM** (uploaded as a build artifact) on every push — codescan scans others' dependencies, so it audits its own. Python deps are version-pinned in `pyproject.toml`. Model-provider supply chain remains contractual (see residuals) |
| Approval and release procedures | [RELEASING.md](RELEASING.md) — including the recommended multi-maintainer hardening (branch protection, required reviews) |

## 4. Change management

The organizational layer of this control (change authority, ticketing system,
business approval, emergency-change delegation) is the **adopting
organization's process**; a tool cannot supply it. codescan supplies the
evidence and enforcement substrate that process plugs into:

| Control element | What codescan provides |
|---|---|
| Formal recordkeeping | Git history (code), append-only audit log (runtime): `config.changed` events name the actor and every changed key; `validation.changed` / `chain.validation.changed` record triage with before/after and notes |
| System of record for runtime changes | `config.overrides.json` — every UI config edit persists there and survives restart |
| Risk / impact identification | The full gate (ruff, mypy, tests) runs locally and in CI on every change; docs-in-lockstep convention keeps DESIGN.md/README current with behavior ([RELEASING.md](RELEASING.md)) |
| Change monitoring / continuous auditing | Audit events fan out to SIEM sinks in near-real-time; `GET /api/audit` and the UI Audit tab expose the trail |
| Communication and approval workflow | **Org-supplied** — wire the audit HTTP sink into the ticketing/ITSM system; protect `main` and require reviews for the approval gate |

## 5. Continuous monitoring and logging

| Control element | Evidence |
|---|---|
| Monitoring of critical systems | `/healthz` liveness probe; structured logs with per-stage timings; `scan.completed` audit events with counts, durations, KEV totals, feedback adjustments |
| Logging → SIEM | Append-only JSONL audit log fanning out to syslog (Splunk/QRadar/ArcSight) and HTTP (HEC/Elastic/webhook) sinks; push is best-effort, the file stays the durable record |
| Input validation / data consistency | Strict config models, typed normalization of every scanner payload, schema-constrained AI outputs, validated API bodies |
| **Model drift** | The calibration loop: every scan re-grades accumulated predictions against analyst outcomes and emits `calibration.drift` audit events (→ SIEM) when high-bucket precision or score separation degrades past configured thresholds (`calibration:` config), with an evidence floor so thin data can't false-alarm. Surfaced in the UI Calibration tab and `codescan calibration` |
| Data quality management | Dedup provenance retained from every scanner; corroboration tracked; legacy/partial records handled explicitly (unscored bucket, migration-on-open for old schemas) |

## Known residuals

Stated explicitly:

- **Per-user authentication** is delegated to a fronting SSO/reverse proxy;
  codescan trusts its identity header for audit attribution (DESIGN.md §8).
- **Approval enforcement** (branch protection, required reviews) is a repo
  setting the operating org must enable; the procedure assumes it in
  multi-maintainer deployments ([RELEASING.md](RELEASING.md)).
- **Provider retention** of AI-stage inputs is contractual, not technical —
  controlled via provider agreements, the Azure region of the Foundry resource, or routing to an
  approved deployment (DESIGN.md §8).
