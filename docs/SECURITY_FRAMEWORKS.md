# codescan — Security Framework Review

Assessment of codescan **as an AI system** against six security/governance
frameworks. It is itself a defensive security tool, but this review applies the
frameworks to how the pipeline protects itself, its data, and its outputs.

Companion documents: [THREATMODEL.md](THREATMODEL.md) (ATLAS-aligned threat
model), [GOVERNANCE.md](GOVERNANCE.md) (control→evidence mapping),
[DATAFLOW.md](DATAFLOW.md) (trust boundaries), [DESIGN.md](DESIGN.md).

## Architectural posture

The design aligns with what these frameworks reward, because several structural
choices *are* the controls:

- **Model output is data, never instructions** — JSON-Schema-constrained,
  validated on input (id allow-listing, score clamping, enum fallback), never
  executed. No `eval`/`exec`/`shell=True` in the codebase.
- **Grounded prompting** — KEV/EPSS/reachability enter as authoritative facts;
  deterministic floors bound the final score so no single AI value is decisive.
- **Bounded, explainable learning** — the feedback prior is capped, weighted,
  and never overrides the KEV floor; poisoned feedback has limited, auditable
  effect.
- **Human-in-the-loop** — the pipeline proposes; analysts dispose. No autonomous
  action.
- **Continuous measurement** — the calibration loop grades predictions against
  analyst outcomes and alerts on drift to the SIEM.

## Framework-by-framework

### NIST AI Risk Management Framework (Govern / Map / Measure / Manage)

| Function | Evidence |
|---|---|
| Govern | Accountable owner, intended-use boundary, and AI-incident response ([GOVERNANCE.md](GOVERNANCE.md) §0); change authority ([RELEASING.md](RELEASING.md)); audit log with actor attribution; MIT license |
| Map | Context/logical/physical DFDs ([DATAFLOW.md](DATAFLOW.md)); "what leaves the environment" (DESIGN.md §8); ATLAS threat model ([THREATMODEL.md](THREATMODEL.md)) |
| Measure | Calibration report (confirm-rate by score bucket, separation); deterministic offline test suite; **adversarial/robustness tests** (`tests/test_security.py`); drift detection |
| Manage | Drift alerts → SIEM; bounded feedback prior; human-in-the-loop; refusal fallback; rate limiting and per-scan ceiling |

### Cloud Security Alliance AI Controls Matrix

| Domain | Status |
|---|---|
| Logging & Monitoring | Append-only audit → syslog/HEC, drift events, per-stage timings |
| IAM | Secret management (Vault, env-only, constant-time token compare); per-user authN delegated to a fronting proxy (residual) |
| Data Security | Metadata-only to LLM by default; TLS everywhere (verify on); least-privilege tokens; `ai.inference_geo` |
| Resilience / DoS | Rate limiting + per-scan ceiling; retry/backoff; per-item failure isolation; idempotent export |
| Model supply chain | `pip-audit` + SBOM in CI for codescan's own deps; model-provider trust contractual (residual) |

### MITRE ATLAS

Full tactic-by-tactic treatment is in [THREATMODEL.md](THREATMODEL.md): indirect
prompt injection (T1), evasion/manipulated output (T2), feedback poisoning (T3),
exfiltration (T4), DoS/cost-harvesting (T5), excessive agency (T6). Each has
documented controls, residual risk, and a guarding test in
`tests/test_security.py`.

### OWASP Top 10 for LLM Applications (2025)

| ID | Status |
|---|---|
| LLM01 Prompt Injection | Threat-modeled (THREATMODEL.md T1); output-as-data + id allow-listing + human-in-loop; guarding tests |
| LLM02 Sensitive Info Disclosure | Metadata-only default; OpenHack source-sharing opt-in, bounded, documented |
| LLM03 Supply Chain | `pip-audit` + CycloneDX SBOM in CI; pinned deps; model provenance contractual |
| LLM04 / LLM10 Unbounded Consumption | Rate limiting on `/api/*` + per-scan finding ceiling + `max_concurrency` |
| LLM05 Improper Output Handling | JSON-Schema structured outputs; output validated and never executed |
| LLM06 Excessive Agency | Proposes, humans dispose; ServiceNow write scoped to import table; no autonomous remediation |
| LLM07 System Prompt Leakage | Prompts are non-secret/documented; no secrets in prompts |
| LLM08 Vector/Embedding | N/A — no RAG/vector store |
| LLM09 Misinformation | Grounded prompting + calibration measures score trustworthiness; rationale explainability |

### IBM Generative AI Controls Framework

Explainability (rationales, calibration), traceability (decision snapshots,
audit, `decided_at`), data governance (metadata-only, residency), and monitoring
(drift) are covered. Fairness is documented (scores software not people;
per-CWE calibration is the fairness measure — GOVERNANCE.md §0). Adversarial
robustness is covered by THREATMODEL.md + `tests/test_security.py`.

### Google Secure AI Framework (SAIF)

| Element | Status |
|---|---|
| Secure by default | Offline/no-AI default, metadata-only, secrets external, fail-loud config |
| Detection & response | Audit→SIEM + drift alerts; AI-incident runbook (GOVERNANCE.md §0) |
| Automated defenses | Deterministic floors + bounded prior + output validation constrain model influence |
| Platform controls | Rate limiting, per-scan ceiling, concurrency bound |
| Risk-based autonomy | Human-in-the-loop; no autonomous action |
| Supply chain | Dependency audit + SBOM in CI; provider trust contractual |

## Review gaps — disposition

The initial review identified five gaps; all are now closed:

| # | Gap | Disposition |
|---|---|---|
| 1 | No API rate limiting / cost ceiling | **Closed** — token-bucket limiter on `/api/*` + `server.max_findings_per_scan`, with tests ([ratelimit.py](../src/codescan/ratelimit.py)) |
| 2 | Indirect prompt injection undocumented/untested | **Closed** — [THREATMODEL.md](THREATMODEL.md) T1 + output-validation hardening + `tests/test_security.py` |
| 3 | No adversarial/robustness testing | **Closed** — `tests/test_security.py` (injection, invented findings, score inflation, feedback poisoning) in the offline gate |
| 4 | Governance soft spots (owner, intended use, incident runbook, bias) | **Closed** — [GOVERNANCE.md](GOVERNANCE.md) §0 |
| 5 | No SBOM / dependency scan | **Closed** — `pip-audit` + CycloneDX SBOM in CI ([ci.yml](../.github/workflows/ci.yml)) |

## Remaining residuals

Structural, operator-owned, and stated openly (GOVERNANCE.md residuals): per-user
authentication delegated to a fronting proxy; branch-protection/required-reviews
a repo setting the operator enables; model-provider retention and supply chain
governed contractually rather than technically. The `pip-audit` step is advisory
(warns, doesn't block) until the dependency baseline is confirmed clean, then it
can be tightened to a hard gate.
