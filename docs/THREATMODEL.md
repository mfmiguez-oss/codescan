# codescan — AI Threat Model (MITRE ATLAS-aligned)

Adversarial threat model for codescan **as an AI system**, mapped to
[MITRE ATLAS](https://atlas.mitre.org/) tactics and OWASP LLM Top-10 items. It
states each threat, the surface, the controls already in place, residual risk,
and the test that guards it. Companion docs: [DATAFLOW.md](DATAFLOW.md) (trust
boundaries), [GOVERNANCE.md](GOVERNANCE.md) (control mapping),
[SECURITY_FRAMEWORKS.md](SECURITY_FRAMEWORKS.md) (framework-by-framework review).

## Trust model

Instructions to the pipeline come only from configuration and authenticated
operators. **Everything a model sees, and everything a model returns, is data,
never instructions.** Scanner findings (titles, descriptions, package names)
originate from third-party feeds (CVE databases, dependency metadata) and are
**partly attacker-influenceable** — a crafted CVE description or a malicious
first-party dependency name can carry text into an LLM prompt. Model responses
are likewise untrusted. The controls below enforce the data-not-instructions
boundary on both sides.

## Threats

### T1 — Indirect prompt injection via finding content
*ATLAS: AML.T0051 (LLM Prompt Injection) · OWASP LLM01*

**Surface.** Finding `title` / `description` (from scanners/CVE feeds) and
analyst notes flow into the exploitability and dedup prompts as JSON values.

**Controls.**
- Model output is **JSON-Schema-constrained** (structured outputs) and consumed
  strictly as typed data. No model field is ever executed, `eval`'d, shelled
  out, or used to build a path/query/URL (verified: no `eval`/`exec`/`shell=True`
  in the codebase).
- `_apply` (exploitability.py) validates on the way in: a response may only
  annotate findings **that were in the request** (unknown ids skipped — the
  model cannot invent findings), scores are **clamped to 0–100** (a manipulated
  value can't inflate the composite), and an out-of-enum level falls back to
  `info` rather than aborting the batch.
- Deterministic signals the model does not control — KEV membership, EPSS, the
  `kev_floor` — bound the final score regardless of what the model returns.
- Human-in-the-loop: the pipeline *proposes*; analysts confirm/override.

**Residual.** A successful injection could bias a rationale string or shift a
score *within* the clamped range; it cannot execute code, invent findings, or
push a KEV finding below the floor. Bounded and analyst-reviewable.

**Guarded by.** `tests/test_security.py::test_injection_text_is_carried_as_data_only`,
`::test_model_cannot_invent_findings_or_inflate_scores`,
`::test_triage_history_note_injection_is_data_only`.

### T2 — Model evasion / manipulated output
*ATLAS: AML.T0015 (Evade ML Model), AML.T0043 · OWASP LLM05, LLM09*

**Surface.** A compromised provider, a poisoned model, or a hostile
OpenAI-compatible endpoint returns manipulated assessments.

**Controls.** Same input-validation as T1 (clamping, id allow-listing, enum
fallback); the composite score is a **blend** of AI judgement with deterministic
dimensions plus floors, so no single AI value is decisive; the calibration
report (calibration.py) measures whether scores actually predict analyst
outcomes and raises `calibration.drift` to the SIEM when they stop doing so —
a detection control for systematic manipulation or degradation.

**Residual.** Subtle, in-range bias below the drift thresholds. Detected over
time by calibration; mitigated by human triage.

**Guarded by.** `test_security.py::test_model_cannot_invent_findings_or_inflate_scores`;
drift coverage in `test_calibration.py` / `test_pipeline.py`.

### T3 — Feedback (training-data) poisoning
*ATLAS: AML.T0020 (Poison Training Data) · OWASP LLM04 (data)*

**Surface.** The feedback prior and the prompt's `prior_analyst_decisions`
learn from persisted analyst decisions. A malicious insider with triage access
could flood confirm/false-positive decisions to bias scoring.

**Controls.** The prior is **bounded and explainable**: capped at
`feedback.max_adjust` (default 15) regardless of volume, evidence-weighted with
shrinkage (mass alone doesn't win), min-evidence gated, self-exclusion, only
accuracy states count, it moves only the machine score (never analyst state),
and it **never pushes a KEV finding below `kev_floor`**. Every adjustment is
logged with its reason; every triage decision is an audited, actor-attributed
event.

**Residual.** A capped ±15 shift on non-KEV findings, fully auditable and
reversible. Insider access control is the operator's IAM responsibility.

**Guarded by.** `test_security.py::test_poisoned_feedback_stays_within_cap`,
`::test_poisoned_feedback_never_overrides_kev_floor`.

### T4 — Sensitive-data exfiltration via inference
*ATLAS: AML.T0024/AML.T0025 (Exfiltration) · OWASP LLM02*

**Surface.** AI stages send data to third-party model APIs.

**Controls.** Metadata-only by default (titles, CVEs, coordinates, deterministic
signals — **not source code**). The one exception, the OpenHack whitebox engine,
sends selected first-party source and is **off unless `openhack.auto`** and
bounded by `max_files` / `max_file_bytes`. Per-boundary data-out is enumerated in
[DATAFLOW.md](DATAFLOW.md) §3. Stricter deployments run `--no-ai`, disable
OpenHack, or route to an approved model deployment; `ai.inference_geo` selects
data residency.

**Residual.** Contractual (provider retention) rather than technical — stated in
GOVERNANCE.md residuals.

### T5 — Denial of service / unbounded consumption
*ATLAS: AML.T0034 (Cost Harvesting) · OWASP LLM04, LLM10*

**Surface.** `POST /api/scan` (and other `/api/*`) can trigger expensive
LLM work; a loop or hostile caller could drive unbounded cost.

**Controls.** Per-client token-bucket rate limiting on `/api/*` (ratelimit.py),
registered as the **outermost** middleware so it runs *before* the token guard —
floods are rejected with `429` before any work, and (because it wraps auth)
bad-token brute-force attempts are throttled rather than yielding unlimited
`401`s. A per-scan finding ceiling (`server.max_findings_per_scan`) bounds any
single run and audits truncation; `ai.max_concurrency` bounds in-flight model
calls. Requests are keyed by SSO actor when present, else client IP.

**Residual.** The in-process limiter is per-replica; behind a load balancer the
proxy's own limiter is preferred (documented). IP keying falls back to the
`X-Forwarded-For` client hop, which is spoofable when codescan is *directly*
exposed (no trusted proxy) — another reason anti-DoS should terminate at the
proxy; the actor key is unspoofable behind an authenticating proxy.

**Guarded by.** `tests/test_ratelimit.py`,
`tests/test_web.py::test_rate_limit_returns_429_on_flood`,
`tests/test_web.py::test_rate_limit_wraps_auth_so_bad_token_floods_are_throttled`,
`tests/test_pipeline.py::test_max_findings_per_scan_caps_and_keeps_worst`.

### T6 — Excessive agency
*OWASP LLM06 · Google SAIF (risk-based autonomy)*

**Surface.** An autonomous system acting on model output could take harmful
action (e.g. auto-closing real vulnerabilities).

**Controls.** codescan takes **no autonomous action**. It proposes validation
states; humans dispose. The only external write is the ServiceNow import,
scoped to the import table and idempotent on `correlation_id`. No remediation,
no code changes, no ticket closure without a human.

**Residual.** None material by design.

## Out of scope

Model *provider* security (training, weights, their infra) is the provider's
responsibility, governed contractually. Host/OS/container hardening and network
segmentation are the deploying organization's. Per-user authentication is
delegated to a fronting SSO/reverse proxy (see GOVERNANCE.md residuals).

## Testing posture

Adversarial and robustness tests live in `tests/test_security.py` and run in the
standard offline gate (no network, no API key) on every CI run. They treat
scanner text and model responses as hostile inputs and assert the controls
above hold. New model-facing surfaces should add a corresponding adversarial
test (NIST AI RMF *Measure*).
