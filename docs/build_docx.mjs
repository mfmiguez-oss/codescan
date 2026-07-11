// Build docs/DESIGN.docx — the full codescan design document with the embedded
// architecture diagram.  Run: node docs/build_docx.mjs
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import {
  Document, Packer, Paragraph, TextRun, HeadingLevel, AlignmentType,
  Table, TableRow, TableCell, WidthType, ShadingType, BorderStyle,
  ImageRun, TableOfContents, PageBreak,
} from "docx";

const HERE = path.dirname(fileURLToPath(import.meta.url));
const USABLE = 9360; // Letter, 1" margins, in DXA

// ---- helpers ----
const H1 = (t) => new Paragraph({ text: t, heading: HeadingLevel.HEADING_1, spacing: { before: 260, after: 120 } });
const H2 = (t) => new Paragraph({ text: t, heading: HeadingLevel.HEADING_2, spacing: { before: 180, after: 80 } });
const P = (t) => new Paragraph({ spacing: { after: 120 }, children: Array.isArray(t) ? t : [new TextRun(t)] });
const bullets = (items) => items.map((i) =>
  new Paragraph({ bullet: { level: 0 }, spacing: { after: 40 },
    children: typeof i === "string" ? [new TextRun(i)] : i }));
const code = (lines) => lines.map((l, idx) =>
  new Paragraph({
    shading: { type: ShadingType.CLEAR, color: "auto", fill: "F1F5F9" },
    spacing: { after: idx === lines.length - 1 ? 120 : 0 },
    children: [new TextRun({ text: l || " ", font: "Consolas", size: 18 })],
  }));

function cell(text, width, { bold = false, fill = null } = {}) {
  return new TableCell({
    width: { size: width, type: WidthType.DXA },
    margins: { top: 40, bottom: 40, left: 80, right: 80 },
    shading: fill ? { type: ShadingType.CLEAR, color: "auto", fill } : undefined,
    children: [new Paragraph({ children: [new TextRun({ text, bold, size: 20 })] })],
  });
}

function table(headers, rows, widths) {
  const headerRow = new TableRow({
    tableHeader: true,
    children: headers.map((h, i) => cell(h, widths[i], { bold: true, fill: "E2E8F0" })),
  });
  const bodyRows = rows.map((r) =>
    new TableRow({ children: r.map((c, i) => cell(c, widths[i])) }));
  return new Table({
    columnWidths: widths,
    width: { size: USABLE, type: WidthType.DXA },
    rows: [headerRow, ...bodyRows],
  });
}

const spacer = () => new Paragraph({ spacing: { after: 120 }, children: [] });

// ---- architecture image (auto-size from PNG IHDR) ----
const pngPath = path.join(HERE, "architecture.png");
const png = fs.readFileSync(pngPath);
const pxW = png.readUInt32BE(16), pxH = png.readUInt32BE(20);
const dispW = 624, dispH = Math.round(dispW * pxH / pxW);
const figure = new Paragraph({
  alignment: AlignmentType.CENTER,
  spacing: { before: 80, after: 60 },
  children: [new ImageRun({ type: "png", data: png, transformation: { width: dispW, height: dispH } })],
});
const caption = new Paragraph({
  alignment: AlignmentType.CENTER, spacing: { after: 160 },
  children: [new TextRun({ text: "Figure 1 — codescan pipeline architecture", italics: true, size: 18, color: "64748B" })],
});

// ---- title block ----
const title = new Paragraph({
  spacing: { after: 40 },
  children: [new TextRun({ text: "codescan — Design Document", bold: true, size: 44, color: "0F172A" })],
});
const subtitle = new Paragraph({
  spacing: { after: 200 },
  children: [new TextRun({
    text: "Enterprise code-scanning aggregation, AI exploitability triage, and ServiceNow Vulnerability Response feed",
    size: 22, color: "64748B" })],
});
const metaTable = table(
  ["Field", "Value"],
  [
    ["Status", "Draft / v0.1"],
    ["Owner", "Application Security Engineering"],
    ["Scope", "Scanner aggregation, AI exploitability & chaining, ServiceNow VR export, analyst UI"],
    ["Related", "README.md (usage); source under src/codescan/"],
  ],
  [2000, 7360]);

// ---- body ----
const children = [
  title, subtitle, metaTable, spacer(),
  new Paragraph({ children: [new TextRun({ text: "Contents", bold: true, size: 24 })], spacing: { before: 160, after: 80 } }),
  new TableOfContents("Contents", { hyperlink: true, headingStyleRange: "1-2" }),
  new Paragraph({ children: [new PageBreak()] }),

  H1("1. Purpose"),
  P("Two commercial scanners — Snyk and JFrog Xray — report vulnerabilities against source in a local Bitbucket Data Center install. Neither output is consumable on its own: they overlap, they rank by raw CVSS (which over-ranks unreachable CVEs and under-ranks chainable mediums), and neither answers the question a responder actually asks — is this exploitable in our environment, and how bad is it if several issues are combined?"),
  P("codescan is the pipeline between the scanners and ServiceNow Vulnerability Response (VR). It aggregates and deduplicates findings, uses an LLM to assess real-world exploitability and discover multi-step attack chains, computes a composite risk score, tracks a validation lifecycle, and emits ServiceNow-ready records — with an analyst UI on top."),
  H2("Goals"),
  ...bullets([
    "One deduplicated finding per real weakness, regardless of how many scanners saw it.",
    "Exploitability grounded in authoritative signals (KEV, EPSS, reachability), not raw CVSS.",
    "Explicit attack chains — sequences of findings that combine into a worse outcome — scored accordingly.",
    "A composite risk score that reorders the queue by actual risk.",
    "A validation lifecycle that survives rescans (analyst decisions are persisted).",
    "Output shaped for ServiceNow VR with idempotent upserts.",
    "Cost-appropriate model use: lower-cost models for mechanical work, deep models for reasoning.",
  ]),
  H2("Non-goals"),
  ...bullets([
    "Running the scans. Snyk/Xray own detection; codescan consumes their results.",
    "Being the system of record. ServiceNow VR is the SoR; codescan is a feeder and triage aid.",
    "Auto-remediation or auto-closing findings. It proposes; humans decide.",
    "Replacing CVSS/EPSS/KEV. It composes them.",
  ]),

  H1("2. Requirements to design mapping"),
  table(
    ["Requirement", "Design element"],
    [
      ["Code in local Bitbucket", "connectors/bitbucket.py — builds the repo inventory. GitHub/GHES (connectors/github.py) is a selectable alternative via source.provider."],
      ["Snyk + Xray available", "connectors/snyk.py, connectors/xray.py — live pull or offline export, normalized to one Finding."],
      ["Output for ServiceNow Vulnerabilities", "servicenow.py — sn_vul_vulnerable_item records, idempotent via correlation_id."],
      ["Validation states", "validation.py + models.py — lifecycle + persistent state store + VR state mapping."],
      ["Deduplication", "dedup.py (deterministic) + dedup_ai.py (semantic, lower-cost tier)."],
      ["Exploitability incl. chaining, scored", "exploitability.py (LLM) + enrich/ (KEV/EPSS/reachability) + scoring.py."],
      ["AI tooling", "llm.py — task-to-model router over the Anthropic SDK."],
    ],
    [3000, 6360]),

  H1("3. Architecture"),
  figure, caption,
  P("The pipeline is a linear series of stages over a list of Finding objects. Each stage enriches the same in-memory list; nothing is scanner-specific past ingestion. The two AI stages (semantic dedup, exploitability) are optional — the deterministic pipeline produces scored, ServiceNow-ready output on its own."),
  H2("Layering"),
  table(
    ["Layer", "Modules", "Responsibility"],
    [
      ["Connectors", "connectors/, openhack_engine.py, openhack_runner.py", "External systems; raw scanner shapes; in-process whitebox review."],
      ["Domain model", "models.py", "Canonical Finding, fingerprinting, state enums, difficulty signals."],
      ["Processing", "dedup*.py, enrich/, exploitability.py, scoring.py, validation.py, feedback.py, calibration.py", "Transform findings; calibrate from feedback; grade score calibration."],
      ["AI infrastructure", "llm.py, providers/, concurrency.py", "Model routing (+ auto-route), multi-provider client, bounded parallelism."],
      ["Orchestration", "pipeline.py", "Wire stages together; two ingest modes."],
      ["Interfaces", "cli.py, web.py, static/", "CLI, HTTP API, dashboard."],
    ],
    [1700, 2900, 4760]),
  P("Dependencies point downward only: interfaces depend on orchestration, which depends on processing, which depends on the domain model. Connectors and llm.py are leaf infrastructure."),

  H1("4. Domain model"),
  P("Everything downstream operates on one type, Finding (models.py). Snyk and Xray describe the same weakness in different shapes; normalization at ingestion means dedup, scoring, and export never branch on scanner. Sub-objects: Component (affected package), Location (repo + path), Exploitability (the assessment: level, 0-100 score, reachability, KEV flag, EPSS, rationale, chain IDs), and the Severity / Source / ValidationState enums."),
  H2("4.1 Fingerprint (the identity function)"),
  P("Dedup and idempotent ServiceNow upserts both hinge on a stable identity:"),
  ...code([
    "fingerprint = sha256( vuln_key | component_key | repo )[:32]",
    "  vuln_key       = sorted CVEs, else sorted CWEs, else lowercased title",
    "  component_key  = name@version   (NOT the purl string)",
    "  repo           = location.repo  (NOT the path)",
  ]),
  P("Two deliberate choices, both learned from bugs the tests caught:"),
  ...bullets([
    "Component, not purl. Snyk emits a purl; Xray often doesn't. Keying on the purl string would prevent the two scanners from ever merging. Normalized name@version aligns them.",
    "Repo, not path. Snyk reports the manifest path; Xray reports the artifact coordinate. For SCA findings the repository is the correct granularity. (Path-level identity is right for SAST — see section 11.)",
  ]),

  H1("5. Component design"),
  H2("5.1 Connectors"),
  P("All connectors extend a shared HttpClient (bearer auth, retry/backoff on 429/5xx, paging). Scanner connectors (Snyk, Xray) have two ingestion paths: fetch() for a live API pull and from_file() for a native scanner export. The offline path is not just for demos — it makes the pipeline runnable in CI, in tests, and against archived scan data with zero credentials."),
  P("Findings sources are pluggable. Beyond Snyk/Xray (SCA/CVE), a third source — OpenHack (connectors/openhack.py) — ingests whitebox source-review findings (finding-candidates/*.json). These are first-party source issues with no CVE (dedup keys on title + path); they carry severity, target path, description, remediation, and OWASP/CWE-class tags, and flow through the same normalize -> dedup -> score -> triage path — giving codescan findings for repos the SCA/CVE scanners never covered. Three ways to produce them: (1) Built-in engine (default auto) — openhack_engine.py runs an in-process whitebox review over a cloned repo using codescan's own LLM harness, no external tool; it walks the source, skips dependency/build/VCS dirs, reviews security-relevant files first, batches source, and asks the model (openhack task) for concrete, code-grounded vulnerabilities, writing OpenHack-schema candidates. (2) External command — openhack.command shells out to a separate OpenHack install ({repo_path}/{output_dir} substituted, AI env passed through); openhack_runner.py clones and dispatches to either path. (3) Ingest an existing run directory."),
  P("Multiple review passes (recall). AI source review is non-deterministic, so the built-in engine runs openhack.passes independent passes (default 2) and unions the results — a vulnerability found in any pass is reported, so more passes miss fewer. Duplicates across passes are consolidated on (file, vulnerability class, title), keeping the strongest severity/confidence seen and recording cross-pass agreement: seen in every pass -> tag corroborated, seen once -> single-pass, with an 'identified in N of M passes' note that survives to the Finding as a confidence signal."),
  P("Different suppliers per pass. openhack.pass_models routes each pass to its own supplier/model (pass i -> pass_models[i % len], unset fields inheriting the openhack tier, via LLMClient.resolve_spec / ModelRouter.override). Different vendors have different blind spots, so diverse passes make the union broader and the agreement more meaningful — a finding confirmed by two or more suppliers earns a multi-supplier tag. Each pass is isolated: a supplier without a configured key is logged and skipped, and the union still benefits from the passes that ran."),
  P("The repo inventory (scan surface) comes from a pluggable SCM source: Bitbucket Data Center (bitbucket.py) or GitHub / GitHub Enterprise Server (github.py), selected by source.provider (editable in the config UI). Both emit the same Repo list; GitHub's identity is owner/name (its full_name), so Snyk/Xray findings anchor to the same repo regardless of provider. Repo mapping (Snyk projects / Xray builds back to repos) is the documented integration point to harden for production."),
  H2("5.2 Deduplication (two passes)"),
  ...bullets([
    "Deterministic (dedup.py) — group by fingerprint, merge collisions. The merge keeps the higher-severity record as primary, unions CVEs/CWEs/references/fixes, prefers a present CVSS and the longer description, and records provenance from every contributing scanner. A finding seen by both scanners earns a corroboration bonus in scoring.",
    "Semantic (dedup_ai.py, optional, lower-cost tier) — catches cross-scanner duplicates the fingerprint misses (same weakness, divergent identifiers). Deliberately narrow: only compares findings in the same repo + same component, and only merges what the model marks as clearly the same vulnerability.",
  ]),
  H2("5.3 Enrichment (pluggable framework)"),
  P("Enrichment is a framework, not a fixed step. Each source is a BaseEnricher (enrich/) with an enrich(findings) method; build_enrichers assembles the enabled ones from config and runs them in order. Adding a source (VEX, asset criticality, exploit-DB) is a new subclass with no pipeline change."),
  ...bullets([
    "CISA KEV — is the CVE actively exploited in the wild?",
    "FIRST EPSS — probability of exploitation (batched lookups).",
    "Reachability — heuristic over scanner metadata; True/False/unknown (negative phrasing checked first).",
    "AI enrichment (optional, lower-cost tier) — remediation guidance + categorization tags, plus a reachability judgement when the scanner gave none. Complements the exploitability engine; routed to the enrichment task (Haiku by default).",
  ]),
  P("Deterministic enrichers run first — cheap, authoritative, and grounding for the LLM stages. Each is toggleable in config and from the config UI. Network failures degrade gracefully rather than failing the run."),
  H2("5.4 Exploitability & chaining engine"),
  P("exploitability.py is the core value-add. Per service, it sends the LLM the finding set plus the deterministic signals and asks two things: (1) per-finding exploitability in our context (0-100), weighting actively-exploited / high-EPSS / reachable issues up and unreachable / fixed issues down; and (2) attack chains — ordered sequences of findings that combine into greater impact (e.g. SSRF reaches an internal service carrying an unauthenticated RCE), each with narrative, preconditions, impact, likelihood, chain score, and MITRE ATT&CK mapping."),
  ...bullets([
    "Grounded, not recalled — the model reasons over KEV/EPSS/CVSS/reachability facts, so its judgement is about our exposure.",
    "Triage history as a grounded fact (feedback.prompt_history, default on) — a finding's digest gains prior_analyst_decisions: counts of how this org's analysts triaged similar findings (same CWE family / component), built from the state store (TriageHistory). The system prompt frames it as organizational context, not a verdict — weighed where it transfers, noted in the rationale, never overriding KEV or reachability. Complements the post-hoc score prior (5.7a) by putting the same ground truth into the reasoning.",
    "Structured output — a JSON Schema guarantees a parseable response; no prompt-scraping.",
    "Per-service scoping — chaining is scoped to a repo/service, which keeps requests tractable and chains meaningful.",
  ]),
  H2("5.5 Model routing + multi-provider harness (llm.py, providers/)"),
  P("Every AI stage runs through a provider harness (providers/): each supplier — anthropic (native structured outputs, adaptive thinking, effort, Fable fallbacks), openai (and any OpenAI-compatible endpoint via OPENAI_BASE_URL), google (Gemini) — implements the same complete_json contract. Non-Anthropic SDKs are imported lazily, so they are optional deps. ModelRouter resolves a task to a ModelSpec (provider + model + effort + token budget) and LLMClient dispatches to the resolved supplier, so a task can run on any model from any supplier, set in config."),
  table(
    ["Task", "Default tier", "Rationale"],
    [
      ["dedup / enrichment", "Haiku 4.5", "Mechanical judgement."],
      ["exploitability", "Opus 4.8 (Fable 5 for hardest chaining)", "Deep, judgement-heavy reasoning."],
      ["threat_model / openhack", "default tier (ai.model)", "Deep reasoning; route to Sonnet for cost."],
      ["(other)", "default tier (ai.model)", "Fallback."],
    ],
    [2000, 3200, 4160]),
  P("The client omits effort / adaptive thinking for models that don't support them (Haiku) and enables server-side refusal fallbacks for Fable/Mythos (security tooling can trip false-positive classifier refusals; the request transparently re-serves on Opus 4.8). Config ai.tasks.<name> overrides any field per task. Adding a new AI stage is a one-liner."),
  P("Enterprise / Fable 5. For security triage, capability on the judgement tasks converts to outcomes, so the enterprise profile (config/config.enterprise.yaml) routes exploitability / threat modeling / whitebox review to Fable 5 and keeps mechanical work on Haiku. codescan handles Fable's enterprise behaviors: the refusal fallback above; data residency (ai.inference_geo us/eu, threaded onto Anthropic first-party requests); and Fable's 30-day data-retention requirement — under zero data retention Anthropic 400s Fable, which the provider re-raises with actionable guidance (route to Opus 4.8). Fable also can't use the Batches API, so batch mode keeps Fable tasks synchronous."),
  P("Silent adaptive routing (ai.auto_route, off by default). When enabled, each AI call is nudged up or down an Anthropic capability ladder — Haiku -> Sonnet -> Opus -> Fable — relative to its configured tier, by a difficulty signal the calling stage computes (group_difficulty / size_difficulty): a single low-severity finding downgrades (cheaper), while a KEV / multi-critical / large group upgrades (stronger). It only shifts Anthropic ladder models — custom ids and other suppliers are untouched — and clamps at both ends. Enabling it is the operator's explicit opt-in; thereafter it applies silently per call."),
  P("Fan-out (complete_json_many). The judgement-heavy stages each build one request per repo/service and hand the list to LLMClient.complete_json_many, which owns the fan-out and returns {custom_id: result}. Two strategies: (a) bounded concurrency (ai.max_concurrency, default 4) via resilient_map — up to N at once, per-item failures isolated, deterministic apply order, latency-only (same requests/cost); or (b) Message Batches (ai.batch) — one Anthropic batch at ~50% token cost, asynchronous (the pipeline polls up to batch_max_wait_seconds), for scheduled runs. Fable (refusal fallbacks are rejected on Batches) and non-Anthropic requests fall back to concurrency, as does the whole set if submission errors. Prompt caching is deliberately omitted: the static system prompts sit below the model's minimum cacheable-prefix size and payloads differ."),
  H2("5.6 Composite scoring (scoring.py)"),
  P("A 0-100 blend of four weighted dimensions (weights configurable, normalized to sum to 1):"),
  table(
    ["Dimension", "Weight", "Signal"],
    [
      ["severity", "0.30", "CVSS-derived base impact"],
      ["exploitability", "0.35", "AI score, EPSS, KEV, threat signal (averaged)"],
      ["exposure", "0.20", "network reachability of the path"],
      ["chaining", "0.15", "max chain score of chains the finding is in"],
    ],
    [2400, 1400, 5560]),
  P("Adjustments on top of the blend: a KEV floor (anything actively exploited is floored to 85) and a corroboration bonus (+2 when both scanners agree). Threat models influence the score in exactly one place — the exploitability dimension: a cited finding's threat signal is one of the averaged exploitability inputs, so a threatened finding scores higher, counted once. Runs without threat modeling are unaffected. This is what makes the queue useful: an unreachable critical drops below a reachable, chainable, threatened high."),
  H2("5.7 Validation states (validation.py)"),
  P("Internal lifecycle mapped to ServiceNow VR states on export: new -> under_investigation -> confirmed / false_positive / risk_accepted / duplicate / resolved. The pipeline proposes a conservative initial state; a human confirms or overrides. Persistence is the important property: the StateStore persists each decision keyed by fingerprint, tags whether a human set it, freezes a machine-belief snapshot — the risk score, AI exploitability score, EPSS, KEV, reachability, severity, and repo the pipeline held at record time — plus a decided_at timestamp and the analyst's optional one-line note (why). Manual entries are never overwritten by machine records, so an analyst decision keeps the prediction it was made against — the ground truth the calibration report (5.7b) grades. On rescan, any manual decision or terminal closure is honored and never re-opened — analyst effort is never silently discarded. The store is pluggable behind StateStoreBase (storage.backend): the file StateStore (JSON, atomic writes) or the DB-backed SqlStateStore (SQLAlchemy -> Postgres/SQLite) for shared HA use, with concurrency-safe writes (a manual decision always wins; a machine proposal never overwrites a manual/terminal row). Pre-snapshot entries still load: the file store tolerates absent keys and the SQL store applies ADD COLUMN migrations on open. Attack chains have a lifecycle too: analysts confirm or dismiss a chain (new / confirmed / false_positive), persisted under a chain:<fingerprint> key — the fingerprint hashes the chain's finding set, stable across runs where model-assigned chain ids are not — and re-applied on every scan. A dismissed chain stays in the result (visible, reversible) but is excluded from scoring, threat modeling, and the ServiceNow export; finding-oriented consumers (feedback prior, calibration) skip chain keys."),
  H2("5.7a Analyst-feedback loop (feedback.py)"),
  P("The persisted validation decisions are also a training signal. Before export, apply_feedback builds a prior from the manual confirmed (true positive) and false_positive decisions in the state store, aggregated by weakness family (CWE) and component. A new finding sharing a trait the org has repeatedly dismissed is nudged down; one repeatedly confirmed, up — so the scanner adapts to this estate rather than scoring every run identically. Conservative and explainable: capped (max_adjust), gated on a minimum sample (min_evidence), a finding never adjusts itself, only accuracy states count (not risk_accepted/resolved), it moves only the machine score (never the analyst's state), and a KEV finding is never pushed below kev_floor. Evidence is weighted, not just counted — delta = max_adjust * (W+ - W-) / (W+ + W- + shrinkage), each decision's weight decayed by age (halving every half_life_days) and boosted when made in the same repo as the new finding (same_repo_boost); the shrinkage pseudo-count limits the influence of small samples (two unanimous decisions produce a small adjustment; twenty approach the cap). Each adjusted finding records the reason in its rationale + a feedback-adjusted tag, and the scan's audit event carries the adjusted count. The same history also reaches the model directly: TriageHistory packages per-finding confirmed/false-positive counts — plus up to three most-recent analyst notes labeled with their outcome — for the exploitability prompt (5.4, feedback.prompt_history). The notes make the history transferable: 'false_positive: vendored test fixture' tells the model when the precedent applies, where a bare count can't. The two mechanisms are complementary — the prompt context lets the model reason with the org's ground truth (and discount it when it doesn't transfer), while the score prior remains a deterministic, bounded backstop that works even when the AI stage is off."),
  H2("5.7b Calibration report (calibration.py)"),
  P("The feedback prior adapts scores; the calibration report measures whether the scores were right to begin with. It joins each manual confirmed / false_positive decision to the machine-belief snapshot frozen with it (5.7) and reports: the confirm rate by predicted-score bucket (0-39 / 40-59 / 60-79 / 80-100) — rising with the bucket means the composite score predicts analyst outcomes, flat or inverted means the weights or the AI stage need work; the score separation (mean predicted score of confirmed vs false-positive decisions); and the noisiest keys — CWE families/components whose manual history is dominated by false positives (the same keys the feedback prior nudges), a concrete scanner-tuning worklist. Like the prior, it uses only accuracy states, and it is read-only — it changes nothing, it grades. Decisions persisted before snapshots existed count toward totals but cannot be bucketed (reported as unscored). Surfaced as GET /api/calibration, the UI Calibration tab, and codescan calibration on the CLI. Because the snapshot captures what the configured pipeline predicted, the report also makes provider/model routing changes (5.5) empirically comparable over time. Drift alerting (thresholds in the calibration config section) turns the pull-based report into a continuous-monitoring control: after each scan the pipeline re-grades the history and raises a calibration.drift audit event — fanning out to the SIEM sinks — when the 80-100 bucket's confirm rate falls below min_high_confirm_rate or the confirmed-vs-false-positive mean-score gap falls below min_separation; both checks stay silent below min_bucket_decisions of evidence, so a new deployment or a small number of disagreeing decisions does not trigger alerts. Alerts also surface in the Calibration tab and the CLI report."),

  H2("5.8 ServiceNow export (servicenow.py)"),
  P("Builds sn_vul_vulnerable_item records, highest-risk first, carrying the composite score, risk rating, validation state, and the exploitability rationale plus attack-chain context in the work notes — so a responder sees why the tool ranked it. correlation_id is the fingerprint, making the import idempotent: re-runs upsert the same item and closed items stay closed. Output is written to a file — JSON (servicenow_import.json) or, when servicenow.format is csv, a CSV (servicenow_import.csv) for CSV Import Sets, with multi-line work notes quoted correctly — or POSTed to the import table via the Table API. The format is settable in config, the config UI, or with --sn-format on the CLI."),
  H2("5.9 Web UI (web.py + static/index.html)"),
  P("A FastAPI backend holds the latest result in memory; the frontend is a single dependency-free HTML page, plus GET /api/export for JSON/CSV downloads. Overview: the landing page — run status (source, mode, last run), key metrics, a severity breakdown, quick actions (run, download JSON/CSV, jump to a tab), and an in-app usage guide, making the UI a complete usage surface with no CLI required. Findings: the triage queue with filters, signal badges, a per-finding detail drawer (CVSS vector, EPSS, reachability, provenance, rationale, remediation, tags, threats, chains), and inline validation-state editing that persists to the persistent store; the drawer's Triage section takes an optional one-line note with the decision — persisted, audited, and fed to the AI on similar findings."),
  P("Threats: the per-service threat models (5.10) — STRIDE threats with linked findings/chains, assets, entry points, trust boundaries, posture, and recommendations."),
  P("Calibration: the score-calibration report (5.7b) — confirm rate by predicted-score bucket, score separation, and the noisiest weakness families/components, via GET /api/calibration."),
  P("Config: edit non-secret settings live — the repo source (Bitbucket/GitHub) and GitHub repo/org targets, default AI tier, per-task model routing, enrichment toggles, threat-modeling toggle, scoring weights, and the ServiceNow push flag/format. Secrets are shown masked and read-only (they stay in the environment). Edits apply to the next scan and persist to config.overrides.json, layered over the base config on restart; POST is validated server-side and rejected with 400 on bad input."),
  P("Scans run from the header (AI / offline / live toggles + Run scan) via POST /api/scan, in-process, recording a last-run timestamp. On-demand live scans of Bitbucket/Snyk/Xray are supported, not just the boot mode. A failed run — e.g. live mode without credentials — is caught and shown in an error banner with the last good result preserved, rather than returning a 500; /healthz backs the container probe."),

  H2("5.10 Threat modeling (threatmodel.py, optional, deep tier)"),
  P("Where the exploitability engine works bottom-up (per-finding scores, concrete chains), threat modeling is the top-down counterpart. Per service it produces a STRIDE threat model grounded in that service's findings and chains:"),
  ...bullets([
    "Assets — what an attacker targets (data, credentials, functionality) with a sensitivity note.",
    "Entry points / trust boundaries — the attack surface implied by the components and findings.",
    "Threats — STRIDE-categorized, each citing the related finding IDs and chain IDs that evidence it, plus likelihood, impact, and mitigations. Prefer fewer, well-grounded threats over generic ones.",
    "Posture — an overall risk level, summary, and prioritized recommendations.",
  ]),
  P("On by default (threat_model.enabled; only runs when the AI stages are enabled — set false to skip the extra per-service call), per-service, routed to the threat_model task (the default deep tier unless overridden), and emits a threat_models.json artifact alongside the ServiceNow export. Threats reference findings by ID, so the UI cross-links both directions."),
  P("It feeds back into scoring. Because it runs before the scorer, apply_threat_influence writes results back onto findings: it records the citing threat IDs, derives a per-finding threat signal (0-100 from the strongest citing threat's likelihood), and raises the categorical exploitability level when the threat implies more than the isolated assessment did. The scorer reflects this through the exploitability dimension only, so the threat is counted once."),

  H1("6. Data flow — a scan"),
  P("On run: list Bitbucket repos; fetch Snyk + Xray findings; normalize and run deterministic dedup; (optional) semantic dedup via Haiku; KEV/EPSS enrichment; (optional) exploitability + chaining via Opus/Fable; composite score; validation states; build/push ServiceNow vulnerable items. The result (findings, chains, items) is returned to the CLI or UI. See Figure 1 for the stage graph."),

  H1("7. Key design decisions"),
  table(
    ["Decision", "Alternatives", "Why"],
    [
      ["One canonical Finding model", "Keep scanner shapes, branch downstream", "Scanner-agnostic dedup/scoring/export; a third scanner is one connector."],
      ["Fingerprint on (vuln, component, repo)", "Include scanner id / path / purl", "Excludes scanner so cross-tool dupes merge; excludes path/purl because scanners disagree."],
      ["Deterministic + optional AI dedup", "AI-only; deterministic-only", "Deterministic is free and exact; AI catches residual near-dupes cheaply (Haiku)."],
      ["Ground the LLM with KEV/EPSS/reachability", "Let the model recall CVE details", "Turns unreliable recall into grounded exposure reasoning."],
      ["Structured outputs (JSON Schema)", "Parse free text", "Guaranteed-parseable; no brittle scraping."],
      ["Per-service chaining scope", "Whole-estate chaining", "Meaningful (connected components) and tractable (bounded requests)."],
      ["Task-based model routing", "One model everywhere", "Haiku for mechanical work, Opus/Fable for reasoning."],
      ["Built-in in-process OpenHack engine", "Require an external OpenHack install", "\"Auto\" mode works with no extra tooling; external command stays as an override."],
      ["Multi-pass whitebox review (default 2)", "Single pass", "AI review is non-deterministic; unioning passes raises recall; agreement is a confidence signal."],
      ["Opt-in silent auto-route", "Fixed tiers; or always-on downgrade", "Adapts cost/quality per call by difficulty; opt-in keeps the default deterministic."],
      ["Bounded concurrency across per-service calls", "Sequential", "Independent I/O-bound calls; parallelism cuts wall-clock time, deterministic apply, no cost change."],
      ["Composite score with KEV floor", "Rank by CVSS", "CVSS mis-ranks; the blend + floor surface exploited/chainable issues."],
      ["Persistent, human-tagged states", "Recompute every run", "Analyst decisions survive rescans; proposals stay re-derivable."],
      ["Feedback loop: bounded, explainable score prior from analyst decisions", "No feedback; or opaque retraining", "Closes the loop (adapts to the estate) while staying transparent, capped, and never overriding the human or the KEV floor."],
      ["Idempotent export via correlation_id", "Insert-only", "Prevents duplicate VR items and re-opening closed ones."],
      ["Default Opus 4.8, opt into Fable 5", "Default Fable", "Opus is the right default; Fable reserved for hardest chaining, auto-enables fallbacks."],
    ],
    [2500, 2700, 4160]),

  H1("8. Security & privacy"),
  P("The formal DFD set (context / logical / physical with trust boundaries and a per-boundary data-crossing table) is docs/DATAFLOW.md; the AI-governance control mapping is docs/GOVERNANCE.md; the change and release procedure is docs/RELEASING.md."),
  ...bullets([
    "What leaves the environment — the exploitability, threat-modeling, dedup, and enrichment stages send finding metadata (titles, CVEs, package coordinates, descriptions, deterministic signals) to the model API, not source code. The exception is the built-in OpenHack engine, whose whole purpose is whitebox review: it sends selected first-party source file contents (off unless openhack.auto; bounded by max_files/max_file_bytes). Stricter deployments can run --no-ai, disable OpenHack while keeping the metadata-only stages, or route to an approved deployment.",
    "Secrets — all credentials are injected via env vars / ${ENV} interpolation; none are committed. .gitignore excludes .env and generated output. Optionally fetched from HashiCorp Vault (vault.enabled, vault.py): KV secrets are injected into the environment before interpolation (token or AppRole auth, KV v1/v2, existing env wins unless override_env); Vault's own bootstrap creds come from the environment.",
    "Refusal handling — on Fable/Mythos the client opts into server-side fallbacks so a false-positive classifier refusal is transparently re-served; a genuine refusal surfaces as an error and deterministic scoring still stands.",
    "Least privilege — Bitbucket read, ServiceNow write to the import table only, scanner tokens read-only.",
    "Idempotency as integrity — correlation_id upserts prevent a misfired run from flooding VR with duplicates.",
    "Optional API-token guard — CODESCAN_API_TOKEN guards /api/* (Authorization: Bearer, X-API-Token, or a cookie set from /?token=) with a constant-time compare; healthz and the static shell stay open. Defense in depth for accidental exposure; SSO/RBAC belongs at the reverse proxy.",
    "Fail-loud config — config models reject unknown keys (extra=forbid), so a misspelled security setting fails at load rather than silently reverting to a default.",
    "Append-only audit log -> SIEM (audit.py) — scan runs, config changes, and validation-state changes are recorded with an actor + UTC timestamp: a durable decision record distinct from operational logs. Events fan out to configurable sinks: a local JSONL file (default; tail-able, source for GET /api/audit and the UI Audit tab) plus optional syslog (Splunk/QRadar/ArcSight) and HTTP (Splunk HEC / Elastic / webhook) sinks for direct SIEM ingestion; push is best-effort (a sink failure is logged, never raised). Actor is best-effort from an SSO/reverse-proxy identity header (X-Remote-User / X-Forwarded-User).",
  ]),

  H1("9. Failure modes & resilience"),
  table(
    ["Failure", "Behavior"],
    [
      ["KEV/EPSS feed unreachable", "Treated as empty; run continues on CVSS/AI/reachability."],
      ["LLM refuses (genuine)", "Raised as an error; deterministic scoring already stands."],
      ["LLM refuses (false positive, Fable)", "Auto re-served by the fallback model in the same call."],
      ["Connector 429/5xx", "Retried with backoff in HttpClient."],
      ["Malformed scanner export", "Per-record normalization is defensive; unknown fields ignored."],
      ["One repo's AI call fails", "Isolated by resilient_map — logged and skipped; other repos still complete."],
      ["ServiceNow push fails", "File is written first (durable); push isolates per-record failures and logs an ok/failed summary."],
      ["Crash mid state-store write", "Atomic temp-file + os.replace — the previous state is never truncated."],
    ],
    [3400, 5960]),
  P("The AI stages are strictly additive: with use_ai=False the pipeline produces a complete, scored, exportable result. AI enriches; it is never a hard dependency."),

  H1("10. Scalability"),
  ...bullets([
    "Ingestion paginates all three sources; dedup/enrichment/scoring are O(n log n) in memory; EPSS lookups are batched (100 CVEs/request).",
    "LLM calls are the cost/latency driver but are bounded by service, not finding count — a repo with 500 findings is one exploitability call, not 500. Lower-cost routing keeps mechanical calls inexpensive.",
    "Horizontal path: the per-service AI calls are embarrassingly parallel — run concurrently (ai.max_concurrency) for latency, or via the Message Batches API (ai.batch) for ~50% cost on scheduled runs.",
  ]),

  H1("11. Known limitations & future work"),
  ...bullets([
    "Repo mapping is slug-based; production should map via explicit metadata (tags, build properties).",
    "Reachability is a metadata heuristic; feeding real call-graph / reachable-vuln data would sharpen both the AI judgement and the exposure score.",
    "SCA-oriented fingerprint; SAST findings need path/line — a finding_kind discriminator would switch granularity.",
    "State store is a JSON file; a shared datastore is needed for concurrent runners / HA.",
    "Single-instance runtime — the web server holds scan state in memory, so it runs as one replica. The shipped Dockerfile / docker-compose.yml deploy a single non-root container that writes runtime artifacts to a /data volume, with secrets injected via environment. Horizontal scale needs the shared datastore above.",
    "AI cost/latency — per-service calls run with bounded parallelism (ai.max_concurrency) or, for ~50% cost on scheduled runs, the Message Batches API (ai.batch); both via complete_json_many.",
    "ServiceNow field mapping targets a generic import; align it to each deployment's VR transform map.",
    "Web UI auth is a single shared token (CODESCAN_API_TOKEN), not per-user authn/z; front the dashboard with SSO for identity/RBAC.",
  ]),

  H1("12. Testing"),
  ...bullets([
    "Deterministic pipeline (tests/test_pipeline.py) — offline over fixtures: cross-scanner dedup, corroboration, reachability-driven scoring, validation states, ServiceNow shape, persistent closures.",
    "Model router (tests/test_llm_router.py) — pure resolution logic (Haiku default, fallback, override precedence, partial-override inheritance) plus auto-route (up/down ladder shift, end-clamping, custom-model and non-Anthropic passthrough).",
    "OpenHack engine (tests/test_openhack_engine.py) — file selection, dependency-dir skipping, min-confidence, and multi-pass union + cross-pass agreement with a stubbed LLM; connector tag-merge in test_openhack.py.",
    "Concurrency (tests/test_concurrency.py) — order preservation, genuine parallelism (barrier), single-item sequential fallback, and per-item failure isolation (resilient_map).",
    "Batches API (tests/test_batch.py) — complete_json_many sync vs batch path, Fable/non-Anthropic exclusion, batch-error fallback to sync, and AnthropicProvider.complete_json_batch collection with a fake batches client.",
    "ServiceNow (tests/test_servicenow.py) — JSON/CSV output and the Table API push path (posts each record; a failing push doesn't abort the export).",
    "State store (tests/test_validation.py) — atomic save round-trip, no temp leftover, crash-during-replace preserves the existing file, machine-belief snapshot capture, analyst-note round-trip, legacy (pre-snapshot) entries loading cleanly, and chain decisions (round-trip, annotation, dismissed-chain exclusion, lifecycle states rejected).",
    "SQL state store (tests/test_state_store_sql.py) — backend factory, round-trip/persistence (incl. snapshots), manual-not-clobbered-by-machine concurrency guard, the pre-snapshot schema upgrading in place, feedback over SQL, and a pipeline run persisting to SQLite.",
    "Calibration (tests/test_calibration.py) — bucket/rate math, accuracy states only, noisy-key surfacing, legacy decisions counted but unbucketed, chain decisions excluded, the empty-store zeroed report, and drift alerts (precision + separation checks, evidence gate, disabled/healthy silence); endpoint coverage in test_web.py and the scan-time calibration.drift audit event in test_pipeline.py.",
    "Enterprise / Fable 5 (tests/test_enterprise.py) — inference_geo threaded onto requests, Fable's data-retention 400 re-raised actionably, and the enterprise config profile routing deep tasks to Fable / mechanical to Haiku.",
    "Vault (tests/test_vault.py) — KV v1/v2 injection, override semantics, auth errors, and the Config.load wiring.",
    "Audit log (tests/test_audit.py) — record/tail JSONL round-trip, disabled no-op, pipeline scan events, web actor-attributed config/state events via GET /api/audit, and the SIEM sinks (HTTP POST incl. HEC event_key, sink-failure isolation, syslog smoke, bad-sink survivability).",
    "Feedback loop (tests/test_feedback.py) — false-positive history lowers / confirmed raises the score, min-evidence gate, self-exclusion, KEV-floor respect, disabled no-op, accuracy-states-only, store attribute round-trip, evidence weighting (shrinkage growth, time decay, same-repo boost), and TriageHistory prompt-context counts and analyst notes (labeled, capped).",
    "Exploitability engine (tests/test_exploitability.py) — fake-LLM prompt assembly: results applied to findings/chains, prior_analyst_decisions carried with the right counts, omitted when there's no history or the feature is off.",
    "Web API (tests/test_web.py) — FastAPI TestClient over state, scan, state-change (persisted across rescan), validation, ServiceNow, and the API-token guard.",
    "All tests run offline with no Anthropic key; AI stages are validated by contract (schema) rather than live calls. CI (.github/workflows/ci.yml) runs ruff + mypy + pytest on a 3.10-3.12 matrix and builds the image on every push/PR; mypy is a clean gate and the package ships py.typed.",
  ]),

  H1("13. Configuration surface"),
  ...bullets([
    "ai — default tier + per-task routing (tasks.<name>), plus max_concurrency (bounded parallelism), auto_route (silent adaptive tier selection), batch (Message Batches API, ~50% cost), and inference_geo (Anthropic data residency). See config/config.enterprise.yaml for a Fable-5 enterprise profile.",
    "source / bitbucket / github — repo inventory (scan surface), tokens, scoping, TLS.",
    "snyk / xray — findings endpoints, tokens, TLS.",
    "openhack — whitebox review: enabled/findings_dir (ingest), auto/clone/command (run), and built-in-engine tuning (passes, pass_models for per-pass suppliers, max_files, max_file_bytes, min_confidence).",
    "servicenow — instance, credentials, push toggle, import table, format.",
    "vault — optional HashiCorp Vault secret source: enabled, address, auth (token/approle), kv_mount/kv_version, paths, override_env.",
    "feedback — analyst-feedback loop: enabled, max_adjust, min_evidence, shrinkage, half_life_days, same_repo_boost (score prior), prompt_history (triage history into the AI prompt).",
    "calibration — drift alerting: alerts_enabled, min_bucket_decisions, min_high_confirm_rate, min_separation.",
    "storage — validation-state backend: backend (file/sql) + dsn (SQLAlchemy URL).",
    "audit — append-only audit log: enabled, path (file sink), and syslog / http sinks for SIEM ingestion.",
    "enrichment — KEV/EPSS feed URLs + per-enricher toggles.",
    "threat_model — enabled.",
    "scoring — dimension weights + kev_floor.",
    "CLI: codescan scan (pipeline), codescan serve (UI), codescan summary (inspect an export). Flags gate AI (--no-ai / --ai), enrichment (--offline), and live vs fixtures (--live / --fixtures).",
  ]),
];

const doc = new Document({
  creator: "codescan",
  title: "codescan — Design Document",
  features: { updateFields: true },
  styles: {
    default: {
      document: { run: { font: "Calibri", size: 22, color: "1F2937" } },
    },
  },
  sections: [{
    properties: {
      page: {
        size: { width: 12240, height: 15840 },
        margin: { top: 1440, right: 1440, bottom: 1440, left: 1440 },
      },
    },
    children,
  }],
});

const out = path.join(HERE, "DESIGN.docx");
Packer.toBuffer(doc).then((buf) => {
  fs.writeFileSync(out, buf);
  console.log(`wrote ${out} (${buf.length} bytes)`);
});
