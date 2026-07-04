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
    "A validation lifecycle that survives re-scans (analyst decisions are sticky).",
    "Output shaped for ServiceNow VR with idempotent upserts.",
    "Cost-appropriate model use: cheap models for mechanical work, deep models for reasoning.",
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
      ["Code in local Bitbucket", "connectors/bitbucket.py — on-prem REST API builds the repo inventory (scan surface)."],
      ["Snyk + Xray available", "connectors/snyk.py, connectors/xray.py — live pull or offline export, normalized to one Finding."],
      ["Output for ServiceNow Vulnerabilities", "servicenow.py — sn_vul_vulnerable_item records, idempotent via correlation_id."],
      ["Validation states", "validation.py + models.py — lifecycle + sticky state store + VR state mapping."],
      ["Deduplication", "dedup.py (deterministic) + dedup_ai.py (semantic, cheap tier)."],
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
      ["Connectors", "connectors/", "Talk to external systems; emit/consume raw scanner shapes."],
      ["Domain model", "models.py", "Canonical Finding, fingerprinting, state enums."],
      ["Processing", "dedup*.py, enrich/, exploitability.py, scoring.py, validation.py", "Transform findings."],
      ["AI infrastructure", "llm.py", "Model routing + structured-output client."],
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
  P("All three extend a shared HttpClient (bearer auth, retry/backoff on 429/5xx, paging). Each has two ingestion paths: fetch() for a live API pull and from_file() for a native scanner export. The offline path is not just for demos — it makes the pipeline runnable in CI, in tests, and against archived scan data with zero credentials. Repo mapping (Snyk projects / Xray builds back to Bitbucket repos) is the documented integration point to harden for production."),
  H2("5.2 Deduplication (two passes)"),
  ...bullets([
    "Deterministic (dedup.py) — group by fingerprint, merge collisions. The merge keeps the higher-severity record as primary, unions CVEs/CWEs/references/fixes, prefers a present CVSS and the longer description, and records provenance from every contributing scanner. A finding seen by both scanners earns a corroboration bonus in scoring.",
    "Semantic (dedup_ai.py, optional, cheap tier) — catches cross-scanner duplicates the fingerprint misses (same weakness, divergent identifiers). Deliberately narrow: only compares findings in the same repo + same component, and only merges what the model marks as clearly the same vulnerability.",
  ]),
  H2("5.3 Enrichment (pluggable framework)"),
  P("Enrichment is a framework, not a fixed step. Each source is a BaseEnricher (enrich/) with an enrich(findings) method; build_enrichers assembles the enabled ones from config and runs them in order. Adding a source (VEX, asset criticality, exploit-DB) is a new subclass with no pipeline change."),
  ...bullets([
    "CISA KEV — is the CVE actively exploited in the wild?",
    "FIRST EPSS — probability of exploitation (batched lookups).",
    "Reachability — heuristic over scanner metadata; True/False/unknown (negative phrasing checked first).",
    "AI enrichment (optional, cheap tier) — remediation guidance + categorization tags, plus a reachability judgement when the scanner gave none. Complements the exploitability engine; routed to the enrichment task (Haiku by default).",
  ]),
  P("Deterministic enrichers run first — cheap, authoritative, and grounding for the LLM stages. Each is toggleable in config and from the config UI. Network failures degrade gracefully rather than failing the run."),
  H2("5.4 Exploitability & chaining engine"),
  P("exploitability.py is the core value-add. Per service, it sends the LLM the finding set plus the deterministic signals and asks two things: (1) per-finding exploitability in our context (0-100), weighting actively-exploited / high-EPSS / reachable issues up and unreachable / fixed issues down; and (2) attack chains — ordered sequences of findings that combine into greater impact (e.g. SSRF reaches an internal service carrying an unauthenticated RCE), each with narrative, preconditions, impact, likelihood, chain score, and MITRE ATT&CK mapping."),
  ...bullets([
    "Grounded, not recalled — the model reasons over KEV/EPSS/CVSS/reachability facts, so its judgement is about our exposure.",
    "Structured output — a JSON Schema guarantees a parseable response; no prompt-scraping.",
    "Per-service scoping — chaining is scoped to a repo/service, which keeps requests tractable and chains meaningful.",
  ]),
  H2("5.5 Model routing (llm.py)"),
  P("Different tasks need different intelligence tiers. ModelRouter resolves a task name to a ModelSpec (model + effort + token budget); LLMClient adapts each request to the model's capabilities so callers never have to."),
  table(
    ["Task", "Default tier", "Rationale"],
    [
      ["dedup", "Haiku 4.5", "Mechanical \"same vuln?\" judgement."],
      ["exploitability", "Opus 4.8 (Fable 5 for hardest chaining)", "Deep, judgement-heavy reasoning."],
      ["(other)", "default tier (ai.model)", "Fallback."],
    ],
    [2000, 3200, 4160]),
  P("The client omits effort / adaptive thinking for models that don't support them (Haiku) and enables server-side refusal fallbacks for Fable/Mythos (security tooling can trip false-positive classifier refusals; the request transparently re-serves on Opus 4.8). Config ai.tasks.<name> overrides any field per task. Adding a new AI stage is a one-liner."),
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
  P("Adjustments on top of the blend: a KEV floor (anything actively exploited is floored to 85), a corroboration bonus (+2 when both scanners agree), and a threat boost — an additive bonus (up to threat_boost, default 15) for findings implicated by the service threat model, scaled by the stronger of the finding's threat signal and its service posture (5.10). Additive, so runs without threat modeling aren't penalized; threats also enrich the exploitability dimension directly. This is what makes the queue useful: an unreachable critical drops below a reachable, chainable, threatened high."),
  H2("5.7 Validation states (validation.py)"),
  P("Internal lifecycle mapped to ServiceNow VR states on export: new -> under_investigation -> confirmed / false_positive / risk_accepted / duplicate / resolved. The pipeline proposes a conservative initial state; a human confirms or overrides. Stickiness is the important property: the StateStore persists each decision keyed by fingerprint and tags whether a human set it. On re-scan, any manual decision or terminal closure is honored and never re-opened — analyst effort is never silently discarded."),
  H2("5.8 ServiceNow export (servicenow.py)"),
  P("Builds sn_vul_vulnerable_item records, highest-risk first, carrying the composite score, risk rating, validation state, and the exploitability rationale plus attack-chain context in the work notes — so a responder sees why the tool ranked it. correlation_id is the fingerprint, making the import idempotent: re-runs upsert the same item and closed items stay closed. Output is written to a file — JSON (servicenow_import.json) or, when servicenow.format is csv, a CSV (servicenow_import.csv) for CSV Import Sets, with multi-line work notes quoted correctly — or POSTed to the import table via the Table API. The format is settable in config, the config UI, or with --sn-format on the CLI."),
  H2("5.9 Web UI (web.py + static/index.html)"),
  P("A FastAPI backend holds the latest result in memory; the frontend is a single dependency-free HTML page with three views. Findings: the triage queue with filters, signal badges, a per-finding detail drawer (CVSS vector, EPSS, reachability, provenance, rationale, remediation, tags, threats, chains), and inline validation-state editing that persists to the sticky store."),
  P("Threats: the per-service threat models (5.10) — STRIDE threats with linked findings/chains, assets, entry points, trust boundaries, posture, and recommendations."),
  P("Config: edit non-secret settings live — default AI tier, per-task model routing, enrichment toggles, threat-modeling toggle, scoring weights, and the ServiceNow push flag. Secrets are shown masked and read-only (they stay in the environment). Edits apply to the next scan and persist to config.overrides.json, layered over the base config on restart; POST is validated server-side and rejected with 400 on bad input."),

  H2("5.10 Threat modeling (threatmodel.py, optional, deep tier)"),
  P("Where the exploitability engine works bottom-up (per-finding scores, concrete chains), threat modeling is the top-down counterpart. Per service it produces a STRIDE threat model grounded in that service's findings and chains:"),
  ...bullets([
    "Assets — what an attacker targets (data, credentials, functionality) with a sensitivity note.",
    "Entry points / trust boundaries — the attack surface implied by the components and findings.",
    "Threats — STRIDE-categorized, each citing the related finding IDs and chain IDs that evidence it, plus likelihood, impact, and mitigations. Prefer fewer, well-grounded threats over generic ones.",
    "Posture — an overall risk level, summary, and prioritized recommendations.",
  ]),
  P("Optional (threat_model.enabled), per-service, routed to the threat_model task (the default deep tier unless overridden), and emits a threat_models.json artifact alongside the ServiceNow export. Threats reference findings by ID, so the UI cross-links both directions."),
  P("It feeds back into scoring. Because it runs before the scorer, apply_threat_influence writes results back onto findings: it records the citing threat IDs, derives a per-finding threat signal (0-100 from the strongest citing threat's likelihood), and raises the categorical exploitability level when the threat implies more than the isolated assessment did. The scorer then consumes the threat signal (exploitability dimension) and the per-service risk posture (additive threat boost)."),

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
      ["Composite score with KEV floor", "Rank by CVSS", "CVSS mis-ranks; the blend + floor surface exploited/chainable issues."],
      ["Sticky, human-tagged states", "Recompute every run", "Analyst decisions survive re-scans; proposals stay re-derivable."],
      ["Idempotent export via correlation_id", "Insert-only", "Prevents duplicate VR items and re-opening closed ones."],
      ["Default Opus 4.8, opt into Fable 5", "Default Fable", "Opus is the right default; Fable reserved for hardest chaining, auto-enables fallbacks."],
    ],
    [2500, 2700, 4160]),

  H1("8. Security & privacy"),
  ...bullets([
    "What leaves the environment — the exploitability engine sends finding metadata (titles, CVEs, package coordinates, descriptions, deterministic signals) to the Anthropic API, not source code. Stricter deployments can run --no-ai (fully deterministic) or route to an approved Anthropic deployment.",
    "Secrets — all credentials are injected via env vars / ${ENV} interpolation; none are committed. .gitignore excludes .env and generated output.",
    "Refusal handling — on Fable/Mythos the client opts into server-side fallbacks so a false-positive classifier refusal is transparently re-served; a genuine refusal surfaces as an error and deterministic scoring still stands.",
    "Least privilege — Bitbucket read, ServiceNow write to the import table only, scanner tokens read-only.",
    "Idempotency as integrity — correlation_id upserts prevent a misfired run from flooding VR with duplicates.",
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
      ["ServiceNow push fails", "Records are written to file first, then pushed; the file is the durable artifact."],
    ],
    [3400, 5960]),
  P("The AI stages are strictly additive: with use_ai=False the pipeline produces a complete, scored, exportable result. AI enriches; it is never a hard dependency."),

  H1("10. Scalability"),
  ...bullets([
    "Ingestion paginates all three sources; dedup/enrichment/scoring are O(n log n) in memory; EPSS lookups are batched (100 CVEs/request).",
    "LLM calls are the cost/latency driver but are bounded by service, not finding count — a repo with 500 findings is one exploitability call, not 500. Cheap-tier routing keeps mechanical calls inexpensive.",
    "Horizontal path: the per-service AI calls are embarrassingly parallel; batching or the Batches API is the natural next step for very large estates.",
  ]),

  H1("11. Known limitations & future work"),
  ...bullets([
    "Repo mapping is slug-based; production should map via explicit metadata (tags, build properties).",
    "Reachability is a metadata heuristic; feeding real call-graph / reachable-vuln data would sharpen both the AI judgement and the exposure score.",
    "SCA-oriented fingerprint; SAST findings need path/line — a finding_kind discriminator would switch granularity.",
    "State store is a JSON file; a shared datastore is needed for concurrent runners / HA.",
    "AI concurrency — per-service calls are serial today; parallelizing or the Batches API would cut wall-clock time.",
    "ServiceNow field mapping targets a generic import; align it to each deployment's VR transform map.",
    "No auth on the web UI; add authn/authz before exposing it beyond a trusted network.",
  ]),

  H1("12. Testing"),
  ...bullets([
    "Deterministic pipeline (tests/test_pipeline.py) — offline over fixtures: cross-scanner dedup, corroboration, reachability-driven scoring, validation states, ServiceNow shape, sticky closures.",
    "Model router (tests/test_llm_router.py) — pure resolution logic (Haiku default, fallback, override precedence, partial-override inheritance).",
    "Web API (tests/test_web.py) — FastAPI TestClient over state, scan, state-change (sticky across rescan), validation, and ServiceNow endpoints.",
    "All tests run offline with no Anthropic key; AI stages are validated by contract (schema) rather than live calls.",
  ]),

  H1("13. Configuration surface"),
  ...bullets([
    "ai — default tier + per-task routing (tasks.dedup, tasks.exploitability).",
    "bitbucket / snyk / xray — endpoints, tokens, project scoping, TLS.",
    "servicenow — instance, credentials, push toggle, import table.",
    "enrichment — KEV/EPSS feed URLs.",
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
