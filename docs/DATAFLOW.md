# codescan — Data Flow Diagrams (DFDs)

The formal DFD set for audit and governance use: **context** (level 0),
**logical** (level 1), and **physical** (deployment + trust boundaries).
Narrative documentation of the same flows lives in [DESIGN.md](DESIGN.md)
(§5 component design, §6 scan sequence, §8 security & privacy); the rendered
architecture diagram is [architecture.svg](architecture.svg). This document is
the *what data moves where* reference — including what crosses each trust
boundary and where data comes to rest.

## 1. Context DFD (level 0)

The system and its external entities. Every arrow is a data flow; credentials
for each flow are environment/Vault-sourced and never persisted by codescan.

```mermaid
flowchart LR
  AN(["Analyst / SOC"]) -->|"triage decisions, notes,<br/>chain confirm/dismiss, config edits"| CS
  CS -->|"dashboards, rationales,<br/>calibration report"| AN

  SCM(["Bitbucket / GitHub"]) -->|"repo inventory<br/>+ source files, OpenHack only"| CS["codescan"]
  SNYK(["Snyk"]) -->|"SCA findings"| CS
  XRAY(["JFrog Xray"]) -->|"artifact findings"| CS
  KEV(["CISA KEV"]) -->|"exploited-CVE catalog"| CS
  EPSS(["FIRST EPSS"]) -->|"exploit probabilities"| CS

  CS -->|"finding metadata digests<br/>+ source excerpts, OpenHack only"| AI(["Microsoft Foundry:<br/>Claude / GPT / Gemini / Mistral"])
  AI -->|"structured assessments:<br/>scores, chains, threat models"| CS

  VLT(["HashiCorp Vault"]) -->|"secrets, at startup"| CS
  CS -->|"vulnerable items<br/>scores, states, rationales"| SN(["ServiceNow VR"])
  CS -->|"audit events<br/>scans, config, triage, drift"| SIEM(["SIEM: syslog / HTTP HEC"])
```

## 2. Logical DFD (level 1)

Processes (P), data stores (D), and the flows between them for one scan.
Multilevel detail per process is in DESIGN.md §5.1–§5.10.

```mermaid
flowchart TB
  subgraph collection ["Collection"]
    P1["P1 ingest<br/>connectors/"] --> P2["P2 normalize + dedup<br/>models.py, dedup*.py"]
  end
  subgraph enrichment ["Enrichment"]
    P2 --> P3["P3 enrich<br/>KEV / EPSS / reachability"]
  end
  subgraph reasoning ["AI reasoning"]
    P3 --> P4["P4 exploitability + chains<br/>exploitability.py"]
    P4 --> P5["P5 threat models<br/>threatmodel.py"]
  end
  subgraph decisioning ["Decisioning"]
    P5 --> P6["P6 composite score<br/>scoring.py"]
    P6 --> P7["P7 feedback prior<br/>feedback.py"]
    P7 --> P8["P8 validation states<br/>validation.py"]
    P8 --> P9["P9 calibration + drift<br/>calibration.py"]
  end
  P8 --> P10["P10 export<br/>servicenow.py"]

  D1[("D1 validation state store<br/>JSON file or SQL")] -->|"prior decisions: history<br/>for prompt + prior"| P4
  D1 -->|"accuracy history"| P7
  P8 -->|"states + snapshots + notes"| D1
  D1 -->|"graded history"| P9
  P9 -->|"calibration.drift events"| D2[("D2 audit log<br/>JSONL to SIEM")]
  P1 -->|"scan events"| D2
  P8 -->|"triage events"| D2
  P10 -->|"export events"| D2
  P5 --> D3[("D3 threat_models.json")]
  P10 --> D4[("D4 servicenow_import.json/csv")]
  D5[("D5 config + overrides")] -->|"settings"| P1
```

Key learning-loop flows (the closed loop): analyst decisions land in **D1**
with a machine-belief snapshot and optional note → **P4** receives them as
`prior_analyst_decisions` prompt context on similar findings → **P7** nudges
scores from the weighted history → **P9** grades predictions against outcomes
and raises drift to **D2**.

## 3. Physical DFD — deployment and trust boundaries

What crosses each boundary, over what, carrying what. All egress is HTTPS/TLS;
scanner and SCM tokens are read-only, ServiceNow write is scoped to the import
table (DESIGN.md §8, least privilege).

```mermaid
flowchart LR
  subgraph org ["Trust boundary: organization network"]
    subgraph host ["codescan container / host"]
      APP["FastAPI + pipeline"]
    end
    FS[("state store: validation_state.json<br/>or Postgres via storage.dsn")]
    AUD[("audit.jsonl — append-only")]
    ART[("run artifacts: servicenow_import,<br/>threat_models.json, overrides")]
    PRX["reverse proxy / SSO"]
    V[("Vault")]
    SIEMBOX["SIEM collector"]
    APP --- FS
    APP --- AUD
    APP --- ART
    PRX -->|"identity header<br/>X-Remote-User"| APP
    V -->|"secrets at startup"| APP
    AUD -->|"syslog / HTTP HEC<br/>best-effort push"| SIEMBOX
  end

  subgraph vendors ["Trust boundary: org-contracted SaaS"]
    BB["Bitbucket / GitHub"]
    SK["Snyk"]
    XR["Xray"]
    SNOW["ServiceNow VR"]
  end

  subgraph aiproviders ["Trust boundary: Microsoft Foundry"]
    ANT["Anthropic Messages API<br/>claude-* deployments"]
    OAI["OpenAI-compatible endpoint<br/>GPT / Gemini / Mistral deployments"]
  end

  subgraph public ["Trust boundary: public internet"]
    KEVSRC["CISA KEV"]
    EPSSSRC["FIRST EPSS"]
  end

  APP -->|"token, read-only: repo list<br/>+ files, OpenHack only"| BB
  APP -->|"token, read-only: findings"| SK
  APP -->|"token, read-only: findings"| XR
  APP -->|"no auth, read-only:<br/>CVE ids only"| KEVSRC
  APP -->|"no auth, read-only:<br/>CVE ids only"| EPSSSRC
  APP -->|"API key: finding METADATA digests, no source code<br/>exception: OpenHack sends selected first-party files"| ANT
  APP -->|"API key: same contract"| OAI
  APP -->|"basic auth, write to<br/>import table only"| SNOW
```

**Data at rest** (all inside the org boundary): the validation state store
(decisions, machine-belief snapshots, analyst notes), the append-only audit
log, threat models, the ServiceNow import file, and config overrides. codescan
persists nothing outside the org boundary; what Microsoft Foundry and
ServiceNow retain is governed by the org's contracts with them (data residency
follows the Azure region of the Foundry resource; DESIGN.md §8 documents the
disable/route-to-approved-deployment options).

**Crossing summary per boundary:**

| Boundary crossed | Data out | Data in | Control |
|---|---|---|---|
| → SaaS scanners/SCM | tokens (headers only) | findings, repo inventory, source (OpenHack) | read-only tokens, TLS |
| → Microsoft Foundry | finding metadata digests, triage-history counts/notes; source files **only** when OpenHack enabled | structured JSON assessments | `--no-ai` / per-stage toggles, Azure region of the resource, bounded file limits |
| → public enrichment | CVE identifiers only | KEV membership, EPSS scores | `--offline` skips entirely |
| → ServiceNow | scored vulnerable items incl. rationales | import results | write scoped to import table, idempotent `correlation_id` |
| → SIEM | audit events (actor, action, timestamps) | — | best-effort push; local file stays durable record |
