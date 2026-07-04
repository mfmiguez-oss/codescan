"""Canonical data model shared across every scanner and downstream stage.

Snyk and Xray describe the same underlying vulnerability in different shapes.
Everything is normalized into `Finding` so dedup, scoring, and export operate on
one consistent representation regardless of which tool reported it.
"""

from __future__ import annotations

import hashlib
from datetime import datetime, timezone
from enum import Enum

from pydantic import BaseModel, Field


class Severity(str, Enum):
    critical = "critical"
    high = "high"
    medium = "medium"
    low = "low"
    info = "info"

    @property
    def rank(self) -> int:
        return {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}[self.value]

    @classmethod
    def from_cvss(cls, score: float | None) -> "Severity":
        if score is None:
            return cls.info
        if score >= 9.0:
            return cls.critical
        if score >= 7.0:
            return cls.high
        if score >= 4.0:
            return cls.medium
        if score > 0.0:
            return cls.low
        return cls.info


class Source(str, Enum):
    snyk = "snyk"
    xray = "xray"


class ValidationState(str, Enum):
    """Internal triage lifecycle. Maps to ServiceNow VR states on export."""

    new = "new"                       # never triaged
    under_investigation = "under_investigation"
    confirmed = "confirmed"           # real, exploitable in our context
    false_positive = "false_positive"
    risk_accepted = "risk_accepted"
    duplicate = "duplicate"           # merged into another finding
    resolved = "resolved"             # fixed / no longer present


# ServiceNow Vulnerability Response "Vulnerable Item" state values.
SERVICENOW_STATE = {
    ValidationState.new: "Open",
    ValidationState.under_investigation: "Under Investigation",
    ValidationState.confirmed: "Open",
    ValidationState.false_positive: "Closed / False Positive",
    ValidationState.risk_accepted: "Closed / Risk Accepted",
    ValidationState.duplicate: "Closed / Duplicate",
    ValidationState.resolved: "Closed / Fixed",
}


class Repo(BaseModel):
    """A Bitbucket repository — the unit of scan surface."""

    project_key: str
    slug: str
    name: str
    clone_url: str
    default_branch: str = "main"

    @property
    def full_name(self) -> str:
        return f"{self.project_key}/{self.slug}"


class Component(BaseModel):
    """The affected software component (dependency or first-party module)."""

    name: str
    version: str | None = None
    ecosystem: str | None = None          # npm, maven, pypi, ...
    purl: str | None = None               # package URL, when derivable


class Location(BaseModel):
    """Where the finding lives in the repo."""

    repo: str                             # "PROJECT/slug"
    path: str | None = None               # manifest or source file
    start_line: int | None = None
    branch: str | None = None


class Exploitability(BaseModel):
    """Output of the exploitability engine for a single finding."""

    level: Severity = Severity.info       # reuse the severity scale for level
    score: float = 0.0                    # 0-100
    reachable: bool | None = None         # is the vulnerable code path reachable
    in_kev: bool = False                  # CISA Known Exploited Vulnerabilities
    epss: float | None = None             # FIRST EPSS probability 0-1
    rationale: str = ""
    chain_ids: list[str] = Field(default_factory=list)


class Finding(BaseModel):
    """One vulnerability instance, normalized across scanners."""

    id: str = ""                          # deterministic fingerprint
    source: Source
    source_ref: str                       # scanner-native id (issue id, violation id)
    title: str
    cve_ids: list[str] = Field(default_factory=list)
    cwe_ids: list[str] = Field(default_factory=list)
    severity: Severity = Severity.info
    cvss_score: float | None = None
    cvss_vector: str | None = None
    component: Component
    location: Location
    fixed_in: list[str] = Field(default_factory=list)
    description: str = ""
    references: list[str] = Field(default_factory=list)

    # Populated by later stages.
    exploitability: Exploitability = Field(default_factory=Exploitability)
    remediation: str = ""                  # enrichment: how to fix
    tags: list[str] = Field(default_factory=list)   # enrichment: categorization
    risk_score: float = 0.0
    validation_state: ValidationState = ValidationState.new
    merged_sources: list[Source] = Field(default_factory=list)
    first_seen: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

    def fingerprint(self) -> str:
        """Stable identity used for dedup and idempotent ServiceNow upserts.

        Two findings collide when they describe the same weakness in the same
        place: same CVE (or CWE+title when no CVE), same package, same repo path.
        Scanner identity is intentionally excluded so Snyk and Xray merge.
        """
        vuln_key = (
            ",".join(sorted(self.cve_ids))
            or ",".join(sorted(self.cwe_ids))
            or self.title.strip().lower()
        )
        # Key on component identity, not the scanner-specific purl string (Snyk
        # emits a purl, Xray often doesn't) — normalized name@version aligns both.
        comp_key = f"{self.component.name}@{self.component.version or ''}"
        # Repo-level, not path-level: Snyk reports the manifest path while Xray
        # reports the artifact coordinate for the same dependency. For SCA
        # findings the repo is the right dedup granularity.
        loc_key = self.location.repo
        raw = f"{vuln_key}|{comp_key}|{loc_key}".lower()
        return hashlib.sha256(raw.encode()).hexdigest()[:32]

    def ensure_id(self) -> "Finding":
        if not self.id:
            self.id = self.fingerprint()
        if not self.merged_sources:
            self.merged_sources = [self.source]
        return self


# --- Threat modeling (service-level synthesis of the findings) -------------

class Stride(str, Enum):
    """STRIDE threat categories."""

    spoofing = "spoofing"
    tampering = "tampering"
    repudiation = "repudiation"
    information_disclosure = "information_disclosure"
    denial_of_service = "denial_of_service"
    elevation_of_privilege = "elevation_of_privilege"


class Asset(BaseModel):
    name: str
    sensitivity: str = ""             # high | medium | low, or a short note


class EntryPoint(BaseModel):
    name: str
    description: str = ""


class Threat(BaseModel):
    id: str
    title: str
    stride: Stride
    description: str = ""
    likelihood: str = ""              # high | medium | low
    impact: str = ""
    related_finding_ids: list[str] = Field(default_factory=list)
    related_chain_ids: list[str] = Field(default_factory=list)
    mitigations: list[str] = Field(default_factory=list)


class ThreatModel(BaseModel):
    """Per-service threat model derived from that service's findings and chains."""

    service: str                      # repo full name
    assets: list[Asset] = Field(default_factory=list)
    entry_points: list[EntryPoint] = Field(default_factory=list)
    trust_boundaries: list[str] = Field(default_factory=list)
    threats: list[Threat] = Field(default_factory=list)
    posture_summary: str = ""
    risk_level: str = ""              # critical | high | medium | low
    recommendations: list[str] = Field(default_factory=list)
