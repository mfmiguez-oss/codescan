from __future__ import annotations

from codescan.models import (
    Finding, Severity, Source, chain_fingerprint, group_difficulty,
    group_findings_by_repo, size_difficulty,
)


def test_chain_fingerprint_is_order_independent():
    assert chain_fingerprint(["b", "a", "c"]) == chain_fingerprint(["c", "a", "b"])
    assert chain_fingerprint(["a", "b"]) != chain_fingerprint(["a", "c"])
    assert len(chain_fingerprint(["a"])) == 32


def _finding(repo: str, fid: str, *, severity: Severity = Severity.medium, kev: bool = False) -> Finding:
    f = Finding(
        id=fid,
        source=Source.snyk,
        source_ref=fid,
        title=f"Finding {fid}",
        severity=severity,
        component={"name": "pkg", "version": "1.0"},
        location={"repo": repo, "path": "requirements.txt"},
    )
    f.exploitability.in_kev = kev
    return f


def test_group_findings_by_repo_groups_by_service():
    findings = [_finding("org/service-a", "a"), _finding("org/service-b", "b"), _finding("org/service-a", "c")]

    grouped = group_findings_by_repo(findings)

    assert list(grouped) == ["org/service-a", "org/service-b"]
    assert [f.id for f in grouped["org/service-a"]] == ["a", "c"]
    assert [f.id for f in grouped["org/service-b"]] == ["b"]


def test_group_difficulty_buckets():
    # Single low/medium finding -> trivial (downgrade).
    assert group_difficulty([_finding("r", "a")]) == "low"
    assert group_difficulty([]) == "low"
    # A couple of mediums -> normal (no change).
    assert group_difficulty([_finding("r", "a"), _finding("r", "b")]) == "normal"
    # KEV forces high (upgrade) even for one finding.
    assert group_difficulty([_finding("r", "a", kev=True)]) == "high"
    # Several high-severity findings -> high.
    highs = [_finding("r", str(i), severity=Severity.high) for i in range(3)]
    assert group_difficulty(highs) == "high"
    # Large group -> high regardless of severity.
    assert group_difficulty([_finding("r", str(i)) for i in range(8)]) == "high"


def test_size_difficulty_buckets():
    assert size_difficulty(1) == "low"
    assert size_difficulty(2) == "low"
    assert size_difficulty(4) == "normal"
    assert size_difficulty(6) == "high"
