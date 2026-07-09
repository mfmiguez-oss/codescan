from __future__ import annotations

from codescan.models import Finding, Source, group_findings_by_repo


def _finding(repo: str, fid: str) -> Finding:
    return Finding(
        id=fid,
        source=Source.snyk,
        source_ref=fid,
        title=f"Finding {fid}",
        component={"name": "pkg", "version": "1.0"},
        location={"repo": repo, "path": "requirements.txt"},
    )


def test_group_findings_by_repo_groups_by_service():
    findings = [_finding("org/service-a", "a"), _finding("org/service-b", "b"), _finding("org/service-a", "c")]

    grouped = group_findings_by_repo(findings)

    assert list(grouped) == ["org/service-a", "org/service-b"]
    assert [f.id for f in grouped["org/service-a"]] == ["a", "c"]
    assert [f.id for f in grouped["org/service-b"]] == ["b"]
