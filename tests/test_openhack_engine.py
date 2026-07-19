"""Built-in OpenHack engine — in-process whitebox review, LLM stubbed.

Asserts the engine selects source, batches it, and writes finding-candidate JSON
that the existing OpenHackConnector ingests unchanged (no network / real model).
"""

from __future__ import annotations

from codescan.config import OpenHackConfig, TaskModel
from codescan.connectors import OpenHackConnector
from codescan.llm import ModelSpec
from codescan.models import Severity, Source
from codescan.openhack_engine import OpenHackEngine


class FakeLLM:
    """Stands in for LLMClient — records calls, returns a canned finding.

    `per_call` (optional) supplies a different finding list for each successive
    call, so tests can simulate non-deterministic passes (a finding one pass sees
    and another misses).
    """

    def __init__(self, findings, per_call=None):
        self.findings = findings
        self.per_call = list(per_call) if per_call is not None else None
        self.calls = []

    def resolve_spec(self, task, override=None):
        model = (override.model if override and override.model else "m")
        return ModelSpec("foundry", model, "high", 8000)

    def complete_json(self, task, system, user, schema, **kwargs):
        self.calls.append({"task": task, "user": user, **kwargs})
        if self.per_call is not None:
            return {"findings": self.per_call[len(self.calls) - 1]}
        return {"findings": self.findings}


def _repo_tree(tmp_path):
    (tmp_path / "src").mkdir(parents=True)
    # A file whose name matches a priority hint (reviewed first).
    (tmp_path / "src" / "auth_controller.py").write_text(
        "def login(req):\n    q = \"SELECT * FROM users WHERE u='\" + req['u'] + \"'\"\n",
        encoding="utf-8",
    )
    # A dependency dir that must be skipped.
    (tmp_path / "node_modules").mkdir()
    (tmp_path / "node_modules" / "lib.js").write_text("module.exports = 1;", encoding="utf-8")
    return tmp_path


def test_engine_writes_ingestable_candidates(tmp_path):
    repo = _repo_tree(tmp_path / "repo")
    out = tmp_path / "out"
    llm = FakeLLM([{
        "title": "SQL injection in login", "severity": "high", "confidence": "high",
        "primary_vulnerability_class": "injection", "target_path": "src/auth_controller.py",
        "summary": "User input concatenated into SQL.", "impact": "Auth bypass / data theft.",
        "example_attack": "u=' OR '1'='1", "recommended_fix": "Use parameterized queries.",
    }])

    cfg = OpenHackConfig(auto=True)
    out_dir = OpenHackEngine(llm, cfg).review(repo, out, "acme/checkout")

    # Wrote a finding-candidate the connector ingests to a proper Finding.
    findings = OpenHackConnector().from_dir(out_dir, "acme/checkout")
    assert len(findings) == 1
    f = findings[0].ensure_id()
    assert f.source == Source.openhack
    assert f.severity == Severity.high
    assert f.location.path == "src/auth_controller.py"
    assert f.remediation == "Use parameterized queries."
    assert "openhack" in f.tags and "injection" in f.tags


def test_engine_skips_dependency_dirs(tmp_path):
    repo = _repo_tree(tmp_path / "repo")
    llm = FakeLLM([])
    OpenHackEngine(llm, OpenHackConfig()).review(repo, tmp_path / "out", "a/b")
    # node_modules content is never sent to the model.
    sent = "\n".join(c["user"] for c in llm.calls)
    assert "auth_controller.py" in sent
    assert "node_modules" not in sent and "module.exports" not in sent


def _cand(title, cls="injection", conf="high", sev="high", path="src/auth_controller.py"):
    return {"title": title, "severity": sev, "confidence": conf,
            "primary_vulnerability_class": cls, "target_path": path,
            "summary": "s", "impact": "i", "example_attack": "a", "recommended_fix": "f"}


def test_multi_pass_unions_findings_for_recall(tmp_path):
    repo = _repo_tree(tmp_path / "repo")
    A, B = _cand("SQLi in login"), _cand("Path traversal in export", cls="path-traversal")
    # Pass 1 finds A+B; pass 2 (non-deterministic) finds only A.
    llm = FakeLLM(findings=None, per_call=[[A, B], [A]])
    cfg = OpenHackConfig(passes=2)
    out_dir = OpenHackEngine(llm, cfg).review(repo, tmp_path / "out", "a/b")

    findings = {f.title: f for f in OpenHackConnector().from_dir(out_dir, "a/b")}
    # Union across passes -> B is not dropped just because pass 2 missed it.
    assert set(findings) == {"SQLi in login", "Path traversal in export"}
    # Cross-pass agreement is surfaced as a confidence tag + note.
    assert "corroborated" in findings["SQLi in login"].tags          # seen in 2/2
    assert "single-pass" in findings["Path traversal in export"].tags  # seen in 1/2
    assert "2 of 2" in findings["SQLi in login"].description


def test_passes_route_to_different_models(tmp_path):
    repo = _repo_tree(tmp_path / "repo")
    llm = FakeLLM([_cand("SQLi in login")])   # every pass finds the same issue
    cfg = OpenHackConfig(passes=2, pass_models=[
        TaskModel(model="claude-opus-4-8"),
        TaskModel(model="gpt-5"),
    ])
    out_dir = OpenHackEngine(llm, cfg).review(repo, tmp_path / "out", "a/b")

    # Each pass used a different model's spec.
    models = [c["spec"].model for c in llm.calls]
    assert models == ["claude-opus-4-8", "gpt-5"]
    # A finding seen by both models is tagged multi-model + corroborated,
    # and the note names the models.
    f = OpenHackConnector().from_dir(out_dir, "a/b")[0]
    assert "multi-model" in f.tags and "corroborated" in f.tags
    assert "claude-opus-4-8, gpt-5" in f.description


def test_cross_model_agreement_merges_similar_titles(tmp_path):
    repo = _repo_tree(tmp_path / "repo")
    # The same weakness (path traversal, same file) worded very differently by
    # two model families must collapse into one corroborated, multi-model finding
    # — an exact-title key would have counted them as two single-pass findings.
    terse = _cand("Path Traversal Vulnerability", cls="path-traversal")
    verbose = _cand("Path traversal in the bash extractor lets attackers read files",
                    cls="path-traversal")
    llm = FakeLLM(findings=None, per_call=[[terse], [verbose]])
    cfg = OpenHackConfig(passes=2, pass_models=[
        TaskModel(model="claude-opus-4-8"),
        TaskModel(model="gpt-5"),
    ])
    out_dir = OpenHackEngine(llm, cfg).review(repo, tmp_path / "out", "a/b")

    findings = OpenHackConnector().from_dir(out_dir, "a/b")
    assert len(findings) == 1
    f = findings[0]
    assert "multi-model" in f.tags and "corroborated" in f.tags
    assert "2 of 2" in f.description
    assert "claude-opus-4-8, gpt-5" in f.description


def test_free_text_class_wordings_share_a_bucket(tmp_path):
    repo = _repo_tree(tmp_path / "repo")
    # Model families word the vulnerability class itself differently; the raw
    # string used to be part of the consolidation key, making cross-model merges
    # structurally impossible. The canonical family must bridge them.
    # (Real pair from a live 3-model graphify run.)
    opus = _cand("GitHub Actions pinned to mutable tags",
                 cls="supply chain / ci security", path=".github/workflows/publish.yml")
    gpt = _cand("Third-party GitHub Actions are referenced by mutable tags",
                cls="ci/cd supply-chain compromise", path=".github/workflows/publish.yml")
    llm = FakeLLM(findings=None, per_call=[[opus], [gpt]])
    cfg = OpenHackConfig(passes=2, pass_models=[
        TaskModel(model="claude-opus-4-8"), TaskModel(model="gpt-5")])
    out_dir = OpenHackEngine(llm, cfg).review(repo, tmp_path / "out", "a/b")

    findings = OpenHackConnector().from_dir(out_dir, "a/b")
    assert len(findings) == 1
    assert "multi-model" in findings[0].tags


def test_cross_model_wording_gap_merges(tmp_path):
    repo = _repo_tree(tmp_path / "repo")
    # Same issue, fully reworded across model families — shares only the core
    # nouns. Needs the singularized tokens + calibrated thresholds to merge.
    # (Real pair from a live 3-model graphify run.)
    opus = _cand("Untrusted entity labels interpolated into LLM prompt (prompt injection)",
                 cls="prompt injection / untrusted input", path="graphify/dedup.py")
    gpt = _cand("Opt-in LLM deduplication is vulnerable to prompt injection through entity labels",
                cls="injection", path="graphify/dedup.py")
    llm = FakeLLM(findings=None, per_call=[[opus], [gpt]])
    cfg = OpenHackConfig(passes=2, pass_models=[
        TaskModel(model="claude-opus-4-8"), TaskModel(model="gpt-5")])
    out_dir = OpenHackEngine(llm, cfg).review(repo, tmp_path / "out", "a/b")

    findings = OpenHackConnector().from_dir(out_dir, "a/b")
    assert len(findings) == 1
    assert "multi-model" in findings[0].tags


def test_canonical_class_families():
    from codescan.openhack_engine import _canonical_class

    assert _canonical_class("supply chain / ci security") == "supply-chain"
    assert _canonical_class("ci/cd supply-chain compromise") == "supply-chain"
    assert _canonical_class("cross-site scripting (xss)") == "xss"
    assert _canonical_class("denial of service / resource exhaustion") == "dos"
    assert _canonical_class("algorithmic denial of service") == "dos"
    assert _canonical_class("path traversal / arbitrary file read") == "path-traversal"
    assert _canonical_class("arbitrary file overwrite / symlink attack") == "path-traversal"
    # Specific injection kinds don't collapse into the generic family.
    assert _canonical_class("sql injection") == "sql-injection"
    assert _canonical_class("cross-site request forgery") == "csrf"
    # Unmatched free text keys on itself (lowercased) rather than a wrong family.
    assert _canonical_class("Network Policy Bypass") == "network policy bypass"
    assert _canonical_class("") == "unknown"


def test_distinct_same_class_findings_stay_separate(tmp_path):
    repo = _repo_tree(tmp_path / "repo")
    # Two genuinely different path-traversal issues in the same file must NOT be
    # merged — false corroboration would be worse than under-counting.
    a = _cand("Backup restore follows symlinks to overwrite arbitrary files", cls="path-traversal")
    b = _cand("Cache cleanup deletes files outside the cache directory", cls="path-traversal")
    llm = FakeLLM(findings=None, per_call=[[a, b], [a, b]])
    cfg = OpenHackConfig(passes=2)
    out_dir = OpenHackEngine(llm, cfg).review(repo, tmp_path / "out", "a/b")

    titles = {f.title for f in OpenHackConnector().from_dir(out_dir, "a/b")}
    assert titles == {a["title"], b["title"]}


def test_failing_pass_is_isolated(tmp_path):
    repo = _repo_tree(tmp_path / "repo")

    class FlakyLLM(FakeLLM):
        def complete_json(self, task, system, user, schema, **kwargs):
            self.calls.append({"spec": kwargs.get("spec")})
            if len(self.calls) == 2:               # 2nd pass (e.g. missing deployment)
                raise RuntimeError("gpt-5: deployment not found")
            return {"findings": self.findings}

    llm = FlakyLLM([_cand("SQLi in login")])
    cfg = OpenHackConfig(passes=2, pass_models=[
        TaskModel(model="claude-opus-4-8"),
        TaskModel(model="gpt-5"),
    ])
    out_dir = OpenHackEngine(llm, cfg).review(repo, tmp_path / "out", "a/b")
    # Pass 1 (claude) still produced the finding despite pass 2 failing.
    titles = {f.title for f in OpenHackConnector().from_dir(out_dir, "a/b")}
    assert titles == {"SQLi in login"}


def test_single_pass_has_no_agreement_signal(tmp_path):
    repo = _repo_tree(tmp_path / "repo")
    llm = FakeLLM([_cand("SQLi in login")])
    out_dir = OpenHackEngine(llm, OpenHackConfig(passes=1)).review(repo, tmp_path / "out", "a/b")
    f = OpenHackConnector().from_dir(out_dir, "a/b")[0]
    assert "corroborated" not in f.tags and "single-pass" not in f.tags
    assert "Review agreement" not in f.description
    assert len(llm.calls) == 1


def test_debug_passes_dumps_raw_per_pass_findings(tmp_path):
    import json

    repo = _repo_tree(tmp_path / "repo")
    A = _cand("SQLi in login")
    B = _cand("Path traversal in export", cls="path-traversal")
    # Pass 1 finds A+B, pass 2 finds only A — raw dump must capture all 3 rows.
    llm = FakeLLM(findings=None, per_call=[[A, B], [A]])
    cfg = OpenHackConfig(passes=2, debug_passes=True, pass_models=[
        TaskModel(model="claude-opus-4-8"),
        TaskModel(model="gpt-5"),
    ])
    OpenHackEngine(llm, cfg).review(repo, tmp_path / "out", "a/b")

    dump = json.loads((tmp_path / "out" / "passes-raw.json").read_text(encoding="utf-8"))
    assert dump["passes"] == 2
    rows = dump["findings"]
    assert len(rows) == 3
    # Each row records which pass/model produced it, before consolidation.
    assert {(r["pass"], r["title"]) for r in rows} == {
        (0, "SQLi in login"), (0, "Path traversal in export"), (1, "SQLi in login"),
    }
    assert {r["model"] for r in rows} == {"claude-opus-4-8", "gpt-5"}


def test_debug_passes_off_by_default(tmp_path):
    repo = _repo_tree(tmp_path / "repo")
    OpenHackEngine(FakeLLM([_cand("SQLi in login")]), OpenHackConfig(passes=1)).review(
        repo, tmp_path / "out", "a/b")
    assert not (tmp_path / "out" / "passes-raw.json").exists()


def test_per_pass_finding_count_is_logged(tmp_path, caplog):
    import logging
    repo = _repo_tree(tmp_path / "repo")
    # Pass 1 finds one issue; pass 2 (different model) finds none.
    llm = FakeLLM(findings=None, per_call=[[_cand("SQLi in login")], []])
    cfg = OpenHackConfig(passes=2, pass_models=[
        TaskModel(model="claude-opus-4-8"), TaskModel(model="gpt-5")])
    with caplog.at_level(logging.INFO, logger="codescan.openhack_engine"):
        OpenHackEngine(llm, cfg).review(repo, tmp_path / "out", "a/b")
    msgs = [r.getMessage() for r in caplog.records]
    # A zero-yield pass is visible without debug mode — the real signal.
    assert any("pass 1/2 (claude-opus-4-8): 1 finding" in m for m in msgs)
    assert any("pass 2/2 (gpt-5): 0 finding" in m for m in msgs)


def test_engine_respects_min_confidence(tmp_path):
    repo = _repo_tree(tmp_path / "repo")
    llm = FakeLLM([
        {"title": "Maybe", "severity": "low", "confidence": "low",
         "primary_vulnerability_class": "misc", "target_path": "src/auth_controller.py",
         "summary": "", "impact": "", "example_attack": "", "recommended_fix": ""},
        {"title": "Solid", "severity": "high", "confidence": "high",
         "primary_vulnerability_class": "injection", "target_path": "src/auth_controller.py",
         "summary": "", "impact": "", "example_attack": "", "recommended_fix": "fix"},
    ])
    cfg = OpenHackConfig(min_confidence="high")
    out_dir = OpenHackEngine(llm, cfg).review(repo, tmp_path / "out", "a/b")
    titles = {f.title for f in OpenHackConnector().from_dir(out_dir, "a/b")}
    assert titles == {"Solid"}          # low-confidence candidate dropped
