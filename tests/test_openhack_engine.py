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
        provider = (override.provider if override and override.provider else "anthropic")
        model = (override.model if override and override.model else "m")
        return ModelSpec(provider, model, "high", 8000)

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


def test_passes_route_to_different_suppliers(tmp_path):
    repo = _repo_tree(tmp_path / "repo")
    llm = FakeLLM([_cand("SQLi in login")])   # every pass finds the same issue
    cfg = OpenHackConfig(passes=2, pass_models=[
        TaskModel(provider="anthropic", model="claude-opus-4-8"),
        TaskModel(provider="openai", model="gpt-5"),
    ])
    out_dir = OpenHackEngine(llm, cfg).review(repo, tmp_path / "out", "a/b")

    # Each pass used a different supplier's spec.
    providers = [c["spec"].provider for c in llm.calls]
    assert providers == ["anthropic", "openai"]
    # A finding seen by both suppliers is tagged multi-supplier + corroborated,
    # and the note names the suppliers.
    f = OpenHackConnector().from_dir(out_dir, "a/b")[0]
    assert "multi-supplier" in f.tags and "corroborated" in f.tags
    assert "anthropic, openai" in f.description


def test_failing_pass_is_isolated(tmp_path):
    repo = _repo_tree(tmp_path / "repo")

    class FlakyLLM(FakeLLM):
        def complete_json(self, task, system, user, schema, **kwargs):
            self.calls.append({"spec": kwargs.get("spec")})
            if len(self.calls) == 2:               # 2nd pass (e.g. missing key)
                raise RuntimeError("openai: no API key")
            return {"findings": self.findings}

    llm = FlakyLLM([_cand("SQLi in login")])
    cfg = OpenHackConfig(passes=2, pass_models=[
        TaskModel(provider="anthropic", model="claude-opus-4-8"),
        TaskModel(provider="openai", model="gpt-5"),
    ])
    out_dir = OpenHackEngine(llm, cfg).review(repo, tmp_path / "out", "a/b")
    # Pass 1 (anthropic) still produced the finding despite pass 2 failing.
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
