"""Built-in OpenHack engine — in-process whitebox review, LLM stubbed.

Asserts the engine selects source, batches it, and writes finding-candidate JSON
that the existing OpenHackConnector ingests unchanged (no network / real model).
"""

from __future__ import annotations

from codescan.config import OpenHackConfig
from codescan.connectors import OpenHackConnector
from codescan.models import Severity, Source
from codescan.openhack_engine import OpenHackEngine


class FakeLLM:
    """Stands in for LLMClient — records calls, returns a canned finding."""

    def __init__(self, findings):
        self.findings = findings
        self.calls = []

    def complete_json(self, task, system, user, schema, **kwargs):
        self.calls.append({"task": task, "user": user, **kwargs})
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
