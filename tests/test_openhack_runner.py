"""OpenHack auto-invocation runner — subprocess mocked, no real OpenHack/git."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

import codescan.openhack_runner as ohr
from codescan.config import OpenHackConfig
from codescan.connectors import OpenHackConnector
from codescan.models import Repo
from codescan.openhack_runner import OpenHackRunner


def _repo():
    return Repo(project_key="acme", slug="checkout", name="acme/checkout", clone_url="")


def test_run_substitutes_paths_and_output_is_ingestable(tmp_path, monkeypatch):
    captured = {}

    class Proc:
        returncode, stdout, stderr = 0, "", ""

    def fake_run(cmd, **kwargs):
        captured["cmd"] = cmd
        out = Path(cmd[-1])                     # {output_dir} substituted
        out.mkdir(parents=True, exist_ok=True)
        (out / "S001-F001.json").write_text(json.dumps(
            {"finding": {"title": "SQLi", "severity": "high", "target_path": "a.java"}}))
        return Proc()

    monkeypatch.setattr(ohr.subprocess, "run", fake_run)

    cfg = OpenHackConfig(auto=True, clone=False, workspace=str(tmp_path),
                         command=["mytool", "{repo_path}", "{output_dir}"])
    out_dir = OpenHackRunner(cfg).run(_repo())

    # Placeholders substituted to real paths.
    assert captured["cmd"][1].endswith("checkout")
    assert captured["cmd"][2] == out_dir
    # The produced output is ingestable by the connector.
    findings = OpenHackConnector().from_dir(out_dir, "acme/checkout")
    assert [f.title for f in findings] == ["SQLi"]


def test_builtin_engine_used_when_no_command(tmp_path, monkeypatch):
    # No external command + an LLM present => the in-process engine runs.
    repo_path = tmp_path / "checkout"
    repo_path.mkdir()

    captured = {}

    class FakeEngine:
        def __init__(self, llm, cfg):
            captured["built"] = True

        def review(self, rp, out_dir, repo):
            captured["review"] = (str(rp), str(out_dir), repo)
            return str(out_dir)

    monkeypatch.setattr("codescan.openhack_engine.OpenHackEngine", FakeEngine)

    cfg = OpenHackConfig(auto=True, clone=False, command=[], workspace=str(tmp_path))
    out_dir = OpenHackRunner(cfg, llm=object()).run(_repo())

    assert captured["built"] is True
    assert captured["review"][0].endswith("checkout")   # repo_path
    assert captured["review"][2] == "acme/checkout"      # repo full name
    assert out_dir.endswith("checkout-openhack-out")


def test_clone_enables_long_paths(tmp_path, monkeypatch):
    # A target repo can carry paths past Windows' 260-char limit; the clone must
    # set core.longpaths or the checkout fails "Filename too long" mid-scan.
    captured = {}

    class Proc:
        returncode, stdout, stderr = 0, "", ""

    def fake_run(cmd, **kw):
        captured["cmd"] = cmd
        Path(cmd[-1]).mkdir(parents=True, exist_ok=True)   # "cloned" working tree
        return Proc()

    monkeypatch.setattr(ohr.subprocess, "run", fake_run)

    class FakeEngine:
        def __init__(self, llm, cfg): ...
        def review(self, rp, out_dir, repo):
            return str(out_dir)

    monkeypatch.setattr("codescan.openhack_engine.OpenHackEngine", FakeEngine)

    cfg = OpenHackConfig(auto=True, clone=True, workspace=str(tmp_path), command=[])
    repo = Repo(project_key="acme", slug="checkout", name="acme/checkout",
                clone_url="https://github.com/acme/checkout.git")
    OpenHackRunner(cfg, llm=object()).run(repo)

    cmd = captured["cmd"]
    assert cmd[:2] == ["git", "clone"]
    assert "core.longpaths=true" in cmd
    assert cmd[-2] == repo.clone_url


def test_builtin_engine_requires_ai(tmp_path):
    # No command and no LLM (AI disabled) => actionable error, not a crash.
    (tmp_path / "checkout").mkdir()
    cfg = OpenHackConfig(auto=True, clone=False, command=[], workspace=str(tmp_path))
    with pytest.raises(RuntimeError, match="AI stages are disabled"):
        OpenHackRunner(cfg, llm=None).run(_repo())


def test_run_surfaces_failure(tmp_path, monkeypatch):
    class Proc:
        returncode, stdout, stderr = 2, "", "boom: openhack exploded"

    monkeypatch.setattr(ohr.subprocess, "run", lambda cmd, **kw: Proc())
    cfg = OpenHackConfig(auto=True, clone=False, workspace=str(tmp_path), command=["x"])
    with pytest.raises(RuntimeError, match="openhack exploded"):
        OpenHackRunner(cfg).run(_repo())


def _raise_missing(cmd, **kw):
    raise FileNotFoundError(2, "No such file or directory", cmd[0])


def test_missing_git_is_an_actionable_error(tmp_path, monkeypatch):
    # git absent from the runtime (e.g. a pre-git container image) must surface
    # install guidance, not a raw FileNotFoundError traceback.
    monkeypatch.setattr(ohr.subprocess, "run", _raise_missing)
    cfg = OpenHackConfig(auto=True, clone=True, workspace=str(tmp_path), command=[])
    repo = Repo(project_key="acme", slug="checkout", name="acme/checkout",
                clone_url="https://github.com/acme/checkout.git")
    with pytest.raises(RuntimeError, match="Install git in the runtime"):
        OpenHackRunner(cfg, llm=object()).run(repo)


def test_missing_external_command_is_an_actionable_error(tmp_path, monkeypatch):
    monkeypatch.setattr(ohr.subprocess, "run", _raise_missing)
    cfg = OpenHackConfig(auto=True, clone=False, workspace=str(tmp_path), command=["mytool"])
    with pytest.raises(RuntimeError, match="command not found: 'mytool'"):
        OpenHackRunner(cfg).run(_repo())
