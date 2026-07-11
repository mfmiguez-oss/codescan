"""CLI wiring — flags map to config without running a real scan."""

from __future__ import annotations

from pathlib import Path

from typer.testing import CliRunner

import codescan.cli as climod
from codescan.pipeline import PipelineResult

ROOT = Path(__file__).resolve().parents[1]
CONFIG = str(ROOT / "config" / "config.example.yaml")
runner = CliRunner()


class _FakePipe:
    """Captures the Config the CLI built; returns an empty result."""

    last_cfg = None

    def __init__(self, cfg, **kwargs):
        _FakePipe.last_cfg = cfg

    def run(self, **kwargs):
        return PipelineResult()


def test_whitebox_flag_enables_builtin_openhack(monkeypatch, tmp_path):
    monkeypatch.setattr(climod, "Pipeline", _FakePipe)
    result = runner.invoke(climod.app, [
        "scan", "--config", CONFIG, "--repo", "mfmiguez-oss/codescan",
        "--whitebox", "--out", str(tmp_path / "out.json"),
        "--state", str(tmp_path / "state.json"),
    ])
    assert result.exit_code == 0, result.output
    cfg = _FakePipe.last_cfg
    assert cfg.source.provider == "github"
    assert cfg.github.repos == ["mfmiguez-oss/codescan"]
    assert cfg.openhack.auto is True and cfg.openhack.clone is True
    assert cfg.openhack.command == []          # built-in engine, not an external command


def test_whitebox_requires_ai():
    # --whitebox needs the AI engine; combining it with --no-ai is rejected early.
    result = runner.invoke(climod.app, ["scan", "--config", CONFIG, "--whitebox", "--no-ai"])
    assert result.exit_code != 0
    assert "whitebox" in result.output.lower()
