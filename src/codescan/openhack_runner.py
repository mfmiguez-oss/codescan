"""Invoke OpenHack automatically during a live scan, then ingest its output.

OpenHack is an external, multi-phase agentic tool (it renders prompts you drive
against an LLM). codescan doesn't reimplement that loop — it runs a configured
command that performs an OpenHack run for a repo and writes findings, then the
`OpenHackConnector` ingests the result. The command is configurable because the
exact invocation depends on your OpenHack setup (its own automation/wrapper, and
which LLM provider it uses); `{repo_path}` and `{output_dir}` are substituted.

Example config:

    openhack:
      auto: true
      clone: true
      workspace: .openhack
      command: ["bash", "run_openhack.sh", "{repo_path}", "{output_dir}"]

The subprocess inherits the current environment, so whichever AI-provider keys
codescan has (ANTHROPIC_API_KEY / OPENAI_API_KEY / GEMINI_API_KEY) are available
to OpenHack too.
"""

from __future__ import annotations

import os
import subprocess
from pathlib import Path

from .config import OpenHackConfig
from .models import Repo


class OpenHackRunner:
    def __init__(self, cfg: OpenHackConfig) -> None:
        self.cfg = cfg

    def run(self, repo: Repo) -> str:
        """Run OpenHack for `repo` and return the output directory to ingest."""
        if not self.cfg.command:
            raise RuntimeError(
                "openhack.auto is set but openhack.command is empty — provide the "
                "command that runs OpenHack (e.g. a wrapper script) with "
                "{repo_path}/{output_dir} placeholders."
            )
        ws = Path(self.cfg.workspace or ".openhack")
        ws.mkdir(parents=True, exist_ok=True)

        repo_path = ws / repo.slug
        if self.cfg.clone and repo.clone_url and not repo_path.exists():
            self._git_clone(repo.clone_url, repo_path)

        out_dir = ws / f"{repo.slug}-openhack-out"
        out_dir.mkdir(parents=True, exist_ok=True)

        cmd = [
            arg.replace("{repo_path}", str(repo_path)).replace("{output_dir}", str(out_dir))
            for arg in self.cfg.command
        ]
        proc = subprocess.run(cmd, capture_output=True, text=True, env=os.environ.copy())
        if proc.returncode != 0:
            tail = (proc.stderr or proc.stdout or "").strip()[-400:]
            raise RuntimeError(f"OpenHack run failed ({' '.join(cmd)}): {tail}")
        return str(out_dir)

    @staticmethod
    def _git_clone(url: str, dest: Path) -> None:
        proc = subprocess.run(
            ["git", "clone", "--depth", "1", url, str(dest)],
            capture_output=True, text=True,
        )
        if proc.returncode != 0:
            raise RuntimeError(f"git clone failed: {(proc.stderr or '').strip()[-300:]}")
