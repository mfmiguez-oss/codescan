"""Run OpenHack automatically during a live scan, then ingest its output.

Two modes, chosen by config:

* **Built-in engine (default).** With no external `command`, codescan runs its own
  in-process whitebox review (`openhack_engine.OpenHackEngine`) over the cloned
  source using the multi-provider LLM harness. This is what makes "auto" mode work
  inside codescan with no external tool — it just needs the AI stages enabled.

* **External command.** Set `openhack.command` to shell out to a separate OpenHack
  install (its own automation/wrapper); `{repo_path}` and `{output_dir}` are
  substituted and the subprocess inherits codescan's AI-provider env vars.

Either way the result is a directory of finding candidates that
`OpenHackConnector` ingests.

Example config (external):

    openhack:
      auto: true
      clone: true
      workspace: .openhack
      command: ["bash", "run_openhack.sh", "{repo_path}", "{output_dir}"]
"""

from __future__ import annotations

import os
import subprocess
from pathlib import Path

from .config import OpenHackConfig
from .llm import LLMClient
from .models import Repo


class OpenHackRunner:
    def __init__(self, cfg: OpenHackConfig, llm: LLMClient | None = None) -> None:
        self.cfg = cfg
        self.llm = llm

    def run(self, repo: Repo) -> str:
        """Run OpenHack for `repo` and return the output directory to ingest."""
        ws = Path(self.cfg.workspace or ".openhack")
        ws.mkdir(parents=True, exist_ok=True)

        repo_path = ws / repo.slug
        if self.cfg.clone and repo.clone_url and not repo_path.exists():
            self._git_clone(repo.clone_url, repo_path)

        out_dir = ws / f"{repo.slug}-openhack-out"
        out_dir.mkdir(parents=True, exist_ok=True)

        if self.cfg.command:
            return self._run_external(repo_path, out_dir)
        return self._run_builtin(repo, repo_path, out_dir)

    # --- built-in in-process engine (default) ----------------------------
    def _run_builtin(self, repo: Repo, repo_path: Path, out_dir: Path) -> str:
        if self.llm is None:
            raise RuntimeError(
                "openhack.auto is set with no external openhack.command, so the "
                "built-in review engine is used — but the AI stages are disabled. "
                "Enable AI (drop --no-ai / set CODESCAN_AI) or set openhack.command."
            )
        if not repo_path.is_dir():
            raise RuntimeError(
                f"OpenHack has no source to review at {repo_path}: enable "
                "openhack.clone (the repo needs a clone_url) or place the source there."
            )
        # Imported here so the engine's cost is only paid on the built-in path.
        from .openhack_engine import OpenHackEngine

        return OpenHackEngine(self.llm, self.cfg).review(repo_path, out_dir, repo.full_name)

    # --- external OpenHack command ---------------------------------------
    def _run_external(self, repo_path: Path, out_dir: Path) -> str:
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
