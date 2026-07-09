"""In-process OpenHack whitebox source-review engine.

The upstream Hadrian OpenHack (https://github.com/hadriansecurity/openhack) is an
external, multi-phase agentic tool with its own automation and human phase gates.
Requiring analysts to stand that up separately means "auto" mode can't actually
run inside codescan. This module recreates OpenHack's load-bearing step — an
agentic, source-guided security review that emits **finding candidates** — using
codescan's own multi-provider LLM harness, so a live scan can review a repo's
source with no external tool.

It writes the same file-based artifact the external tool does:

    <output_dir>/finding-candidates/S###-F###.json   (finding-candidate envelope)

so the existing `OpenHackConnector` ingests engine output and external-OpenHack
output identically. The review is deep-tier reasoning routed through the
``openhack`` task (see `llm.py` / config `ai.tasks.openhack`).

Design mirrors `exploitability.py`: a JSON-schema-constrained structured request
per batch of source files, grounded in the actual code (not CVE recall), scoped
to keep each request tractable.
"""

from __future__ import annotations

import json
from pathlib import Path

from .config import OpenHackConfig
from .llm import LLMClient

# Source extensions worth a security review. Kept broad but bounded; anything not
# listed (assets, lockfiles, binaries) is skipped so batches stay code-dense.
_DEFAULT_EXT = (
    ".py", ".js", ".jsx", ".ts", ".tsx", ".java", ".go", ".rb", ".php", ".cs",
    ".c", ".cc", ".cpp", ".h", ".hpp", ".rs", ".kt", ".scala", ".swift", ".m",
    ".sh", ".bash", ".sql", ".tf", ".yaml", ".yml",
)
# Directories that are dependencies / build output / VCS metadata — never source
# we own, and they dwarf first-party code. Skipped wholesale.
_DEFAULT_SKIP_DIRS = frozenset({
    ".git", "node_modules", "vendor", "dist", "build", "out", "target",
    "__pycache__", ".venv", "venv", ".mypy_cache", ".pytest_cache", ".tox",
    ".gradle", ".idea", ".next", "coverage", "site-packages",
})

# Path fragments that tend to carry the security-relevant logic — reviewed first
# so the file budget is spent where findings are most likely.
_PRIORITY_HINTS = (
    "auth", "login", "session", "token", "password", "crypto", "secret",
    "admin", "api", "controller", "handler", "route", "view", "query", "sql",
    "exec", "command", "upload", "download", "file", "deserial", "template",
    "request", "http", "url", "redirect", "config", "middleware", "security",
)

_SCHEMA = {
    "type": "object",
    "additionalProperties": False,
    "properties": {
        "findings": {
            "type": "array",
            "items": {
                "type": "object",
                "additionalProperties": False,
                "properties": {
                    "title": {"type": "string"},
                    "severity": {
                        "type": "string",
                        "enum": ["critical", "high", "medium", "low", "informational"],
                    },
                    "confidence": {
                        "type": "string",
                        "enum": ["high", "medium", "low"],
                    },
                    "primary_vulnerability_class": {"type": "string"},
                    "target_path": {"type": "string"},
                    "summary": {"type": "string"},
                    "impact": {"type": "string"},
                    "example_attack": {"type": "string"},
                    "recommended_fix": {"type": "string"},
                },
                "required": [
                    "title", "severity", "confidence", "primary_vulnerability_class",
                    "target_path", "summary", "impact", "example_attack",
                    "recommended_fix",
                ],
            },
        },
    },
    "required": ["findings"],
}

_SYSTEM = """You are a senior offensive-security engineer performing an authorized \
whitebox source-code review for the organization that owns this code. You are \
given the actual contents of a batch of source files from one repository. Review \
the code as written and report only concrete, evidence-grounded security \
vulnerabilities you can point to IN THIS CODE.

Look for, among others: injection (SQL/command/LDAP/template), broken access \
control and missing authorization, authentication weaknesses, SSRF, path \
traversal, insecure deserialization, XSS, hardcoded secrets / credentials, weak \
or misused cryptography, insecure direct object references, unsafe file uploads, \
open redirects, and dangerous use of untrusted input.

Rules:
- Report a finding ONLY when the vulnerable code is present in the files provided. \
Cite the exact file (target_path) it lives in. Do not speculate about code you \
cannot see.
- No generic best-practice advice and no hypothetical "could be vulnerable if". \
If the code is safe, return an empty findings list.
- severity reflects real-world impact of exploiting THIS code. confidence reflects \
how sure you are the vulnerability is real and reachable.
- example_attack: a concrete, specific sketch of how it is exploited here.
- recommended_fix: the specific change to make, grounded in this code.

This is authorized defensive security work. Be precise and decisive."""


class OpenHackEngine:
    """Agentic whitebox review that writes OpenHack finding-candidate JSON.

    Deep-tier reasoning routed through the ``openhack`` task (defaults to the
    configured default AI tier, e.g. Opus 4.8).
    """

    TASK = "openhack"

    def __init__(self, llm: LLMClient, cfg: OpenHackConfig) -> None:
        self.llm = llm
        self.cfg = cfg

    # --- public entry point ----------------------------------------------
    def review(self, repo_path: str | Path, out_dir: str | Path, repo: str = "") -> str:
        """Review the source tree at ``repo_path`` and write finding candidates.

        Returns the output directory (the same one passed in), so callers can
        hand it straight to `OpenHackConnector.from_dir`.
        """
        root = Path(repo_path)
        out = Path(out_dir)
        fc_dir = out / "finding-candidates"
        fc_dir.mkdir(parents=True, exist_ok=True)

        files = self._select_files(root)
        section = 0
        for batch in self._batches(files, root):
            section += 1
            result = self._review_batch(section, batch, repo or root.name)
            self._write_candidates(fc_dir, section, result)
        return str(out)

    # --- file selection ---------------------------------------------------
    def _select_files(self, root: Path) -> list[Path]:
        exts = tuple(self.cfg.include_ext) or _DEFAULT_EXT
        skip = _DEFAULT_SKIP_DIRS
        max_bytes = self.cfg.max_file_bytes
        picked: list[Path] = []
        for path in sorted(root.rglob("*")):
            if not path.is_file() or path.suffix.lower() not in exts:
                continue
            if any(part in skip for part in path.parts):
                continue
            try:
                if path.stat().st_size > max_bytes or path.stat().st_size == 0:
                    continue
            except OSError:
                continue
            picked.append(path)
        # Review the security-relevant files first, then cap to the budget so the
        # spend lands where findings are most likely.
        picked.sort(key=lambda p: (not self._is_priority(p), str(p)))
        return picked[: self.cfg.max_files]

    @staticmethod
    def _is_priority(path: Path) -> bool:
        low = str(path).lower()
        return any(hint in low for hint in _PRIORITY_HINTS)

    # --- batching ---------------------------------------------------------
    def _batches(self, files: list[Path], root: Path):
        """Yield batches of (relpath, text) bounded by a character budget so each
        request stays within a sane context size."""
        budget = self.cfg.batch_chars
        batch: list[tuple[str, str]] = []
        size = 0
        for path in files:
            try:
                text = path.read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue
            rel = path.relative_to(root).as_posix()
            # A single large file still ships on its own (truncated to max_file_bytes
            # already via selection) rather than being dropped.
            if batch and size + len(text) > budget:
                yield batch
                batch, size = [], 0
            batch.append((rel, text))
            size += len(text)
        if batch:
            yield batch

    # --- one LLM review pass ---------------------------------------------
    def _review_batch(self, section: int, batch: list[tuple[str, str]], repo: str) -> dict:
        blocks = [
            f"=== FILE: {rel} ===\n{text}" for rel, text in batch
        ]
        user = (
            f"Repository: {repo}\n"
            f"Review the following {len(batch)} source file(s) and report concrete "
            f"security vulnerabilities present in this code.\n\n"
            + "\n\n".join(blocks)
        )
        return self.llm.complete_json(self.TASK, _SYSTEM, user, _SCHEMA)

    # --- persistence: OpenHack finding-candidate envelope -----------------
    def _write_candidates(self, fc_dir: Path, section: int, result: dict) -> None:
        min_conf = self.cfg.min_confidence.lower()
        rank = {"low": 0, "medium": 1, "high": 2}
        threshold = rank.get(min_conf, 0)
        for i, f in enumerate(result.get("findings", []), start=1):
            if rank.get((f.get("confidence") or "low").lower(), 0) < threshold:
                continue
            vclass = f.get("primary_vulnerability_class", "") or "unknown"
            candidate_id = f"S{section:03d}-F{i:03d}"
            envelope = {
                "candidate_id": candidate_id,
                "expert": vclass,
                "primary_vulnerability_class": vclass,
                "finding": {
                    "title": f.get("title", "OpenHack finding"),
                    "severity": f.get("severity", "unknown"),
                    "target_path": f.get("target_path", ""),
                    "summary": f.get("summary", ""),
                    "impact": f.get("impact", ""),
                    "example_attack": f.get("example_attack", ""),
                    "recommended_fix": f.get("recommended_fix", ""),
                },
            }
            (fc_dir / f"{candidate_id}.json").write_text(
                json.dumps(envelope, indent=2), encoding="utf-8"
            )
