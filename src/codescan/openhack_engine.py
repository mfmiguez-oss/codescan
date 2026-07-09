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
from .models import size_difficulty

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
# Orderings for cross-pass consolidation (keep the strongest signal seen).
_SEV_RANK = {"critical": 4, "high": 3, "medium": 2, "low": 1, "informational": 0, "info": 0, "unknown": 0}
_CONF_RANK = {"high": 2, "medium": 1, "low": 0}

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

        Runs `cfg.passes` independent review passes (default 2) and **unions** the
        results: because AI source review is non-deterministic, a single pass can
        miss real issues, so multiple passes raise recall. Duplicate findings across
        passes are consolidated (keyed on path + class + title), keeping the highest
        severity/confidence seen and recording how many passes agreed — a confidence
        signal surfaced as a `corroborated` tag and a note in the finding.

        Returns the output directory (the same one passed in), so callers can hand
        it straight to `OpenHackConnector.from_dir`.
        """
        root = Path(repo_path)
        out = Path(out_dir)
        fc_dir = out / "finding-candidates"
        fc_dir.mkdir(parents=True, exist_ok=True)

        files = self._select_files(root)
        passes = max(1, self.cfg.passes)
        consolidated: dict[tuple[str, str, str], dict] = {}
        for _ in range(passes):
            for batch in self._batches(files, root):
                result = self._review_batch(batch, repo or root.name)
                for finding in result.get("findings", []):
                    self._merge(consolidated, finding)
        self._write_candidates(fc_dir, consolidated, passes)
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
    def _review_batch(self, batch: list[tuple[str, str]], repo: str) -> dict:
        blocks = [
            f"=== FILE: {rel} ===\n{text}" for rel, text in batch
        ]
        user = (
            f"Repository: {repo}\n"
            f"Review the following {len(batch)} source file(s) and report concrete "
            f"security vulnerabilities present in this code.\n\n"
            + "\n\n".join(blocks)
        )
        # Larger batches (more files / more surface) get a stronger model when
        # auto_route is on; a one- or two-file batch a cheaper one.
        return self.llm.complete_json(
            self.TASK, _SYSTEM, user, _SCHEMA, difficulty=size_difficulty(len(batch)),
        )

    # --- cross-pass consolidation ----------------------------------------
    def _merge(self, acc: dict[tuple[str, str, str], dict], f: dict) -> None:
        """Fold one raw finding into the consolidation map, keyed on identity.

        Same weakness in the same file (path + vulnerability class + title) reported
        across passes collapses into one entry; distinct titles stay separate (union
        favors recall). Keeps the strongest severity/confidence seen and counts how
        many passes reported it.
        """
        path = f.get("target_path", "") or ""
        vclass = (f.get("primary_vulnerability_class") or "unknown")
        title = f.get("title", "OpenHack finding")
        key = (path, vclass.lower(), title.strip().lower())
        cur = acc.get(key)
        if cur is None:
            acc[key] = {"finding": dict(f), "passes": 1}
            return
        cur["passes"] += 1
        best = cur["finding"]
        if _SEV_RANK.get((f.get("severity") or "").lower(), 0) > _SEV_RANK.get((best.get("severity") or "").lower(), 0):
            best["severity"] = f.get("severity")
        if _CONF_RANK.get((f.get("confidence") or "").lower(), 0) > _CONF_RANK.get((best.get("confidence") or "").lower(), 0):
            best["confidence"] = f.get("confidence")

    # --- persistence: OpenHack finding-candidate envelope -----------------
    def _write_candidates(self, fc_dir: Path, acc: dict[tuple[str, str, str], dict], passes: int) -> None:
        threshold = _CONF_RANK.get(self.cfg.min_confidence.lower(), 0)
        n = 0
        # Stable order (by key) -> deterministic candidate ids across runs.
        for _, entry in sorted(acc.items()):
            f = entry["finding"]
            found = entry["passes"]
            if _CONF_RANK.get((f.get("confidence") or "low").lower(), 0) < threshold:
                continue
            n += 1
            candidate_id = f"OH-{n:04d}"
            vclass = f.get("primary_vulnerability_class", "") or "unknown"
            summary = f.get("summary", "")
            tags = ["openhack"]
            if passes > 1:
                summary = (
                    f"{summary}\n\nReview agreement: identified in {found} of {passes} "
                    "independent whitebox review passes."
                ).strip()
                tags.append("corroborated" if found >= 2 else "single-pass")
            envelope = {
                "candidate_id": candidate_id,
                "expert": vclass,
                "primary_vulnerability_class": vclass,
                "tags": tags,
                "finding": {
                    "title": f.get("title", "OpenHack finding"),
                    "severity": f.get("severity", "unknown"),
                    "target_path": f.get("target_path", ""),
                    "summary": summary,
                    "impact": f.get("impact", ""),
                    "example_attack": f.get("example_attack", ""),
                    "recommended_fix": f.get("recommended_fix", ""),
                },
            }
            (fc_dir / f"{candidate_id}.json").write_text(
                json.dumps(envelope, indent=2), encoding="utf-8"
            )
