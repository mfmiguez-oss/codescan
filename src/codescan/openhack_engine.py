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
import logging
import re
from pathlib import Path

from .config import OpenHackConfig
from .llm import LLMClient, ModelSpec

logger = logging.getLogger(__name__)

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

# Cross-pass consolidation keys on file + *canonical* vulnerability class, then
# clusters by title similarity — different model families word the same weakness
# differently, so exact class/title keys under-counted cross-model agreement.
# The family table folds free-text class wordings ("supply chain / ci security",
# "ci/cd supply-chain compromise") into one bucket; first matching family wins,
# most specific first; unmatched wordings key on their own lowercase text.
# Calibrated against a live 3-model run (Opus / GPT / Codestral over graphify).
_CLASS_FAMILIES: tuple[tuple[str, tuple[str, ...]], ...] = (
    ("path-traversal", ("travers", "path handling", "path confinement",
                        "arbitrary file", "symlink", "zip slip", "zipslip")),
    ("xss", ("xss", "cross-site scripting", "cross site scripting")),
    ("csrf", ("csrf", "cross-site request forgery")),
    ("ssrf", ("ssrf", "request forgery")),
    ("sql-injection", ("sql",)),
    ("command-injection", ("command injection", "os command", "command execution")),
    ("injection", ("injection",)),
    ("dos", ("denial of service", "redos", "resource exhaustion",
             "resource consumption", "backtracking", "(dos)")),
    ("supply-chain", ("supply chain", "supply-chain", "ci/cd", "ci security", "workflow")),
    ("secrets", ("secret", "credential", "hardcoded")),
    ("info-disclosure", ("information disclosure", "data exposure",
                         "information leak", "sensitive data")),
    ("deserialization", ("deserial",)),
    ("access-control", ("access control", "idor", "direct object reference",
                        "authoriz", "privilege")),
    ("open-redirect", ("open redirect",)),
    ("crypto", ("cryptograph", "randomness", "certificate", "transport security",
                "tls", "collision", "hash")),
    ("upload", ("upload",)),
)


def _canonical_class(vclass: str) -> str:
    """Fold a model's free-text vulnerability class into its canonical family."""
    low = (vclass or "unknown").lower()
    for family, needles in _CLASS_FAMILIES:
        if any(n in low for n in needles):
            return family
    return low


# These stopwords (function words + generic security noise) are dropped before
# comparing titles so "Path Traversal Vulnerability" and "path traversal in the
# bash extractor" match on {path, traversal}.
_TITLE_STOP = frozenset({
    "a", "an", "the", "and", "or", "of", "to", "in", "on", "for", "with",
    "without", "via", "is", "are", "be", "can", "could", "may", "that", "this",
    "it", "its", "into", "from", "by", "as", "at", "not", "no", "do", "does",
    "when", "which", "if", "but", "over", "under", "using", "due",
    "vulnerability", "vuln", "issue", "issues", "insecure", "unsafe",
    "potential", "possible", "security", "flaw", "weakness", "risk", "allows",
    "allow", "enables", "enable", "leads", "causes", "cause",
})


def _title_tokens(title: str) -> frozenset[str]:
    """Significant lowercase word tokens of a finding title.

    Stopwords are dropped and plural nouns lightly singularized ("globs" /
    "glob", "symlinks" / "symlink") so wording variation across model families
    doesn't split tokens that mean the same thing.
    """
    words = re.split(r"[^a-z0-9]+", (title or "").lower())
    out = set()
    for w in words:
        if len(w) <= 1 or w in _TITLE_STOP:
            continue
        if len(w) > 3 and w.endswith("s") and not w.endswith("ss"):
            w = w[:-1]
        out.add(w)
    return frozenset(out)


def _titles_match(a: frozenset[str], b: frozenset[str]) -> bool:
    """Whether two token sets describe the same finding.

    Deliberately conservative — over-merging distinct same-class findings would
    fabricate cross-model 'corroboration'. Matches on either a Jaccard overlap
    of >= 0.4, or high containment of the smaller set (a terse title that is
    essentially a subset of a descriptive one). Thresholds calibrated against a
    live 3-model run: at these values every cross-model merge inspected was the
    same issue reworded, while distinct same-file same-class findings stayed
    separate; tighter values missed real agreement, looser ones began merging
    unrelated findings.
    """
    if not a or not b:
        return a == b
    inter = len(a & b)
    if inter == 0:
        return False
    if inter / len(a | b) >= 0.4:
        return True
    smaller = a if len(a) <= len(b) else b
    return len(smaller) >= 2 and inter / len(smaller) >= 0.7

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
the code as written and report the security vulnerabilities you can point to IN \
THIS CODE.

Look for, among others: injection (SQL/command/LDAP/template), broken access \
control and missing authorization, authentication weaknesses, SSRF, path \
traversal, insecure deserialization, XSS, hardcoded secrets / credentials, weak \
or misused cryptography, insecure direct object references, unsafe file uploads, \
open redirects, and dangerous use of untrusted input.

Coverage first: report EVERY plausible vulnerability you identify, including ones \
you are less certain about or judge lower-severity. Do not silently drop a \
candidate because you are unsure — include it and set the `confidence` field \
honestly (high / medium / low). A separate scoring and analyst-triage stage \
filters by confidence downstream, so under-reporting here loses real issues for \
good. It is better to surface a finding that later gets filtered than to miss a \
real bug.

Grounding rules (these keep precision without suppressing real findings):
- Report a finding only when the vulnerable code is present in the files provided; \
cite the exact file (target_path) it lives in. Do not invent code you cannot see.
- Tie every finding to specific code in these files — not generic best-practice \
advice untethered from a concrete manifestation here.
- severity reflects the real-world impact of exploiting THIS code; confidence \
reflects how sure you are the vulnerability is real and reachable.
- example_attack: a concrete, specific sketch of how it is exploited here.
- recommended_fix: the specific change to make, grounded in this code.

This is authorized defensive security work."""


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
        miss real issues, so multiple passes raise recall. With `cfg.pass_models`,
        each pass runs on a different model — diverse model families miss
        different things, so the union is broader and cross-model agreement is a
        stronger signal. Duplicate findings across passes are consolidated (keyed on
        path + class + title), keeping the highest severity/confidence seen and
        recording how many passes (and which models) agreed — surfaced as
        `corroborated` / `multi-model` tags and a note in the finding.

        A pass that fails (e.g. a model deployment that doesn't exist on the
        resource) is logged and skipped; the union still benefits from the passes
        that succeeded.

        Returns the output directory (the same one passed in), so callers can hand
        it straight to `OpenHackConnector.from_dir`.
        """
        root = Path(repo_path)
        out = Path(out_dir)
        fc_dir = out / "finding-candidates"
        fc_dir.mkdir(parents=True, exist_ok=True)

        files = self._select_files(root)
        passes = max(1, self.cfg.passes)
        # (path, vuln-class) -> list of clusters; each cluster groups findings
        # whose titles describe the same weakness across passes.
        consolidated: dict[tuple[str, str], list[dict]] = {}
        raw_by_pass: list[dict] = []          # diagnostics (cfg.debug_passes)
        for pass_idx in range(passes):
            spec = self._pass_spec(pass_idx)
            pass_count = 0
            try:
                for batch in self._batches(files, root):
                    result = self._review_batch(batch, repo or root.name, spec)
                    for finding in result.get("findings", []):
                        pass_count += 1
                        self._merge(consolidated, finding, spec.model, pass_idx)
                        if self.cfg.debug_passes:
                            raw_by_pass.append({
                                "pass": pass_idx, "model": spec.model,
                                "target_path": finding.get("target_path", ""),
                                "primary_vulnerability_class": finding.get("primary_vulnerability_class", ""),
                                "title": finding.get("title", ""),
                                "severity": finding.get("severity", ""),
                                "confidence": finding.get("confidence", ""),
                            })
            except Exception as exc:  # noqa: BLE001 - isolate a failing pass/model
                logger.warning("OpenHack pass %d (%s/%s) failed: %s",
                               pass_idx + 1, spec.provider, spec.model, exc)
            # Per-pass yield is a cheap, always-on signal — a model contributing
            # 0 findings (silent under-performance, not an error) shows up here.
            logger.info("OpenHack pass %d/%d (%s): %d finding(s)",
                        pass_idx + 1, passes, spec.model, pass_count)
        self._write_candidates(fc_dir, consolidated, passes)
        if self.cfg.debug_passes:
            (out / "passes-raw.json").write_text(
                json.dumps({"passes": passes, "findings": raw_by_pass}, indent=2),
                encoding="utf-8",
            )
            logger.info("OpenHack: wrote %d raw per-pass findings to %s",
                        len(raw_by_pass), out / "passes-raw.json")
        return str(out)

    def _pass_spec(self, pass_idx: int):
        """Resolve the model for pass `pass_idx` (cycles `pass_models`)."""
        overrides = self.cfg.pass_models
        override = overrides[pass_idx % len(overrides)] if overrides else None
        return self.llm.resolve_spec(self.TASK, override)

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
        request stays within a predictable context size."""
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
    def _review_batch(self, batch: list[tuple[str, str]], repo: str, spec: ModelSpec) -> dict:
        blocks = [
            f"=== FILE: {rel} ===\n{text}" for rel, text in batch
        ]
        user = (
            f"Repository: {repo}\n"
            f"Review the following {len(batch)} source file(s) and report concrete "
            f"security vulnerabilities present in this code.\n\n"
            + "\n\n".join(blocks)
        )
        # `spec` pins this pass to its configured model.
        return self.llm.complete_json(self.TASK, _SYSTEM, user, _SCHEMA, spec=spec)

    # --- cross-pass consolidation ----------------------------------------
    def _merge(self, acc: dict[tuple[str, str], list[dict]], f: dict,
               model: str, pass_idx: int) -> None:
        """Fold one raw finding into the consolidation map.

        Keyed on file + canonical vulnerability-class family; within a key,
        findings whose titles describe the same weakness (`_titles_match`)
        collapse into one cluster —
        so the same issue worded differently by two model families counts as
        agreement, while genuinely distinct same-class findings stay separate.
        Records the **distinct passes** and models that reported each cluster
        (not raw occurrences), and keeps the strongest severity/confidence seen.
        """
        path = f.get("target_path", "") or ""
        vclass = _canonical_class(f.get("primary_vulnerability_class") or "unknown")
        tokens = _title_tokens(f.get("title", "OpenHack finding"))
        clusters = acc.setdefault((path, vclass), [])
        for cur in clusters:
            if _titles_match(tokens, cur["tokens"]):
                cur["passes"].add(pass_idx)
                cur["models"].add(model)
                best = cur["finding"]
                if _SEV_RANK.get((f.get("severity") or "").lower(), 0) > _SEV_RANK.get((best.get("severity") or "").lower(), 0):
                    best["severity"] = f.get("severity")
                if _CONF_RANK.get((f.get("confidence") or "").lower(), 0) > _CONF_RANK.get((best.get("confidence") or "").lower(), 0):
                    best["confidence"] = f.get("confidence")
                return
        clusters.append({"finding": dict(f), "tokens": tokens,
                         "passes": {pass_idx}, "models": {model}})

    # --- persistence: OpenHack finding-candidate envelope -----------------
    def _write_candidates(self, fc_dir: Path, acc: dict[tuple[str, str], list[dict]], passes: int) -> None:
        threshold = _CONF_RANK.get(self.cfg.min_confidence.lower(), 0)
        # Flatten to (sort-key, cluster); stable order -> deterministic ids.
        entries = sorted(
            ((key, cur) for key, clusters in acc.items() for cur in clusters),
            key=lambda kc: (kc[0], (kc[1]["finding"].get("title") or "").lower()),
        )
        n = 0
        for _key, entry in entries:
            f = entry["finding"]
            found = len(entry["passes"])
            if _CONF_RANK.get((f.get("confidence") or "low").lower(), 0) < threshold:
                continue
            n += 1
            candidate_id = f"OH-{n:04d}"
            vclass = f.get("primary_vulnerability_class", "") or "unknown"
            summary = f.get("summary", "")
            models = sorted(entry["models"])
            tags = ["openhack"]
            if passes > 1:
                model_note = f" (models: {', '.join(models)})" if len(models) > 1 else ""
                summary = (
                    f"{summary}\n\nReview agreement: identified in {found} of {passes} "
                    f"independent whitebox review passes{model_note}."
                ).strip()
                tags.append("corroborated" if found >= 2 else "single-pass")
                if len(models) >= 2:
                    tags.append("multi-model")
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
