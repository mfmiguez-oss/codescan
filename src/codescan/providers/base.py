"""LLM provider harness — provider-agnostic interface.

codescan's AI stages (semantic dedup, exploitability, threat modeling, AI
enrichment) go through an `LLMProvider` implementing the same
`complete_json(request) -> dict` contract, so a task can be routed to any
configured model via config (see `llm.py` / `ModelRouter`). Models are served
through Microsoft Foundry: claude-* deployments use native structured outputs;
other deployments request JSON and parse defensively (`extract_json`), which
keeps the adapter robust across the frequent API changes on those platforms.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass


@dataclass
class CompletionRequest:
    model: str
    system: str
    user: str
    schema: dict
    effort: str = "high"
    max_tokens: int = 16000


class LLMProvider:
    name = "base"

    def complete_json(self, req: CompletionRequest) -> dict:  # pragma: no cover - interface
        raise NotImplementedError

    def list_deployments(self) -> list[str]:  # pragma: no cover - interface
        """Model deployment names available from this provider (UI suggestions)."""
        raise NotImplementedError


def build_json_instruction(req: CompletionRequest) -> str:
    """Return the shared schema-guidance text appended to provider prompts."""
    return (
        "Respond ONLY with a single JSON object matching this schema:\n"
        + json.dumps(req.schema)
    )


def extract_json(text: str) -> dict:
    """Best-effort parse of a JSON object from model text (fences, prose, etc.)."""
    text = (text or "").strip()
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        pass
    fenced = re.search(r"```(?:json)?\s*(\{.*\})\s*```", text, re.S)
    if fenced:
        return json.loads(fenced.group(1))
    start, end = text.find("{"), text.rfind("}")
    if start != -1 and end > start:
        return json.loads(text[start : end + 1])
    raise RuntimeError(f"provider returned non-JSON output: {text[:200]}")
