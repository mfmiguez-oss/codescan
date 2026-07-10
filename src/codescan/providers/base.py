"""Multi-provider LLM harness — provider-agnostic interface.

codescan's AI stages (semantic dedup, exploitability, threat modeling, AI
enrichment) go through an `LLMProvider`. Each supplier — Anthropic, OpenAI (and
any OpenAI-compatible endpoint), Google — implements the same
`complete_json(request) -> dict` contract, so a task can be routed to any model
from any supplier via config (see `llm.py` / `ModelRouter`).

The Anthropic provider uses native structured outputs; other providers request
JSON and parse defensively (`extract_json`), which keeps the adapters robust
across the frequent API changes on those platforms.
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
    supports_batch = False

    def complete_json(self, req: CompletionRequest) -> dict:  # pragma: no cover - interface
        raise NotImplementedError

    def complete_json_batch(
        self,
        requests: list[tuple[str, CompletionRequest]],
        *,
        poll_seconds: int = 30,
        max_wait_seconds: int = 3600,
    ) -> dict[str, dict]:  # pragma: no cover - interface
        """Run many requests as one async batch; return {custom_id: parsed_json}.

        Only providers with `supports_batch = True` implement this.
        """
        raise NotImplementedError(f"{self.name} provider has no Batches API support")


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
