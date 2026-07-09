"""OpenAI provider — also covers any OpenAI-compatible endpoint.

Uses the `openai` SDK (imported lazily so it's an optional dependency). Point it
at another supplier by setting `OPENAI_BASE_URL` (+ that supplier's key in
`OPENAI_API_KEY`) — e.g. Azure OpenAI, Together, Groq, OpenRouter, or a local
server. JSON mode + the schema in the system prompt keeps output parseable
across those endpoints.
"""

from __future__ import annotations

from .base import CompletionRequest, LLMProvider, build_json_instruction, extract_json


class OpenAIProvider(LLMProvider):
    name = "openai"

    def __init__(self) -> None:
        self._client = None

    @property
    def client(self):
        if self._client is None:
            try:
                from openai import OpenAI
            except ImportError as exc:  # pragma: no cover
                raise RuntimeError(
                    "openai SDK not installed. `pip install openai` (or use the "
                    "anthropic provider). Set OPENAI_API_KEY / OPENAI_BASE_URL."
                ) from exc
            self._client = OpenAI()      # reads OPENAI_API_KEY / OPENAI_BASE_URL
        return self._client

    def complete_json(self, req: CompletionRequest) -> dict:
        system = req.system + "\n\n" + build_json_instruction(req)
        messages = [
            {"role": "system", "content": system},
            {"role": "user", "content": req.user},
        ]
        common = dict(model=req.model, messages=messages,
                      response_format={"type": "json_object"})
        # Newer (reasoning) models want max_completion_tokens; older take max_tokens.
        try:
            resp = self.client.chat.completions.create(
                **common, max_completion_tokens=req.max_tokens)
        except Exception:
            resp = self.client.chat.completions.create(**common, max_tokens=req.max_tokens)
        return extract_json(resp.choices[0].message.content)
