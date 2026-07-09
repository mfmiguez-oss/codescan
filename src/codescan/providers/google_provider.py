"""Google (Gemini) provider — uses the `google-genai` SDK (lazy import).

Reads GEMINI_API_KEY (or GOOGLE_API_KEY). Requests JSON output and embeds the
schema in the prompt, parsing defensively.
"""

from __future__ import annotations

import os

from .base import CompletionRequest, LLMProvider, build_json_instruction, extract_json


class GoogleProvider(LLMProvider):
    name = "google"

    def __init__(self) -> None:
        self._client = None

    @property
    def client(self):
        if self._client is None:
            try:
                from google import genai
            except ImportError as exc:  # pragma: no cover
                raise RuntimeError(
                    "google-genai not installed. `pip install google-genai`. "
                    "Set GEMINI_API_KEY (or GOOGLE_API_KEY)."
                ) from exc
            key = os.environ.get("GEMINI_API_KEY") or os.environ.get("GOOGLE_API_KEY")
            self._client = genai.Client(api_key=key)
        return self._client

    def complete_json(self, req: CompletionRequest) -> dict:
        from google.genai import types

        prompt = req.user + "\n\n" + build_json_instruction(req)
        resp = self.client.models.generate_content(
            model=req.model,
            contents=prompt,
            config=types.GenerateContentConfig(
                system_instruction=req.system,
                response_mime_type="application/json",
                max_output_tokens=req.max_tokens,
            ),
        )
        return extract_json(resp.text)
