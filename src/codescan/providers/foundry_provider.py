"""Microsoft Foundry provider (Azure AI Foundry).

Foundry serves model deployments behind OpenAI-compatible endpoints, so this
provider drives the standard `openai` SDK (lazily imported, optional dep) — but
it is a first-class provider name so codescan can be configured directly for
Foundry-backed deployments (`provider: foundry`, model = your deployment name).

Environment:
- FOUNDRY_API_KEY      (or AZURE_OPENAI_API_KEY)
- FOUNDRY_BASE_URL     (or AZURE_OPENAI_BASE_URL) — the project's
  OpenAI-compatible endpoint, e.g. https://<resource>.services.ai.azure.com/openai/v1/
- FOUNDRY_API_VERSION  (or AZURE_OPENAI_API_VERSION) — set only for classic
  Azure OpenAI data-plane endpoints (`?api-version=...`); selects the
  `AzureOpenAI` client, which is the only one that speaks that dialect.
"""

from __future__ import annotations

import os

from .base import CompletionRequest, LLMProvider, build_json_instruction, extract_json


def _env(*names: str) -> str:
    for name in names:
        value = os.getenv(name)
        if value:
            return value
    return ""


class FoundryProvider(LLMProvider):
    name = "foundry"

    def __init__(self) -> None:
        self._client = None

    @property
    def client(self):
        if self._client is None:
            try:
                from openai import AzureOpenAI, OpenAI
            except ImportError as exc:  # pragma: no cover
                raise RuntimeError(
                    "openai SDK not installed. `pip install openai` (or use another "
                    "provider). Set FOUNDRY_API_KEY + FOUNDRY_BASE_URL."
                ) from exc

            api_key = _env("FOUNDRY_API_KEY", "AZURE_OPENAI_API_KEY")
            base_url = _env("FOUNDRY_BASE_URL", "AZURE_OPENAI_BASE_URL")
            api_version = _env("FOUNDRY_API_VERSION", "AZURE_OPENAI_API_VERSION")

            if not api_key:
                raise RuntimeError(
                    "Microsoft Foundry needs FOUNDRY_API_KEY (or AZURE_OPENAI_API_KEY) "
                    "in the environment."
                )
            if not base_url:
                raise RuntimeError(
                    "Microsoft Foundry needs FOUNDRY_BASE_URL (or AZURE_OPENAI_BASE_URL) "
                    "— your project's OpenAI-compatible endpoint, e.g. "
                    "https://<resource>.services.ai.azure.com/openai/v1/"
                )

            if api_version:
                self._client = AzureOpenAI(
                    api_key=api_key, azure_endpoint=base_url, api_version=api_version
                )
            else:
                self._client = OpenAI(api_key=api_key, base_url=base_url)
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
