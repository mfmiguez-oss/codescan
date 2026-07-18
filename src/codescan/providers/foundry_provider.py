"""Microsoft Foundry provider — codescan's sole model gateway.

Every AI model is served through one Azure AI Foundry resource; the model name
decides which of the resource's two API surfaces a request uses:

* ``claude-*`` models → Anthropic's native Messages API on Foundry
  (`anthropic.AnthropicFoundry`): structured outputs, adaptive thinking,
  effort, and client-side Fable refusal fallbacks (Foundry has no server-side
  fallback support, so the SDK middleware re-serves refusals on Opus).
* everything else (OpenAI GPT, Mistral, or any other Foundry
  deployment) → the resource's OpenAI-compatible chat-completions endpoint via
  the ``openai`` SDK, with JSON mode + defensive parsing.

Environment:
- FOUNDRY_API_KEY      (or AZURE_OPENAI_API_KEY) — the resource API key
- FOUNDRY_RESOURCE     — the Foundry resource name (e.g. ``myresource``);
  required for claude-* models, and derives the OpenAI-compatible endpoint
  (https://<resource>.services.ai.azure.com/openai/v1/) when no base URL is set
- FOUNDRY_BASE_URL     (or AZURE_OPENAI_BASE_URL) — explicit OpenAI-compatible
  endpoint; overrides the FOUNDRY_RESOURCE derivation
- FOUNDRY_API_VERSION  (or AZURE_OPENAI_API_VERSION) — set only for classic
  Azure OpenAI data-plane endpoints (``?api-version=...``); selects the
  `AzureOpenAI` client, which is the only one that speaks that dialect.
"""

from __future__ import annotations

import json
import logging
import os
from urllib.parse import urlsplit

from .base import CompletionRequest, LLMProvider, build_json_instruction, extract_json

logger = logging.getLogger(__name__)

# Anthropic capability matrix (substring match on model id).
_EFFORT_MODELS = ("opus-4-5", "opus-4-6", "opus-4-7", "opus-4-8", "sonnet-5", "sonnet-4-6", "fable", "mythos")
_ADAPTIVE_MODELS = ("opus-4-6", "opus-4-7", "opus-4-8", "sonnet-5", "sonnet-4-6", "fable", "mythos")


def _env(*names: str) -> str:
    for name in names:
        value = os.getenv(name)
        if value:
            return value
    return ""


def _has(model: str, subs: tuple[str, ...]) -> bool:
    return any(s in model for s in subs)


class FoundryProvider(LLMProvider):
    name = "foundry"

    def __init__(self) -> None:
        self._anthropic_client = None
        self._openai_client = None

    # --- clients (lazy; SDKs are imported on first use) -------------------

    @property
    def anthropic_client(self):
        if self._anthropic_client is None:
            try:
                from anthropic import AnthropicFoundry, BetaRefusalFallbackMiddleware
            except ImportError as exc:  # pragma: no cover
                raise RuntimeError(
                    "anthropic SDK not installed. `pip install anthropic`. "
                    "Set FOUNDRY_API_KEY + FOUNDRY_RESOURCE."
                ) from exc

            api_key = _env("FOUNDRY_API_KEY", "AZURE_OPENAI_API_KEY")
            resource = _env("FOUNDRY_RESOURCE")
            if not api_key:
                raise RuntimeError(
                    "Microsoft Foundry needs FOUNDRY_API_KEY (or AZURE_OPENAI_API_KEY) "
                    "in the environment."
                )
            if not resource:
                raise RuntimeError(
                    "claude-* models on Microsoft Foundry need FOUNDRY_RESOURCE — the "
                    "Foundry resource name that serves your Anthropic deployments."
                )
            # Foundry has no server-side refusal fallbacks; the SDK middleware
            # retries Fable false-positive refusals on Opus client-side.
            self._anthropic_client = AnthropicFoundry(
                api_key=api_key, resource=resource,
                middleware=[BetaRefusalFallbackMiddleware([{"model": "claude-opus-4-8"}])],
            )
        return self._anthropic_client

    @property
    def openai_client(self):
        if self._openai_client is None:
            try:
                from openai import AzureOpenAI, OpenAI
            except ImportError as exc:  # pragma: no cover
                raise RuntimeError(
                    "openai SDK not installed. `pip install openai`. "
                    "Set FOUNDRY_API_KEY + FOUNDRY_BASE_URL (or FOUNDRY_RESOURCE)."
                ) from exc

            api_key = _env("FOUNDRY_API_KEY", "AZURE_OPENAI_API_KEY")
            resource = _env("FOUNDRY_RESOURCE")
            base_url = _env("FOUNDRY_BASE_URL", "AZURE_OPENAI_BASE_URL")
            api_version = _env("FOUNDRY_API_VERSION", "AZURE_OPENAI_API_VERSION")

            if not api_key:
                raise RuntimeError(
                    "Microsoft Foundry needs FOUNDRY_API_KEY (or AZURE_OPENAI_API_KEY) "
                    "in the environment."
                )
            if not base_url and resource:
                base_url = f"https://{resource}.services.ai.azure.com/openai/v1/"
            if not base_url:
                raise RuntimeError(
                    "Microsoft Foundry needs FOUNDRY_BASE_URL (or FOUNDRY_RESOURCE, or "
                    "AZURE_OPENAI_BASE_URL) — the resource's OpenAI-compatible endpoint, "
                    "e.g. https://<resource>.services.ai.azure.com/openai/v1/"
                )

            if api_version:
                self._openai_client = AzureOpenAI(
                    api_key=api_key, azure_endpoint=base_url, api_version=api_version
                )
            else:
                self._openai_client = OpenAI(api_key=api_key, base_url=base_url)
        return self._openai_client

    # --- resource introspection -------------------------------------------

    def list_deployments(self) -> list[str]:
        """Names of the model deployments on the Foundry resource.

        These are the values `ai.model` / task routes can be set to. Uses the
        resource's data-plane deployments endpoint with the same API key as
        inference. Raises on missing credentials or an unreachable resource —
        callers that only *suggest* models (the config UI) degrade to a static
        list.
        """
        import requests

        api_key = _env("FOUNDRY_API_KEY", "AZURE_OPENAI_API_KEY")
        resource = _env("FOUNDRY_RESOURCE")
        base_url = _env("FOUNDRY_BASE_URL", "AZURE_OPENAI_BASE_URL")
        if not api_key:
            raise RuntimeError("FOUNDRY_API_KEY (or AZURE_OPENAI_API_KEY) is not set")
        if resource:
            root = f"https://{resource}.services.ai.azure.com"
        elif base_url:
            parts = urlsplit(base_url)
            root = f"{parts.scheme}://{parts.netloc}"
        else:
            raise RuntimeError("FOUNDRY_RESOURCE (or FOUNDRY_BASE_URL) is not set")

        resp = requests.get(
            f"{root}/openai/deployments",
            params={"api-version": "2023-03-15-preview"},
            headers={"api-key": api_key}, timeout=15,
        )
        resp.raise_for_status()
        names = [d["id"] for d in resp.json().get("data", []) if d.get("id")]
        return sorted(names, key=str.lower)

    # --- request paths ----------------------------------------------------

    def complete_json(self, req: CompletionRequest) -> dict:
        if req.model.startswith("claude"):
            return self._complete_anthropic(req)
        return self._complete_openai_compat(req)

    def _complete_anthropic(self, req: CompletionRequest) -> dict:
        """Native Messages API — structured outputs guarantee valid JSON back.

        Foundry workspaces don't all support structured outputs (it's in beta
        there, per model/workspace); on that specific 400 the request retries
        once with the schema prompted instead and the reply parsed defensively.
        """
        try:
            return self._anthropic_call(req, structured=True)
        except Exception as exc:  # noqa: BLE001 - retry only the known capability gap
            if "structured_outputs not supported" not in str(exc):
                raise
            logger.info("foundry: structured outputs unsupported for %s in this "
                        "workspace — falling back to prompted JSON", req.model)
            return self._anthropic_call(req, structured=False)

    def _anthropic_call(self, req: CompletionRequest, *, structured: bool) -> dict:
        output_config: dict = {}
        system = req.system
        if structured:
            output_config["format"] = {"type": "json_schema", "schema": req.schema}
        else:
            system = system + "\n\n" + build_json_instruction(req)
        if _has(req.model, _EFFORT_MODELS):
            output_config["effort"] = req.effort
        kwargs: dict = dict(
            model=req.model, max_tokens=req.max_tokens, system=system,
            messages=[{"role": "user", "content": req.user}],
        )
        if output_config:
            kwargs["output_config"] = output_config
        if _has(req.model, _ADAPTIVE_MODELS):
            kwargs["thinking"] = {"type": "adaptive"}

        client = self.anthropic_client
        if req.model.startswith(("claude-fable", "claude-mythos")):
            # Beta surface so the refusal-fallback middleware applies — security
            # tooling can trip Fable's false-positive classifier refusals.
            with client.beta.messages.stream(**kwargs) as stream:
                msg = stream.get_final_message()
        else:
            with client.messages.stream(**kwargs) as stream:
                msg = stream.get_final_message()

        if msg.stop_reason == "refusal":
            raise RuntimeError(
                f"foundry model {req.model} refused: {getattr(msg, 'stop_details', None)}. "
                "If this recurs, route the task to claude-opus-4-8 (ai.tasks.<task>.model)."
            )
        text = next((b.text for b in msg.content if b.type == "text"), "{}")
        return json.loads(text) if structured else extract_json(text)

    def _complete_openai_compat(self, req: CompletionRequest) -> dict:
        """Chat completions: JSON mode + schema in the prompt, parsed defensively."""
        system = req.system + "\n\n" + build_json_instruction(req)
        messages = [
            {"role": "system", "content": system},
            {"role": "user", "content": req.user},
        ]
        common = dict(model=req.model, messages=messages,
                      response_format={"type": "json_object"})
        # Newer (reasoning) models want max_completion_tokens; older take max_tokens.
        try:
            resp = self.openai_client.chat.completions.create(
                **common, max_completion_tokens=req.max_tokens)
        except Exception:
            resp = self.openai_client.chat.completions.create(**common, max_tokens=req.max_tokens)
        return extract_json(resp.choices[0].message.content)
