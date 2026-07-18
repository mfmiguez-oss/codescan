"""Provider registry — resolve a provider name to a shared instance.

codescan accesses all AI models through Microsoft Foundry (`foundry`), which
serves Anthropic, OpenAI, Google, and Mistral model deployments behind one
resource. SDKs are imported lazily inside the provider, so importing this
package never requires `anthropic` / `openai` to be installed. Add a supplier
by writing an `LLMProvider` subclass and registering it in `_CLASSES`.
"""

from __future__ import annotations

from .base import CompletionRequest, LLMProvider, build_json_instruction, extract_json
from .foundry_provider import FoundryProvider

_CLASSES: dict[str, type[LLMProvider]] = {
    "foundry": FoundryProvider,
}
_INSTANCES: dict[str, LLMProvider] = {}

PROVIDERS = list(_CLASSES)


def get_provider(name: str) -> LLMProvider:
    key = (name or "foundry").lower()
    if key not in _CLASSES:
        raise RuntimeError(f"unknown AI provider '{name}'. Known: {PROVIDERS}")
    if key not in _INSTANCES:
        _INSTANCES[key] = _CLASSES[key]()
    return _INSTANCES[key]


__all__ = ["CompletionRequest", "LLMProvider", "build_json_instruction", "extract_json", "get_provider", "PROVIDERS"]
