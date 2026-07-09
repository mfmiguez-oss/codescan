"""Provider registry — resolve a supplier name to a shared provider instance.

Non-Anthropic SDKs are imported lazily inside each provider, so importing this
package never requires `openai` / `google-genai` to be installed. Add a supplier
by writing an `LLMProvider` subclass and registering it in `_CLASSES`.
"""

from __future__ import annotations

from .anthropic_provider import AnthropicProvider
from .base import CompletionRequest, LLMProvider, build_json_instruction, extract_json
from .google_provider import GoogleProvider
from .openai_provider import OpenAIProvider

_CLASSES: dict[str, type[LLMProvider]] = {
    "anthropic": AnthropicProvider,
    "openai": OpenAIProvider,
    "google": GoogleProvider,
}
_INSTANCES: dict[str, LLMProvider] = {}

PROVIDERS = list(_CLASSES)


def get_provider(name: str) -> LLMProvider:
    key = (name or "anthropic").lower()
    if key not in _CLASSES:
        raise RuntimeError(f"unknown AI provider '{name}'. Known: {PROVIDERS}")
    if key not in _INSTANCES:
        _INSTANCES[key] = _CLASSES[key]()
    return _INSTANCES[key]


__all__ = ["CompletionRequest", "LLMProvider", "build_json_instruction", "extract_json", "get_provider", "PROVIDERS"]
