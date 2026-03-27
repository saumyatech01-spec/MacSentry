"""
MacSentry - core/ai_provider/__init__.py
Provider factory. Controls which AI backend is used via AI_PROVIDER env var.

Usage:
    from core.ai_provider import get_provider
    provider = get_provider()           # uses AI_PROVIDER env var (default: gemini)
    provider = get_provider("ollama")   # explicit override
"""
from __future__ import annotations

import os

from .base_provider import BaseAIProvider, AIProviderError
from .gemini_provider import GeminiProvider
from .ollama_provider import OllamaProvider

__all__ = [
    "BaseAIProvider",
    "AIProviderError",
    "GeminiProvider",
    "OllamaProvider",
    "get_provider",
]

_PROVIDERS: dict[str, type[BaseAIProvider]] = {
    "gemini": GeminiProvider,
    "ollama": OllamaProvider,
}


def get_provider(name: str | None = None) -> BaseAIProvider:
    """
    Return an instantiated AI provider.

    Args:
        name: Provider name. If None, reads AI_PROVIDER env var.
              Defaults to 'gemini' if env var is also not set.

    Returns:
        Instantiated BaseAIProvider.

    Raises:
        ValueError:       If the provider name is unknown.
        AIProviderError:  If the provider fails to initialise
                          (e.g. missing API key).
    """
    resolved = name or os.getenv("AI_PROVIDER", "gemini")
    resolved = resolved.strip().lower()

    if resolved not in _PROVIDERS:
        available = ", ".join(sorted(_PROVIDERS.keys()))
        raise ValueError(
            f"Unknown AI provider: '{resolved}'. "
            f"Available providers: {available}"
        )

    return _PROVIDERS[resolved]()
