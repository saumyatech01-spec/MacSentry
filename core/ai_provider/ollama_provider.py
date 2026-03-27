"""
MacSentry - core/ai_provider/ollama_provider.py
Stub for self-hosted model support via Ollama or vLLM.

Supported models (future): DeepSeek, GLM, Llama, Gemma

To activate:
  1. Install Ollama: https://ollama.ai
  2. Pull a model: ollama pull llama3.3:70b
  3. Set AI_PROVIDER=ollama in .env
  4. Implement the get_suggestion() method below
"""
from __future__ import annotations

import json
import os

# TODO: Install httpx for async HTTP when implementing
# import httpx

from .base_provider import BaseAIProvider, AIProviderError


class OllamaProvider(BaseAIProvider):
    """
    Stub AI provider for self-hosted models via Ollama or vLLM.

    Supports: DeepSeek-R1, DeepSeek-V3, GLM-4, Llama 3.3, Gemma 3
    (any model accessible via Ollama's /api/generate or /api/chat endpoint)

    Configuration (via .env):
      OLLAMA_MODEL    = model tag, e.g. "llama3.3:70b" or "deepseek-r1:70b"
      OLLAMA_BASE_URL = base URL, e.g. "http://localhost:11434"
    """

    def __init__(self) -> None:
        self._model = os.getenv("OLLAMA_MODEL", "llama3.3:70b")
        self._base_url = os.getenv("OLLAMA_BASE_URL", "http://localhost:11434").rstrip("/")

    @property
    def provider_name(self) -> str:
        return "ollama"

    @property
    def model_name(self) -> str:
        return self._model

    async def get_suggestion(self, sanitized_payload: dict) -> dict:
        """
        TODO: Implement self-hosted model inference via Ollama API.

        Endpoint: POST {OLLAMA_BASE_URL}/api/generate
        or:       POST {OLLAMA_BASE_URL}/api/chat  (preferred for instruct models)

        Steps to implement:
          1. Build the prompt using the same system prompt as GeminiProvider
          2. POST to Ollama endpoint with the model name and prompt
          3. Stream or await the response
          4. Parse the JSON response using the same _parse_response() logic
          5. Return structured dict matching MacSentry suggestion schema

        Model-specific notes:
          - DeepSeek-R1: Strong reasoning; use <think> stripping on output
          - Llama 3.3 70B: Best general-purpose open model for this use case
          - Gemma 3: Good for lower-RAM machines (27B fits in 24GB VRAM)
          - GLM-4: Strong Chinese-English bilingual capability

        Example implementation:

            async with httpx.AsyncClient(timeout=120.0) as client:
                response = await client.post(
                    f"{self._base_url}/api/generate",
                    json={
                        "model": self._model,
                        "prompt": _build_prompt(sanitized_payload),
                        "stream": False,
                        "format": "json",
                    }
                )
                response.raise_for_status()
                raw = response.json().get("response", "")
                return _parse_response(raw)
        """
        # TODO: Remove this placeholder once implemented
        raise AIProviderError(
            "ollama",
            (
                f"Ollama provider is not yet implemented. "
                f"Model '{self._model}' at '{self._base_url}' is configured. "
                f"Set AI_PROVIDER=gemini to use Gemini instead."
            ),
        )


def _build_prompt(payload: dict) -> str:
    """TODO: Build the full system+user prompt for Ollama instruct models."""
    # TODO: Reuse the same _SYSTEM_PROMPT from gemini_provider.py
    # or define a shared prompt module at core/ai_provider/prompts.py
    bullets = payload.get("impact_bullets", [])
    bullets_str = "\n".join(f"  - {b}" for b in bullets) if bullets else "  - Not specified"
    return (
        "[SYSTEM]\n"
        "You are a trusted macOS cybersecurity expert. "
        "Return ONLY valid JSON matching the MacSentry suggestion schema.\n"
        "[USER]\n"
        f"Module: {payload.get('module_name', 'Unknown')}\n"
        f"Risk: {payload.get('risk_level', 'UNKNOWN')}\n"
        f"Finding: {payload.get('finding_text', '')}\n"
        f"Impact:\n{bullets_str}\n"
        f"Platform: {payload.get('macos_version', 'macOS 14')}\n"
        "Provide safe step-by-step remediation with macOS terminal commands."
    )
