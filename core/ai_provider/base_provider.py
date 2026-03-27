"""
MacSentry - core/ai_provider/base_provider.py
Abstract base class for all AI provider implementations.
All providers (Gemini, Ollama, vLLM) must implement this interface.
"""
from __future__ import annotations

from abc import ABC, abstractmethod


class BaseAIProvider(ABC):
    """Abstract AI provider interface for MacSentry security suggestions."""

    @abstractmethod
    async def get_suggestion(self, sanitized_payload: dict) -> dict:
        """
        Request a security remediation suggestion from the AI provider.

        Args:
            sanitized_payload: A pre-sanitized finding dict containing:
                - module_name:    str  (e.g. "Network Security")
                - risk_level:     str  (CRITICAL / HIGH / MEDIUM / LOW / SAFE)
                - finding_text:   str  (sanitized description of the issue)
                - impact_bullets: list[str]
                - macos_version:  str  (e.g. "macOS 14")

        Returns:
            A dict matching the MacSentry suggestion schema:
            {
              "summary": str,
              "steps": [
                {
                  "step_number": int,
                  "title": str,
                  "description": str,
                  "command": str | None,
                  "caution": str | None
                }
              ],
              "verify_command": str | None,
              "references": list[str]
            }

        Raises:
            AIProviderError: If the provider call fails for any reason.
        """
        ...

    @property
    @abstractmethod
    def provider_name(self) -> str:
        """Human-readable provider name, e.g. 'gemini' or 'ollama'."""
        ...

    @property
    @abstractmethod
    def model_name(self) -> str:
        """Model identifier string, e.g. 'gemini-2.5-pro' or 'llama3.3:70b'."""
        ...


class AIProviderError(Exception):
    """Raised when an AI provider call fails."""

    def __init__(self, provider: str, message: str, status_code: int | None = None):
        self.provider = provider
        self.status_code = status_code
        super().__init__(f"[{provider}] {message}")
