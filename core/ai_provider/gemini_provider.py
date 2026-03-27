"""
MacSentry - core/ai_provider/gemini_provider.py
Gemini 2.5 Pro AI provider implementation.

Requires:
  pip install google-generativeai
  GEMINI_API_KEY environment variable set
"""
from __future__ import annotations

import json
import os
import asyncio
from typing import Any

try:
    import google.generativeai as genai
    from google.api_core.exceptions import ResourceExhausted, GoogleAPIError
except ImportError as exc:
    raise ImportError(
        "google-generativeai not installed. Run: pip install google-generativeai"
    ) from exc

from .base_provider import BaseAIProvider, AIProviderError


_SYSTEM_PROMPT = """\
You are a trusted macOS cybersecurity expert embedded in MacSentry,
a security scanner for Apple Silicon and Intel MacBook Pros (macOS 13+).
Provide clear, safe, step-by-step remediation for the security finding below.

STRICT RULES:
- Only suggest commands that are safe and reversible where possible.
- Mark any irreversible commands with the caution field.
- Never suggest disabling SIP unless absolutely necessary.
- All commands must be native macOS / standard Unix tools.
- Max 6 steps. Fewer is better.
- Return ONLY a valid JSON object. No text outside the JSON block.
- Use this exact schema:
{
  "summary": "string",
  "steps": [
    {
      "step_number": 1,
      "title": "string",
      "description": "string",
      "command": "string or null",
      "caution": "string or null"
    }
  ],
  "verify_command": "string or null",
  "references": ["url1", "url2"]
}
"""


class GeminiProvider(BaseAIProvider):
    """Gemini 2.5 Pro provider for MacSentry security suggestions."""

    _MODEL_ID = "gemini-2.5-pro"

    def __init__(self) -> None:
        api_key = os.getenv("GEMINI_API_KEY")
        if not api_key:
            raise AIProviderError(
                "gemini",
                "GEMINI_API_KEY environment variable is not set.",
            )
        genai.configure(api_key=api_key)
        self._client = genai.GenerativeModel(
            model_name=self._MODEL_ID,
            system_instruction=_SYSTEM_PROMPT,
            generation_config=genai.GenerationConfig(
                response_mime_type="application/json",
                temperature=0.2,
                max_output_tokens=2048,
            ),
        )

    @property
    def provider_name(self) -> str:
        return "gemini"

    @property
    def model_name(self) -> str:
        return self._MODEL_ID

    async def get_suggestion(self, sanitized_payload: dict) -> dict:
        """
        Call Gemini 2.5 Pro with the sanitized finding and return
        a structured suggestion dict.
        """
        user_message = _build_user_message(sanitized_payload)

        try:
            # google-generativeai is sync; run in thread pool to keep FastAPI async
            loop = asyncio.get_event_loop()
            response = await loop.run_in_executor(
                None, lambda: self._client.generate_content(user_message)
            )
        except ResourceExhausted as exc:
            raise AIProviderError(
                "gemini",
                "Rate limit reached (429). Please wait a moment and try again.",
                status_code=429,
            ) from exc
        except GoogleAPIError as exc:
            raise AIProviderError(
                "gemini",
                f"Gemini API error: {exc}",
            ) from exc
        except Exception as exc:
            raise AIProviderError(
                "gemini",
                f"Unexpected error calling Gemini: {exc}",
            ) from exc

        return _parse_response(response.text)


def _build_user_message(payload: dict) -> str:
    """Format the sanitized payload into the Gemini user message."""
    bullets = payload.get("impact_bullets", [])
    bullets_str = "\n".join(f"  - {b}" for b in bullets) if bullets else "  - Not specified"
    return (
        f"MacSentry Security Finding:\n"
        f"Module:   {payload.get('module_name', 'Unknown')}\n"
        f"Risk:     {payload.get('risk_level', 'UNKNOWN')}\n"
        f"Finding:  {payload.get('finding_text', '')}\n"
        f"Impact:\n{bullets_str}\n"
        f"Platform: {payload.get('macos_version', 'macOS 14')} (Apple Silicon / Intel)\n\n"
        f"Provide safe, step-by-step remediation with terminal commands."
    )


def _parse_response(raw_text: str) -> dict:
    """
    Parse Gemini's JSON response into the MacSentry suggestion schema.
    Falls back to a safe error structure if parsing fails.
    """
    try:
        # Gemini may wrap JSON in code fences even with application/json mime type
        text = raw_text.strip()
        if text.startswith("```"):
            lines = text.split("\n")
            text = "\n".join(
                line for line in lines
                if not line.strip().startswith("```")
            )
        data = json.loads(text)
        # Validate required keys
        if "steps" not in data or "summary" not in data:
            raise ValueError("Missing required keys in Gemini response")
        return data
    except (json.JSONDecodeError, ValueError) as exc:
        return {
            "summary": "AI response could not be parsed. Please try again.",
            "steps": [
                {
                    "step_number": 1,
                    "title": "Manual Review Required",
                    "description": (
                        "The AI returned an unexpected response format. "
                        "Please consult the MacSentry static 'How to Fix' section above."
                    ),
                    "command": None,
                    "caution": None,
                }
            ],
            "verify_command": None,
            "references": [],
            "_parse_error": str(exc),
        }
