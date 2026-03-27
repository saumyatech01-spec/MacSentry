"""
MacSentry - api/routes/ai_suggestion.py
FastAPI route: POST /api/ai-suggestion

Receives a finding payload, sanitizes it, calls the configured
AI provider, and returns structured remediation steps.

This is a NEW FastAPI app (api/main.py) separate from
the legacy Flask server (ui/web_dashboard.py).
"""
from __future__ import annotations

import logging
import sys
from pathlib import Path
from typing import Any

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, Field

# Allow imports from repo root
sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent))

from core.sanitizer import sanitize_finding
from core.ai_provider import get_provider, AIProviderError

logger = logging.getLogger(__name__)

router = APIRouter()


# ---------------------------------------------------------------------------
# Request / Response models
# ---------------------------------------------------------------------------

class AISuggestionRequest(BaseModel):
    module_name: str = Field(..., example="Network Security")
    risk_level: str = Field(..., example="CRITICAL")
    finding_text: str = Field(..., example="Firewall is disabled")
    impact_bullets: list[str] = Field(default_factory=list)
    macos_version: str = Field(default="macOS 14", example="macOS 14")
    provider: str | None = Field(
        default=None,
        description="AI provider override. If None, uses AI_PROVIDER env var.",
        example="gemini",
    )


class RemediationStep(BaseModel):
    step_number: int
    title: str
    description: str
    command: str | None = None
    caution: str | None = None


class AISuggestion(BaseModel):
    summary: str
    steps: list[RemediationStep]
    verify_command: str | None = None
    references: list[str] = Field(default_factory=list)


class AISuggestionResponse(BaseModel):
    provider: str
    model: str
    suggestion: AISuggestion
    sanitization_applied: bool = True
    redaction_notes: list[str] = Field(default_factory=list)


class AISuggestionError(BaseModel):
    error: str
    provider: str | None = None
    retryable: bool = False


# ---------------------------------------------------------------------------
# Route
# ---------------------------------------------------------------------------

@router.post(
    "/ai-suggestion",
    response_model=AISuggestionResponse,
    summary="Get AI security remediation suggestion",
    description=(
        "Sanitizes the finding payload (strips PII) then calls the configured "
        "AI provider (Gemini 2.5 Pro by default) to return structured, "
        "step-by-step macOS remediation guidance."
    ),
    tags=["AI"],
)
async def ai_suggestion(request: AISuggestionRequest) -> AISuggestionResponse:
    """
    POST /api/ai-suggestion

    1. Sanitize the incoming payload (remove PII, device IDs, credentials)
    2. Call the AI provider (Gemini 2.5 Pro or configured provider)
    3. Return structured remediation steps
    """
    # --- Step 1: Sanitize ---
    raw_payload = request.model_dump(exclude={"provider"})
    sanitized, redaction_notes = sanitize_finding(raw_payload)

    if redaction_notes:
        logger.info(
            "Sanitized finding before LLM call. Redactions: %s",
            "; ".join(redaction_notes),
        )

    # --- Step 2: Get provider ---
    try:
        provider = get_provider(request.provider)
    except (ValueError, AIProviderError) as exc:
        logger.error("Provider init failed: %s", exc)
        raise HTTPException(status_code=503, detail=str(exc))

    # --- Step 3: Call AI ---
    try:
        suggestion_data = await provider.get_suggestion(sanitized)
    except AIProviderError as exc:
        logger.error("AI provider error [%s]: %s", exc.provider, exc)
        status = exc.status_code or 502
        raise HTTPException(
            status_code=status,
            detail={
                "error": str(exc),
                "provider": exc.provider,
                "retryable": status == 429,
            },
        )
    except Exception as exc:
        logger.exception("Unexpected error calling AI provider")
        raise HTTPException(
            status_code=500,
            detail={"error": f"Unexpected AI error: {exc}", "retryable": False},
        )

    # --- Step 4: Build response ---
    try:
        suggestion = AISuggestion(**suggestion_data)
    except Exception as exc:
        logger.error("Failed to parse AI suggestion schema: %s", exc)
        # Return a safe degraded response
        suggestion = AISuggestion(
            summary="AI returned a response that could not be fully parsed.",
            steps=[],
            verify_command=None,
            references=[],
        )

    return AISuggestionResponse(
        provider=provider.provider_name,
        model=provider.model_name,
        suggestion=suggestion,
        sanitization_applied=True,
        redaction_notes=redaction_notes,
    )
