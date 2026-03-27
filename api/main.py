"""
MacSentry - api/main.py
New FastAPI application for AI-powered security suggestions.

This is a SEPARATE server from the legacy Flask server (ui/web_dashboard.py).
Runs on port 5002 by default to avoid conflicts with Flask (port 5001).

The Vite dev proxy at /api already points to port 5001 (Flask).
To also proxy AI calls, update vite.config.js /api/ai-suggestion to port 5002,
or run this FastAPI app behind the same Flask server using a reverse proxy.

Usage:
  uvicorn api.main:app --port 5002 --reload

Endpoints:
  POST /api/ai-suggestion  → AI security remediation suggestion
  GET  /api/health         → Health check
  GET  /docs               → Swagger UI
  GET  /redoc              → ReDoc UI
"""
from __future__ import annotations

import logging
import os
import sys
from pathlib import Path

# Ensure repo root is on path for core/ imports
REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from api.routes.ai_suggestion import router as ai_suggestion_router

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s  %(levelname)-8s  %(name)s  %(message)s",
)
logger = logging.getLogger("macsentry.api")

# ---------------------------------------------------------------------------
# App
# ---------------------------------------------------------------------------
app = FastAPI(
    title="MacSentry AI API",
    description=(
        "MacSentry AI-powered security remediation suggestions. "
        "Sanitizes finding data before sending to LLM providers. "
        "Designed to work alongside the legacy Flask dashboard."
    ),
    version="1.0.0",
    docs_url="/docs",
    redoc_url="/redoc",
)

# ---------------------------------------------------------------------------
# CORS — allow Vite dev server and production build
# ---------------------------------------------------------------------------
allowed_origins = [
    "http://localhost:5173",   # Vite dev server
    "http://localhost:5001",   # Flask legacy server
    "http://localhost:5002",   # This FastAPI server
    "http://127.0.0.1:5173",
    "http://127.0.0.1:5001",
    "http://127.0.0.1:5002",
]

app.add_middleware(
    CORSMiddleware,
    allow_origins=allowed_origins,
    allow_credentials=True,
    allow_methods=["GET", "POST", "OPTIONS"],
    allow_headers=["*"],
)

# ---------------------------------------------------------------------------
# Routers
# ---------------------------------------------------------------------------
app.include_router(ai_suggestion_router, prefix="/api")


# ---------------------------------------------------------------------------
# Health check
# ---------------------------------------------------------------------------
@app.get("/api/health", tags=["System"])
async def health() -> dict:
    """Health check endpoint."""
    return {
        "status": "ok",
        "service": "MacSentry AI API",
        "ai_provider": os.getenv("AI_PROVIDER", "gemini"),
    }


# ---------------------------------------------------------------------------
# Run directly
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    import uvicorn

    port = int(os.getenv("AI_API_PORT", "5002"))
    logger.info("Starting MacSentry AI API on port %s", port)
    logger.info("AI provider: %s", os.getenv("AI_PROVIDER", "gemini"))
    logger.info("Swagger UI: http://localhost:%s/docs", port)
    uvicorn.run("api.main:app", host="0.0.0.0", port=port, reload=True)
