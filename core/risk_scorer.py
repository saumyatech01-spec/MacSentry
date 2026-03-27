"""
MacSentry - core/risk_scorer.py
CVSS-inspired security scoring engine.
"""
from __future__ import annotations

WEIGHTS = {"CRITICAL": 10.0, "HIGH": 7.0, "MEDIUM": 4.0, "LOW": 1.0, "SAFE": 0.0}

SEVERITY_COLORS = {
    "CRITICAL": "#FF3B30",
    "HIGH": "#FF9500",
    "MEDIUM": "#FFCC00",
    "LOW": "#34C759",
    "SAFE": "#8E8E93",
}


def calculate_overall_score(findings: list[dict]) -> dict:
    """Calculate the overall security score from a list of findings."""
    if not findings:
        return {
            "score": 100, "band": "Excellent",
            "critical_count": 0, "high_count": 0,
            "medium_count": 0, "low_count": 0,
            "safe_count": 0, "total_findings": 0,
        }

    counts = {k: 0 for k in WEIGHTS}
    total_penalty = 0.0
    for f in findings:
        sev = f.get("severity", "SAFE").upper()
        if sev not in WEIGHTS:
            sev = "SAFE"
        counts[sev] += 1
        total_penalty += WEIGHTS[sev]

    max_possible = len(findings) * 10.0
    score = max(0, round(100 - (total_penalty / max_possible * 100))) if max_possible > 0 else 100

    if score >= 90:
        band = "Excellent"
    elif score >= 70:
        band = "Good"
    elif score >= 50:
        band = "Fair"
    elif score >= 30:
        band = "Poor"
    else:
        band = "Critical"

    return {
        "score": score,
        "band": band,
        "critical_count": counts["CRITICAL"],
        "high_count": counts["HIGH"],
        "medium_count": counts["MEDIUM"],
        "low_count": counts["LOW"],
        "safe_count": counts["SAFE"],
        "total_findings": len(findings),
    }


def score_to_risk_level(score: int) -> str:
    """Convert a numeric score to a risk level string."""
    if score >= 90:
        return "LOW"
    elif score >= 70:
        return "MEDIUM"
    elif score >= 50:
        return "HIGH"
    else:
        return "CRITICAL"


def color_for_severity(severity: str) -> str:
    """Return hex color for a severity level."""
    return SEVERITY_COLORS.get(severity.upper(), "#8E8E93")
