"""
MacSentry - core/report_generator.py
Generates PDF and JSON security reports using ReportLab.
"""
from __future__ import annotations
import json
import time
from pathlib import Path


def generate_json_report(summary: dict, output_path: str) -> str:
    """Save the scan summary as a formatted JSON file."""
    path = Path(output_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w") as f:
        json.dump(summary, f, indent=2)
    return str(path)


def generate_pdf_report(summary: dict, output_path: str) -> str:
    """
    Generate a PDF security report using ReportLab.
    Falls back gracefully if ReportLab is not installed.
    """
    try:
        from reportlab.lib.pagesizes import A4
        from reportlab.lib import colors
        from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
        from reportlab.platypus import (
            SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, HRFlowable
        )
        from reportlab.lib.units import cm
    except ImportError:
        raise ImportError(
            "ReportLab is required for PDF export. Install with: pip install reportlab"
        )

    path = Path(output_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    doc = SimpleDocTemplate(str(path), pagesize=A4)
    styles = getSampleStyleSheet()
    story = []

    # Title
    title_style = ParagraphStyle(
        "Title", parent=styles["Title"], fontSize=24, spaceAfter=12
    )
    story.append(Paragraph("MacSentry Security Report", title_style))
    story.append(Paragraph(
        f"Generated: {time.strftime('%Y-%m-%d %H:%M:%S')}", styles["Normal"]
    ))
    story.append(Spacer(1, 0.5 * cm))
    story.append(HRFlowable(width="100%"))
    story.append(Spacer(1, 0.5 * cm))

    # Overall Score
    overall = summary.get("overall", {})
    score = overall.get("score", 0)
    band = overall.get("band", "Unknown")
    story.append(Paragraph(
        f"Overall Security Score: <b>{score}%</b> — {band}", styles["Heading2"]
    ))
    story.append(Paragraph(
        f"Critical: {overall.get('critical_count', 0)} | "
        f"High: {overall.get('high_count', 0)} | "
        f"Medium: {overall.get('medium_count', 0)} | "
        f"Low: {overall.get('low_count', 0)} | "
        f"Safe: {overall.get('safe_count', 0)}",
        styles["Normal"]
    ))
    story.append(Spacer(1, 0.5 * cm))

    # Per-step findings table
    story.append(Paragraph("Findings Summary", styles["Heading2"]))
    table_data = [["Step", "Name", "Risk", "Findings", "Duration"]]
    for step in summary.get("steps", []):
        table_data.append([
            str(step.get("step_number", "")),
            step.get("step_name", "")[:30],
            step.get("risk_level", "SAFE"),
            str(len(step.get("findings", []))),
            f"{step.get('scan_duration_ms', 0)}ms",
        ])

    SEV_COLORS = {
        "CRITICAL": colors.HexColor("#FF3B30"),
        "HIGH": colors.HexColor("#FF9500"),
        "MEDIUM": colors.HexColor("#FFCC00"),
        "LOW": colors.HexColor("#34C759"),
        "SAFE": colors.HexColor("#8E8E93"),
    }

    table = Table(table_data, colWidths=[1.5 * cm, 8 * cm, 3 * cm, 2.5 * cm, 3 * cm])
    ts = TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#007AFF")),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
        ("FONTSIZE", (0, 0), (-1, -1), 9),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#F5F5F7")]),
        ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#C7C7CC")),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
    ])
    # Color-code the Risk column
    for i, step in enumerate(summary.get("steps", []), start=1):
        risk = step.get("risk_level", "SAFE")
        c = SEV_COLORS.get(risk, colors.gray)
        ts.add("TEXTCOLOR", (2, i), (2, i), c)
        ts.add("FONTNAME", (2, i), (2, i), "Helvetica-Bold")
    table.setStyle(ts)
    story.append(table)
    story.append(Spacer(1, 1 * cm))

    # Detailed findings per step
    story.append(Paragraph("Detailed Findings", styles["Heading2"]))
    for step in summary.get("steps", []):
        if not step.get("findings"):
            continue
        story.append(Paragraph(
            f"Step {step['step_number']}: {step['step_name']}", styles["Heading3"]
        ))
        for f in step["findings"]:
            if f.get("severity") == "SAFE":
                continue
            story.append(Paragraph(
                f"<b>[{f['severity']}]</b> {f['title']}", styles["Normal"]
            ))
            story.append(Paragraph(f['detail'], styles["Normal"]))
            if f.get("fix_steps"):
                for j, fix in enumerate(f["fix_steps"], 1):
                    story.append(Paragraph(f"  {j}. {fix}", styles["Normal"]))
            if f.get("command"):
                story.append(Paragraph(
                    f"<font name='Courier' size=8>$ {f['command']}</font>",
                    styles["Normal"]
                ))
            story.append(Spacer(1, 0.3 * cm))

    doc.build(story)
    return str(path)
