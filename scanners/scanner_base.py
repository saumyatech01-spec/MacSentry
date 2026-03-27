"""
MacSentry - scanner_base.py
Shared utilities used by all scanner modules.
"""
from __future__ import annotations
import subprocess
import time
from typing import Optional


def run_cmd(cmd: list, timeout: int = 15, env=None) -> tuple:
    """Run a shell command safely. Returns (stdout, stderr, returncode)."""
    try:
        result = subprocess.run(
            cmd, capture_output=True, text=True, timeout=timeout, env=env
        )
        return result.stdout.strip(), result.stderr.strip(), result.returncode
    except subprocess.TimeoutExpired:
        return "", f"Timed out after {timeout}s", 1
    except FileNotFoundError:
        return "", f"Not found: {cmd[0]}", 127
    except Exception as e:
        return "", str(e), 1


def build_finding(
    title: str,
    severity: str = "SAFE",
    detail: str = "",
    fix_steps=None,
    command: str = "",
    auto_fixable: bool = False,
    mitre_tag: str = "",
) -> dict:
    return {
        "title": title,
        "severity": severity.upper(),
        "detail": detail,
        "fix_steps": fix_steps or [],
        "command": command,
        "auto_fixable": auto_fixable,
        "mitre_tag": mitre_tag,
    }


def build_result(
    step_number: int,
    step_name: str,
    description: str,
    findings: list,
    start_time: float,
) -> dict:
    duration_ms = int((time.time() - start_time) * 1000)
    severity_order = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "SAFE"]
    worst = "SAFE"
    has_issues = False
    for f in findings:
        sev = f.get("severity", "SAFE").upper()
        if sev != "SAFE":
            has_issues = True
        if severity_order.index(sev) < severity_order.index(worst):
            worst = sev
    status = "issues_found" if has_issues else "complete"
    return {
        "step_number": step_number,
        "step_name": step_name,
        "description": description,
        "status": status,
        "completion_pct": 100.0,
        "findings": findings,
        "risk_level": worst,
        "scan_duration_ms": duration_ms,
    }
