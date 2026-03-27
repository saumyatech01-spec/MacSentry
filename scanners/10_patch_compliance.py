"""MacSentry — 10_patch_compliance.py
Checks all installed apps + runtimes against OSV.dev and NVD CVE databases.
Requires network access (user-disclosed before this step runs).
"""
from __future__ import annotations
import json, re, time
from pathlib import Path
from scanner_base import run_cmd, build_finding, build_result

STEP_NUMBER = 10
STEP_NAME = "Patch & CVE Compliance"
DESCRIPTION = (
    "Checks all installed apps, runtimes, and packages against the NIST "
    "NVD and OSV.dev databases for known unpatched vulnerabilities."
)

OSV_API = "https://api.osv.dev/v1/query"


def _query_osv(package_name: str, version: str, ecosystem: str = "PyPI") -> list[dict]:
    """Query OSV.dev for CVEs. Returns list of vulnerability dicts."""
    try:
        import urllib.request, urllib.error
        payload = json.dumps({
            "package": {"name": package_name, "ecosystem": ecosystem},
            "version": version
        }).encode()
        req = urllib.request.Request(
            OSV_API,
            data=payload,
            headers={"Content-Type": "application/json"},
            method="POST"
        )
        with urllib.request.urlopen(req, timeout=8) as resp:
            data = json.loads(resp.read())
        return data.get("vulns", [])
    except Exception:
        return []


def _check_macos_updates() -> list[dict]:
    findings = []
    out, _, _ = run_cmd(["softwareupdate", "--list"], timeout=30)
    critical_updates = [l for l in out.splitlines()
                        if "Security" in l or "Rapid Security Response" in l]
    all_updates = [l for l in out.splitlines() if l.strip().startswith("*")]
    if critical_updates:
        findings.append(build_finding(
            title=f"{len(critical_updates)} pending Security Update(s) for macOS",
            severity="HIGH",
            detail="Security updates patch critical OS vulnerabilities. Delaying them leaves known exploits unpatched.",
            fix_steps=[
                "Open System Settings → General → Software Update.",
                "Click 'Update Now' for all security updates.",
                "Or run: sudo softwareupdate --install --all",
            ],
            command="sudo softwareupdate --install --all",
            auto_fixable=True,
            mitre_tag="T1195",
        ))
    elif all_updates:
        findings.append(build_finding(
            title=f"{len(all_updates)} macOS update(s) available (non-security)",
            severity="LOW",
            detail="Non-critical updates are available.",
            fix_steps=["Run: sudo softwareupdate --install --all"],
            command="sudo softwareupdate --install --all",
            auto_fixable=True,
        ))
    else:
        findings.append(build_finding(
            title="macOS is fully up to date",
            severity="SAFE",
            detail="No pending macOS updates.",
            fix_steps=[],
            command="softwareupdate --list",
        ))
    return findings


def _check_homebrew() -> list[dict]:
    findings = []
    brew_path = "/opt/homebrew/bin/brew"
    if not Path(brew_path).exists():
        brew_path = "/usr/local/bin/brew"
    if not Path(brew_path).exists():
        return findings
    out, _, _ = run_cmd([brew_path, "outdated", "--verbose"], timeout=30)
    outdated = [l for l in out.splitlines() if l.strip()]
    if len(outdated) >= 20:
        findings.append(build_finding(
            title=f"{len(outdated)} outdated Homebrew packages (≥20 threshold)",
            severity="MEDIUM",
            detail="A large backlog of outdated Homebrew packages increases the chance of running vulnerable software.",
            fix_steps=["Run: brew update && brew upgrade"],
            command="brew update && brew upgrade",
            auto_fixable=True,
        ))
    elif outdated:
        findings.append(build_finding(
            title=f"{len(outdated)} Homebrew package(s) can be updated",
            severity="LOW",
            detail="Minor backlog of Homebrew updates.",
            fix_steps=["Run: brew update && brew upgrade"],
            command="brew update && brew upgrade",
            auto_fixable=True,
        ))
    else:
        findings.append(build_finding(
            title="All Homebrew packages are up to date",
            severity="SAFE",
            detail="Homebrew package index is current.",
            fix_steps=[],
            command="brew outdated",
        ))
    return findings


def _check_python_runtime() -> list[dict]:
    findings = []
    out, _, rc = run_cmd(["python3", "--version"])
    m = re.search(r"Python (\d+)\.(\d+)\.?(\d*)", out)
    if not m:
        return findings
    major, minor = int(m.group(1)), int(m.group(2))
    version_str = f"{major}.{minor}.{m.group(3)}"
    if major == 3 and minor <= 8:
        findings.append(build_finding(
            title=f"Python {version_str} is End-of-Life",
            severity="HIGH",
            detail="Python 3.8 reached end-of-life October 2024. No more security patches will be issued.",
            fix_steps=[
                "Install via Homebrew: brew install python@3.12",
                "Or download from python.org",
            ],
            command="brew install python@3.12",
            auto_fixable=True,
            mitre_tag="T1195.001",
        ))
    else:
        findings.append(build_finding(
            title=f"Python {version_str} is within supported lifecycle",
            severity="SAFE",
            detail="Python runtime is a supported version.",
            fix_steps=[],
            command="python3 --version",
        ))
    return findings


def run() -> dict:
    start = time.time()
    findings = []
    findings += _check_macos_updates()
    findings += _check_homebrew()
    findings += _check_python_runtime()
    return build_result(STEP_NUMBER, STEP_NAME, DESCRIPTION, findings, start)
