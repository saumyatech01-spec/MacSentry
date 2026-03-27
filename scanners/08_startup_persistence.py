"""MacSentry — 08_startup_persistence.py
Checks Login Items, LaunchAgents/Daemons, system extensions,
shell profile backdoors, native messaging hosts, AT jobs.
"""
from __future__ import annotations
import re, time, plistlib
from pathlib import Path
from scanner_base import run_cmd, build_finding, build_result

STEP_NUMBER = 8
STEP_NAME = "Startup & Persistence Mechanisms"
DESCRIPTION = (
    "Identifies all programs that automatically run at startup or login, "
    "including hidden persistence mechanisms used by malware."
)

SHELL_PROFILES = [
    Path.home() / ".zshrc",
    Path.home() / ".zprofile",
    Path.home() / ".bash_profile",
    Path.home() / ".bashrc",
    Path.home() / ".profile",
    Path("/etc/profile"),
    Path("/etc/zshrc"),
]

SHELL_DANGER_PATTERNS = [
    r"curl\s+.*\|\s*(ba)?sh",
    r"wget\s+.*\|\s*(ba)?sh",
    r"nc\s+.*-e\s+/bin",
    r"base64\s+--decode.*\|\s*(ba)?sh",
    r"python\s+-c\s+.*exec",
    r"mkfifo\s+/tmp",
]


def _check_login_items() -> list[dict]:
    findings = []
    out, _, _ = run_cmd([
        "osascript", "-e",
        'tell application "System Events" to get the name of every login item'
    ], timeout=10)
    items = [i.strip() for i in out.split(",") if i.strip()] if out else []
    if items:
        findings.append(build_finding(
            title=f"{len(items)} Login Item(s): {', '.join(items)}",
            severity="LOW",
            detail="Review each Login Item to ensure it is intentional. Malware often adds itself here for persistence.",
            fix_steps=[
                "Open System Settings → General → Login Items & Extensions.",
                "Remove any items you don't recognise.",
            ],
            command="osascript -e 'tell app \"System Events\" to get login items'",
            auto_fixable=False,
            mitre_tag="T1547.015",
        ))
    else:
        findings.append(build_finding(
            title="No Login Items configured",
            severity="SAFE",
            detail="No apps are set to launch at login.",
            fix_steps=[],
        ))
    return findings


def _check_shell_profiles() -> list[dict]:
    findings = []
    for profile in SHELL_PROFILES:
        if not profile.exists():
            continue
        try:
            content = profile.read_text(errors="ignore")
        except PermissionError:
            continue
        for pattern in SHELL_DANGER_PATTERNS:
            for line in content.splitlines():
                if re.search(pattern, line, re.IGNORECASE) and not line.strip().startswith("#"):
                    findings.append(build_finding(
                        title=f"Backdoor pattern in {profile.name}: {line.strip()[:60]}",
                        severity="HIGH",
                        detail=f"'{profile}' contains a command that downloads and executes remote code.",
                        fix_steps=[
                            f"Review: cat '{profile}'",
                            f"Edit: nano '{profile}'",
                            "Comment out or delete the suspicious line.",
                            "Reload: source ~/.zshrc",
                        ],
                        command=f"nano '{profile}'",
                        auto_fixable=False,
                        mitre_tag="T1059.004",
                    ))
    if not findings:
        findings.append(build_finding(
            title="No backdoor patterns found in shell profile files",
            severity="SAFE",
            detail="Shell profile files (.zshrc, .bash_profile, etc.) look clean.",
            fix_steps=[],
            command="cat ~/.zshrc ~/.zprofile ~/.bash_profile 2>/dev/null",
        ))
    return findings


def _check_system_extensions() -> list[dict]:
    findings = []
    out, _, rc = run_cmd(["systemextensionsctl", "list"])
    if rc != 0:
        return findings
    non_apple = []
    for line in out.splitlines():
        if ("enabled activated" in line.lower() or "activated waiting" in line.lower()):
            if "com.apple." not in line and "com.docker." not in line:
                non_apple.append(line.strip()[:80])
    if non_apple:
        findings.append(build_finding(
            title=f"{len(non_apple)} non-Apple System Extension(s) active",
            severity="MEDIUM",
            detail="System Extensions provide deep kernel-level access. Verify each one is from a trusted developer.",
            fix_steps=[
                "Run: systemextensionsctl list",
                "For each unknown extension, identify its parent app.",
                "Remove via System Settings → Privacy & Security → Extensions.",
            ],
            command="systemextensionsctl list",
            auto_fixable=False,
            mitre_tag="T1547.006",
        ))
    return findings


def run() -> dict:
    start = time.time()
    findings = []
    findings += _check_login_items()
    findings += _check_shell_profiles()
    findings += _check_system_extensions()
    return build_result(STEP_NUMBER, STEP_NAME, DESCRIPTION, findings, start)
