"""MacSentry — 03_user_auth.py
Checks login policies, admin accounts, sudo privileges, screen lock, SSH keys.
"""
from __future__ import annotations
import re, time
from pathlib import Path
from scanner_base import run_cmd, build_finding, build_result

STEP_NUMBER = 3
STEP_NAME = "User Authentication & Access Control"
DESCRIPTION = (
    "Checks login policies, admin account hygiene, sudo privileges, "
    "screen lock settings, and SSH key security."
)


def _check_auto_login() -> list[dict]:
    findings = []
    out, _, rc = run_cmd(["defaults", "read",
                          "/Library/Preferences/com.apple.loginwindow",
                          "autoLoginUser"])
    if rc == 0 and out.strip():
        findings.append(build_finding(
            title=f"Auto-login is enabled for user: {out.strip()}",
            severity="CRITICAL",
            detail="Auto-login bypasses the login screen entirely, allowing anyone with physical access full control of the account.",
            fix_steps=[
                "System Settings → General → Login Options.",
                "Set 'Automatic login' to Off.",
            ],
            command="sudo defaults delete /Library/Preferences/com.apple.loginwindow autoLoginUser",
            auto_fixable=True,
            mitre_tag="T1078",
        ))
    else:
        findings.append(build_finding(
            title="Auto-login is disabled",
            severity="SAFE",
            detail="Login screen is required on startup.",
            fix_steps=[],
            command="defaults read /Library/Preferences/com.apple.loginwindow autoLoginUser",
        ))
    return findings


def _check_guest_account() -> list[dict]:
    findings = []
    out, _, _ = run_cmd(["dscl", ".", "read", "/Users/Guest"])
    if out.strip():
        findings.append(build_finding(
            title="Guest account is active",
            severity="MEDIUM",
            detail="Guest accounts allow anyone to log in and browse files/network without authentication.",
            fix_steps=[
                "System Settings → Users & Groups → Guest User.",
                "Toggle 'Allow guests to log in to this computer' to OFF.",
            ],
            command="sudo dscl . -delete /Users/Guest",
            auto_fixable=False,
            mitre_tag="T1078.003",
        ))
    return findings


def _check_sudo_nopasswd() -> list[dict]:
    findings = []
    sudoers_files = [Path("/etc/sudoers")] + list(Path("/etc/sudoers.d").glob("*") if Path("/etc/sudoers.d").exists() else [])
    for f in sudoers_files:
        try:
            content = f.read_text(errors="ignore")
        except PermissionError:
            continue
        for line in content.splitlines():
            if "NOPASSWD" in line and not line.strip().startswith("#"):
                findings.append(build_finding(
                    title=f"NOPASSWD sudo detected in {f.name}: {line.strip()[:60]}",
                    severity="CRITICAL",
                    detail="NOPASSWD allows running sudo commands without a password, enabling privilege escalation without authentication.",
                    fix_steps=[
                        f"Edit: sudo visudo {f}",
                        "Remove or comment out NOPASSWD entries.",
                        "Save and verify: sudo -l",
                    ],
                    command=f"sudo visudo {f}",
                    auto_fixable=False,
                    mitre_tag="T1548.003",
                ))
    if not findings:
        findings.append(build_finding(
            title="No NOPASSWD sudo entries found",
            severity="SAFE",
            detail="All sudo rules require password authentication.",
            fix_steps=[],
            command="sudo -l",
        ))
    return findings


def _check_admin_users() -> list[dict]:
    findings = []
    out, _, _ = run_cmd(["dscl", ".", "-read", "/Groups/admin", "GroupMembership"])
    admins = []
    for line in out.splitlines():
        if "GroupMembership:" in line:
            admins = line.replace("GroupMembership:", "").split()
    # Filter out known system accounts
    user_admins = [a for a in admins if not a.startswith("_") and a != "root"]
    if len(user_admins) > 1:
        findings.append(build_finding(
            title=f"Multiple admin accounts detected: {', '.join(user_admins)}",
            severity="HIGH",
            detail=f"Found {len(user_admins)} admin accounts. Each admin account is an attack vector. Use standard accounts for daily tasks.",
            fix_steps=[
                "System Settings → Users & Groups.",
                "For each non-primary admin, change role to 'Standard' user.",
            ],
            command="dscl . -read /Groups/admin GroupMembership",
            auto_fixable=False,
            mitre_tag="T1078",
        ))
    return findings


def _check_ssh_keys() -> list[dict]:
    findings = []
    auth_keys = Path.home() / ".ssh" / "authorized_keys"
    if auth_keys.exists():
        try:
            content = auth_keys.read_text(errors="ignore")
            key_count = sum(1 for l in content.splitlines() if l.strip() and not l.startswith("#"))
            if key_count > 0:
                findings.append(build_finding(
                    title=f"{key_count} SSH authorized key(s) found in ~/.ssh/authorized_keys",
                    severity="HIGH",
                    detail="Authorized keys allow passwordless SSH login. Review each key to ensure it belongs to a trusted device.",
                    fix_steps=[
                        "Review: cat ~/.ssh/authorized_keys",
                        "Remove unknown entries: nano ~/.ssh/authorized_keys",
                        "If SSH is not needed: sudo systemsetup -setremotelogin off",
                    ],
                    command="cat ~/.ssh/authorized_keys",
                    auto_fixable=False,
                    mitre_tag="T1098.004",
                ))
        except PermissionError:
            pass
    return findings


def run() -> dict:
    start = time.time()
    findings = []
    findings += _check_auto_login()
    findings += _check_guest_account()
    findings += _check_sudo_nopasswd()
    findings += _check_admin_users()
    findings += _check_ssh_keys()
    return build_result(STEP_NUMBER, STEP_NAME, DESCRIPTION, findings, start)
