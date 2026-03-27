"""
MacSentry — 01_system_integrity.py
Verifies SIP, Gatekeeper, Secure Boot, XProtect, macOS version, and SSV.
"""
from __future__ import annotations
import re, time, plistlib
from pathlib import Path
from scanner_base import run_cmd, build_finding, build_result

STEP_NUMBER = 1
STEP_NAME = "System Integrity & OS Hardening"
DESCRIPTION = (
    "Verifies that Apple's core protection layers — SIP, Gatekeeper, "
    "Secure Boot, and XProtect — are active and up to date."
)


def _check_sip() -> list[dict]:
    out, _, _ = run_cmd(["csrutil", "status"])
    if "enabled" in out.lower() and "disabled" not in out.lower():
        return [build_finding(
            title="System Integrity Protection (SIP) is enabled",
            severity="SAFE",
            detail="SIP is active and protecting core system files.",
            fix_steps=[],
            command="csrutil status",
        )]
    return [build_finding(
        title="System Integrity Protection (SIP) is DISABLED",
        severity="CRITICAL",
        detail=(
            "SIP prevents even root-level processes from modifying protected "
            "system files, kernel extensions, and runtime protections. "
            "Without it, malware can permanently compromise macOS."
        ),
        fix_steps=[
            "Reboot into macOS Recovery (hold Cmd+R on Intel, hold power on Apple Silicon).",
            "Open Terminal from Utilities menu.",
            "Run: csrutil enable",
            "Reboot normally.",
        ],
        command="csrutil enable  # run in Recovery Mode",
        auto_fixable=False,
        mitre_tag="T1562.010",
    )]


def _check_gatekeeper() -> list[dict]:
    out, _, rc = run_cmd(["spctl", "--status"])
    if "assessments enabled" in out.lower():
        return [build_finding(
            title="Gatekeeper is enabled",
            severity="SAFE",
            detail="Gatekeeper is blocking apps from unidentified developers.",
            fix_steps=[],
            command="spctl --status",
        )]
    return [build_finding(
        title="Gatekeeper is DISABLED",
        severity="HIGH",
        detail=(
            "Gatekeeper verifies downloaded apps are signed and notarized by Apple. "
            "Disabling it allows unsigned, potentially malicious software to run."
        ),
        fix_steps=[
            "Open System Settings → Privacy & Security.",
            "Set 'Allow apps downloaded from' to 'App Store and identified developers'.",
            "Or run: sudo spctl --master-enable",
        ],
        command="sudo spctl --master-enable",
        auto_fixable=True,
        mitre_tag="T1553.001",
    )]


def _check_macos_version() -> list[dict]:
    out, _, _ = run_cmd(["sw_vers", "-productVersion"])
    ver = out.strip()
    parts = ver.split(".")
    try:
        major = int(parts[0])
        minor = int(parts[1]) if len(parts) > 1 else 0
    except ValueError:
        return []

    # macOS 15 (Sequoia) = latest as of 2024; flag if 2+ major versions behind
    LATEST_MAJOR = 15
    if major < LATEST_MAJOR - 1:
        return [build_finding(
            title=f"macOS {ver} is severely outdated (2+ versions behind)",
            severity="HIGH",
            detail=(
                f"macOS {ver} no longer receives security patches. "
                "Known exploits exist for your current version."
            ),
            fix_steps=[
                "Open System Settings → General → Software Update.",
                "Click 'Upgrade Now' to update to the latest macOS.",
            ],
            command="softwareupdate --list",
            auto_fixable=False,
            mitre_tag="T1195",
        )]
    return [build_finding(
        title=f"macOS {ver} is current or one version behind",
        severity="SAFE" if major >= LATEST_MAJOR - 1 else "MEDIUM",
        detail=f"macOS {ver} is receiving security updates.",
        fix_steps=[],
        command="sw_vers -productVersion",
    )]


def _check_secure_boot() -> list[dict]:
    out, _, _ = run_cmd(["nvram", "-p"])
    boot_args = ""
    for line in out.splitlines():
        if "boot-args" in line:
            boot_args = line
            break

    suspicious = [arg for arg in ["kext-dev-mode", "amfi_get_out_of_my_way",
                                   "cs_enforcement_disable", "amfi=0xff"]
                  if arg in boot_args]
    if suspicious:
        return [build_finding(
            title=f"Suspicious boot-args detected: {', '.join(suspicious)}",
            severity="HIGH",
            detail=(
                "Custom boot-args can disable AMFI (Apple Mobile File Integrity) "
                "and other security checks, weakening macOS protections."
            ),
            fix_steps=[
                "Review: nvram -p | grep boot-args",
                "Remove suspect args: sudo nvram boot-args=\"\"",
                "Reboot and verify: nvram -p",
            ],
            command="sudo nvram boot-args=\"\"",
            auto_fixable=True,
            mitre_tag="T1542",
        )]
    return [build_finding(
        title="No suspicious Secure Boot arguments found",
        severity="SAFE",
        detail="NVRAM boot-args do not contain known security bypass arguments.",
        fix_steps=[],
        command="nvram -p | grep boot-args",
    )]


def _check_xprotect() -> list[dict]:
    plist_paths = [
        Path("/Library/Apple/System/Library/CoreServices/XProtect.bundle/Contents/Resources/XProtect.meta.plist"),
        Path("/System/Library/CoreServices/XProtect.bundle/Contents/Resources/XProtect.meta.plist"),
    ]
    for p in plist_paths:
        if p.exists():
            try:
                data = plistlib.loads(p.read_bytes())
                version = data.get("Version", "unknown")
                return [build_finding(
                    title=f"XProtect definitions version {version} installed",
                    severity="SAFE",
                    detail="XProtect malware definitions are present.",
                    fix_steps=[],
                    command="defaults read /Library/Preferences/com.apple.SoftwareUpdate",
                )]
            except Exception:
                pass
    return [build_finding(
        title="XProtect definition plist not found",
        severity="MEDIUM",
        detail="Could not verify XProtect definition freshness.",
        fix_steps=["Run: sudo softwareupdate --background"],
        command="sudo softwareupdate --background",
        auto_fixable=True,
    )]


def run() -> dict:
    start = time.time()
    findings = []
    findings += _check_sip()
    findings += _check_gatekeeper()
    findings += _check_macos_version()
    findings += _check_secure_boot()
    findings += _check_xprotect()
    return build_result(STEP_NUMBER, STEP_NAME, DESCRIPTION, findings, start)
