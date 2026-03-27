"""MacSentry — 04_encryption.py
Validates FileVault, Keychain lock, certificate integrity, volume encryption.
"""
from __future__ import annotations
import re, time, plistlib
from pathlib import Path
from scanner_base import run_cmd, build_finding, build_result

STEP_NUMBER = 4
STEP_NAME = "Encryption & Data Protection"
DESCRIPTION = (
    "Validates FileVault disk encryption, Keychain lock settings, "
    "certificate integrity, and volume-level encryption status."
)


def _check_filevault() -> list[dict]:
    findings = []
    out, _, _ = run_cmd(["fdesetup", "status"])
    if "On" in out:
        findings.append(build_finding(
            title="FileVault 2 is enabled",
            severity="SAFE",
            detail="Full-disk encryption is active. Data is protected if the device is lost or stolen.",
            fix_steps=[],
            command="fdesetup status",
        ))
    else:
        findings.append(build_finding(
            title="FileVault 2 is DISABLED",
            severity="CRITICAL",
            detail="Without FileVault, anyone with physical access can read all data by booting into Recovery Mode.",
            fix_steps=[
                "System Settings → Privacy & Security → FileVault.",
                "Click 'Turn On FileVault...' and follow the wizard.",
                "Save the recovery key in a secure location.",
            ],
            command="sudo fdesetup enable",
            auto_fixable=False,
            mitre_tag="T1486",
        ))
    return findings


def _check_volumes() -> list[dict]:
    findings = []
    out, _, _ = run_cmd(["diskutil", "list", "-plist"])
    try:
        data = plistlib.loads(out.encode() if isinstance(out, str) else out)
        all_disks = data.get("AllDisksAndPartitions", [])
        for disk in all_disks:
            for part in disk.get("Partitions", []):
                name = part.get("VolumeName", "")
                vtype = part.get("Content", "")
                if "APFS" in vtype and "Boot" not in name and "Recovery" not in name:
                    # Check if it's encrypted
                    v_out, _, _ = run_cmd(["diskutil", "info", part.get("DeviceIdentifier", "")])
                    if "FileVault" in v_out and "No" in v_out:
                        findings.append(build_finding(
                            title=f"APFS volume '{name}' is not encrypted",
                            severity="MEDIUM",
                            detail=f"Volume '{name}' is an APFS partition without FileVault encryption.",
                            fix_steps=["Enable FileVault via System Settings → Privacy & Security."],
                            command=f"diskutil info {part.get('DeviceIdentifier', '')}",
                            auto_fixable=False,
                            mitre_tag="T1486",
                        ))
    except Exception:
        pass
    return findings


def _check_keychain() -> list[dict]:
    findings = []
    out, _, rc = run_cmd(["security", "show-keychain-info",
                          str(Path.home() / "Library/Keychains/login.keychain-db")])
    if rc == 0:
        if "no-timeout" in out.lower() or "timeout=0" in out.lower():
            findings.append(build_finding(
                title="Login Keychain never auto-locks",
                severity="HIGH",
                detail="A keychain that never locks leaves credentials accessible to any process running as your user.",
                fix_steps=[
                    "Open Keychain Access app.",
                    "Keychain Access → Settings → set 'Lock after X minutes of inactivity'.",
                    "Recommended: 5-15 minutes.",
                ],
                command="security set-keychain-settings -t 300 ~/Library/Keychains/login.keychain-db",
                auto_fixable=True,
                mitre_tag="T1555.001",
            ))
    return findings


def _check_certificates() -> list[dict]:
    findings = []
    out, _, _ = run_cmd(["security", "find-certificate", "-a", "-p"])
    import datetime
    expired = []
    # Parse PEM certs and check expiry via openssl
    certs = re.findall(r"-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----", out, re.DOTALL)
    for i, cert in enumerate(certs[:20]):
        tmp = f"/tmp/macsentry_cert_{i}.pem"
        try:
            Path(tmp).write_text(cert)
            exp_out, _, _ = run_cmd(["openssl", "x509", "-noout", "-enddate", "-in", tmp])
            if "notAfter" in exp_out:
                date_str = exp_out.split("=")[-1].strip()
                try:
                    exp_date = datetime.datetime.strptime(date_str, "%b %d %H:%M:%S %Y %Z")
                    if exp_date < datetime.datetime.utcnow():
                        expired.append(date_str)
                except ValueError:
                    pass
        except Exception:
            pass
    if expired:
        findings.append(build_finding(
            title=f"{len(expired)} expired certificate(s) found in Keychain",
            severity="MEDIUM",
            detail="Expired certificates can cause TLS failures and may indicate stale/compromised credential stores.",
            fix_steps=[
                "Open Keychain Access app.",
                "View → Show Expired Certificates.",
                "Delete expired certs that are no longer needed.",
            ],
            command="security find-certificate -a | openssl x509 -noout -enddate",
            auto_fixable=False,
        ))
    return findings


def run() -> dict:
    start = time.time()
    findings = []
    findings += _check_filevault()
    findings += _check_volumes()
    findings += _check_keychain()
    findings += _check_certificates()
    return build_result(STEP_NUMBER, STEP_NAME, DESCRIPTION, findings, start)
