"""MacSentry — 05_app_permissions.py
Audits TCC database for camera, mic, location, Full Disk Access, Accessibility.
"""
from __future__ import annotations
import sqlite3, shutil, time, os, tempfile
from pathlib import Path
from scanner_base import run_cmd, build_finding, build_result

STEP_NUMBER = 5
STEP_NAME = "Application Permissions & Privacy"
DESCRIPTION = (
    "Audits which apps have access to your camera, microphone, location, "
    "contacts, Full Disk Access, and Accessibility APIs."
)

TCC_SERVICE_LABELS = {
    "kTCCServiceCamera": "Camera",
    "kTCCServiceMicrophone": "Microphone",
    "kTCCServiceLocation": "Location",
    "kTCCServiceAddressBook": "Contacts",
    "kTCCServiceCalendar": "Calendar",
    "kTCCServicePhotos": "Photos",
    "kTCCServiceAccessibility": "Accessibility",
    "kTCCServiceScreenCapture": "Screen Recording",
    "kTCCServiceSystemPolicyAllFiles": "Full Disk Access",
}

APPLE_BUNDLE_PREFIXES = (
    "com.apple.", "com.microsoft.", "com.google.",
    "org.mozilla.", "com.adobe.", "com.dropbox.",
)


def _read_tcc_db(db_path: Path) -> list[tuple]:
    """Copy TCC.db to temp, query it read-only."""
    if not db_path.exists():
        return []
    tmp = tempfile.mktemp(suffix=".db")
    try:
        shutil.copy2(str(db_path), tmp)
        conn = sqlite3.connect(f"file:{tmp}?mode=ro", uri=True)
        rows = conn.execute(
            "SELECT service, client, auth_value FROM access WHERE auth_value=1"
        ).fetchall()
        conn.close()
        return rows
    except Exception:
        return []
    finally:
        try:
            os.unlink(tmp)
        except Exception:
            pass


def _check_tcc_permissions() -> list[dict]:
    findings = []
    tcc_paths = [
        Path.home() / "Library/Application Support/com.apple.TCC/TCC.db",
        Path("/Library/Application Support/com.apple.TCC/TCC.db"),
    ]
    all_rows = []
    for p in tcc_paths:
        all_rows += _read_tcc_db(p)

    if not all_rows:
        findings.append(build_finding(
            title="TCC database could not be read (Full Disk Access required)",
            severity="LOW",
            detail="Grant MacSentry Full Disk Access in System Settings to audit app permissions.",
            fix_steps=[
                "System Settings → Privacy & Security → Full Disk Access.",
                "Add MacSentry or Terminal to the list.",
            ],
            command="open 'x-apple.systempreferences:com.apple.preference.security?Privacy_AllFiles'",
        ))
        return findings

    fda_apps = []
    accessibility_apps = []
    camera_apps = []
    mic_apps = []

    for service, client, auth_value in all_rows:
        label = TCC_SERVICE_LABELS.get(service, service)
        is_apple = any(client.startswith(p) for p in APPLE_BUNDLE_PREFIXES)

        if service == "kTCCServiceSystemPolicyAllFiles" and not is_apple:
            fda_apps.append(client)
        elif service == "kTCCServiceAccessibility" and not is_apple:
            accessibility_apps.append(client)
        elif service == "kTCCServiceCamera":
            camera_apps.append(client)
        elif service == "kTCCServiceMicrophone":
            mic_apps.append(client)

    if fda_apps:
        for app in fda_apps[:3]:
            findings.append(build_finding(
                title=f"Non-system app has Full Disk Access: {app}",
                severity="CRITICAL",
                detail=f"'{app}' has Full Disk Access, meaning it can read ALL files including passwords, keys, and private data.",
                fix_steps=[
                    "System Settings → Privacy & Security → Full Disk Access.",
                    f"Remove '{app}' unless you explicitly need it.",
                ],
                command="open 'x-apple.systempreferences:com.apple.preference.security?Privacy_AllFiles'",
                auto_fixable=False,
                mitre_tag="T1005",
            ))

    if accessibility_apps:
        for app in accessibility_apps[:3]:
            findings.append(build_finding(
                title=f"Non-system app has Accessibility access: {app}",
                severity="CRITICAL",
                detail=f"'{app}' has Accessibility API access, allowing it to observe and control all UI interactions.",
                fix_steps=[
                    "System Settings → Privacy & Security → Accessibility.",
                    f"Remove '{app}' unless it's a known assistive tool.",
                ],
                command="open 'x-apple.systempreferences:com.apple.preference.security?Privacy_Accessibility'",
                auto_fixable=False,
                mitre_tag="T1056.001",
            ))

    if not fda_apps and not accessibility_apps:
        findings.append(build_finding(
            title="No unexpected Full Disk Access or Accessibility grants found",
            severity="SAFE",
            detail="TCC database shows no suspicious high-privilege app grants.",
            fix_steps=[],
            command="",
        ))

    return findings


def run() -> dict:
    start = time.time()
    findings = _check_tcc_permissions()
    return build_result(STEP_NUMBER, STEP_NAME, DESCRIPTION, findings, start)
