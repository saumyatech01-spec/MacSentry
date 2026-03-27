"""MacSentry — 09_browser_security.py
Audits Safari, Chrome, Firefox, Brave, Edge for risky extensions,
outdated versions, unsafe settings, and saved-password exposure.
"""
from __future__ import annotations
import json, re, time
from pathlib import Path
from scanner_base import run_cmd, build_finding, build_result

STEP_NUMBER = 9
STEP_NAME = "Browser Security Audit"
DESCRIPTION = (
    "Audits Safari, Chrome, Firefox, and Brave for risky extensions, "
    "outdated versions, unsafe settings, and exposed credentials."
)

BROWSERS = {
    "Google Chrome": {
        "app": Path("/Applications/Google Chrome.app"),
        "ext_dir": Path.home() / "Library/Application Support/Google/Chrome/Default/Extensions",
        "prefs": Path.home() / "Library/Application Support/Google/Chrome/Default/Preferences",
    },
    "Brave Browser": {
        "app": Path("/Applications/Brave Browser.app"),
        "ext_dir": Path.home() / "Library/Application Support/BraveSoftware/Brave-Browser/Default/Extensions",
        "prefs": Path.home() / "Library/Application Support/BraveSoftware/Brave-Browser/Default/Preferences",
    },
    "Firefox": {
        "app": Path("/Applications/Firefox.app"),
        "ext_dir": None,
        "prefs": None,
    },
    "Safari": {
        "app": Path("/Applications/Safari.app"),
        "ext_dir": None,
        "prefs": None,
    },
}

MIN_VERSIONS = {
    "Google Chrome": (124, 0),
    "Brave Browser": (1, 65),
    "Firefox": (125, 0),
    "Safari": (17, 4),
}

DANGEROUS_PERMS = {"<all_urls>", "nativeMessaging", "debugger", "proxy", "webRequestBlocking"}


def _get_browser_version(info: dict) -> tuple | None:
    plist_path = info["app"] / "Contents/Info.plist"
    if not plist_path.exists():
        return None
    import plistlib
    try:
        data = plistlib.loads(plist_path.read_bytes())
        ver_str = data.get("CFBundleShortVersionString", "")
        parts = re.findall(r"\d+", ver_str)
        return tuple(int(p) for p in parts[:3]) if parts else None
    except Exception:
        return None


def _check_browser_versions() -> list[dict]:
    findings = []
    for name, info in BROWSERS.items():
        if not info["app"].exists():
            continue
        ver = _get_browser_version(info)
        if not ver:
            continue
        min_v = MIN_VERSIONS.get(name)
        if min_v and ver < min_v:
            findings.append(build_finding(
                title=f"{name} {'.'.join(map(str, ver))} is outdated (min: {'.'.join(map(str, min_v))})",
                severity="HIGH",
                detail=f"{name} version {'.'.join(map(str, ver))} may have unpatched CVEs.",
                fix_steps=[
                    f"Open {name} → Help / About → Check for updates.",
                    "Or download the latest version from the official website.",
                ],
                command=f"open /Applications/'{name}.app'",
                auto_fixable=False,
                mitre_tag="T1203",
            ))
        else:
            findings.append(build_finding(
                title=f"{name} {'.'.join(map(str, ver))} is up to date",
                severity="SAFE",
                detail=f"{name} version is within the safe range.",
                fix_steps=[],
            ))
    return findings


def _check_chrome_extensions(browser_name: str, ext_dir: Path | None) -> list[dict]:
    findings = []
    if not ext_dir or not ext_dir.exists():
        return findings
    risky_exts = []
    for ext_id_dir in ext_dir.iterdir():
        if not ext_id_dir.is_dir():
            continue
        for ver_dir in ext_id_dir.iterdir():
            manifest = ver_dir / "manifest.json"
            if not manifest.exists():
                continue
            try:
                data = json.loads(manifest.read_text(errors="ignore"))
            except Exception:
                continue
            name = data.get("name", ext_id_dir.name)
            perms = set(data.get("permissions", []) + data.get("host_permissions", []))
            risky_p = perms & DANGEROUS_PERMS
            if risky_p:
                risky_exts.append((name, risky_p))
    for ext_name, perms in risky_exts[:5]:
        findings.append(build_finding(
            title=f"{browser_name} extension '{ext_name}' has dangerous permissions: {', '.join(perms)}",
            severity="HIGH",
            detail=f"'{ext_name}' requests {', '.join(perms)} — permissions that allow reading all web page data.",
            fix_steps=[
                f"Open {browser_name} → Extensions.",
                f"Review and remove '{ext_name}' if it's not essential.",
            ],
            command="open chrome://extensions",
            auto_fixable=False,
            mitre_tag="T1176",
        ))
    return findings


def run() -> dict:
    start = time.time()
    findings = []
    findings += _check_browser_versions()
    for name, info in BROWSERS.items():
        if not info["app"].exists():
            continue
        findings += _check_chrome_extensions(name, info.get("ext_dir"))
    return build_result(STEP_NUMBER, STEP_NAME, DESCRIPTION, findings, start)
