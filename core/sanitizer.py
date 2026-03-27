"""
MacSentry - core/sanitizer.py
Sanitizes finding payloads before sending to any LLM API.
Strips all PII, device identifiers, credentials, and sensitive
network/system data. Returns a safe copy + redaction audit log.
"""
from __future__ import annotations

import copy
import re
from typing import Any

# ---------------------------------------------------------------------------
# Redaction patterns
# ---------------------------------------------------------------------------

_PATTERNS: list[tuple[str, re.Pattern[str], str]] = [
    # IPv4
    (
        "IPv4 address",
        re.compile(
            r"\b(?:\d{1,3}\.){3}\d{1,3}\b"
        ),
        "[IP_REDACTED]",
    ),
    # IPv6 (simplified)
    (
        "IPv6 address",
        re.compile(
            r"\b(?:[0-9a-fA-F]{1,4}:){2,7}[0-9a-fA-F]{1,4}\b"
            r"|\b::(?:[0-9a-fA-F]{1,4}:)*[0-9a-fA-F]{1,4}\b"
        ),
        "[IP_REDACTED]",
    ),
    # MAC address  (xx:xx:xx:xx:xx:xx or xx-xx-xx-xx-xx-xx)
    (
        "MAC address",
        re.compile(
            r"\b([0-9a-fA-F]{2}[:\-]){5}[0-9a-fA-F]{2}\b"
        ),
        "[MAC_REDACTED]",
    ),
    # /Users/<username>/  or  /home/<username>/
    (
        "Unix home path username",
        re.compile(r"/(Users|home)/([^/\s]+)/"),
        r"/\1/[USERNAME]/",
    ),
    # Standalone username= or user= patterns
    (
        "Credential pattern (user)",
        re.compile(r"(?i)\b(username|user)\s*=\s*\S+"),
        r"\1=[USERNAME]",
    ),
    # password / token / secret / key / api_key
    (
        "Credential pattern (secret)",
        re.compile(
            r"(?i)\b(password|passwd|token|secret|api[_-]key|apikey|key)\s*[=:]\s*\S+"
        ),
        r"\1=[CREDENTIAL_REDACTED]",
    ),
    # SSH key content marker
    (
        "SSH key content",
        re.compile(
            r"-----BEGIN [A-Z ]+KEY-----.*?-----END [A-Z ]+KEY-----",
            re.DOTALL,
        ),
        "[SSH_KEY_REDACTED]",
    ),
    # SSH fingerprint (e.g. SHA256:xxxx)
    (
        "SSH fingerprint",
        re.compile(r"\b(MD5|SHA256):[A-Za-z0-9+/=:]{10,}\b"),
        "[SSH_KEY_REDACTED]",
    ),
    # Wi-Fi SSID pattern  (SSID: "MyNetwork" or ssid=MyNetwork)
    (
        "Wi-Fi SSID",
        re.compile(r"(?i)\b(ssid|network name|wi-?fi network)\s*[=:"\u201c]\s*["\u201c]?([^"\u201d\s,]+)["\u201d]?"),
        r"\1: [NETWORK_NAME]",
    ),
    # Hardware serial numbers (common macOS format: C02 prefix or 10-12 alphanum)
    (
        "Hardware serial number",
        re.compile(r"\b(serial\s*(?:number|no\.?|#)?\s*[=:]?\s*)[A-Z0-9]{8,14}\b", re.IGNORECASE),
        r"\1[HARDWARE_ID]",
    ),
    # UUID v4
    (
        "UUID",
        re.compile(
            r"\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-4[0-9a-fA-F]{3}-"
            r"[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}\b"
        ),
        "[HARDWARE_ID]",
    ),
    # Hostname / device name context  (hostname: foo.local  or device: MacBook-Pro)
    (
        "Hostname/device name",
        re.compile(r"(?i)\b(hostname|device name|computer name|device)\s*[=:]\s*([\w.-]+)"),
        r"\1: [DEVICE]",
    ),
    # PID + process name in port context
    # e.g. "EpicGames (PID 1234) on port 24563"  -->  "Unknown process on port 24563"
    (
        "Process name in port context",
        re.compile(
            r"([\w. -]+?)\s*(?:\(PID\s*\d+\))?\s*(?:is listening |on port |:)(\d{1,5})",
            re.IGNORECASE,
        ),
        r"Unknown process on port \2",
    ),
]

# macOS sub-version trimmer: "macOS 14.5.2" -> "macOS 14"
_MACOS_VERSION_RE = re.compile(
    r"(?i)(macos\s+)(\d+)(\.\d+)+"
)


# ---------------------------------------------------------------------------
# Public interface
# ---------------------------------------------------------------------------

def sanitize_finding(payload: dict[str, Any]) -> tuple[dict[str, Any], list[str]]:
    """
    Sanitize a MacSentry finding payload before LLM submission.

    Args:
        payload: The raw finding dict (never mutated).

    Returns:
        A tuple of:
          - sanitized_payload: deep copy with all PII redacted.
          - redaction_notes:   list of human-readable log entries describing
                               what was removed, for audit logging.
    """
    safe = copy.deepcopy(payload)
    notes: list[str] = []

    _sanitize_value(safe, notes)

    return safe, notes


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _sanitize_str(text: str, notes: list[str]) -> str:
    """Apply all redaction patterns to a single string."""
    # First trim macOS sub-version
    new_text, n = _MACOS_VERSION_RE.subn(r"\1\2", text)
    if n:
        notes.append(f"macOS sub-version trimmed in: '{text[:60]}...'" if len(text) > 60 else f"macOS sub-version trimmed")
    text = new_text

    for label, pattern, replacement in _PATTERNS:
        new_text, n = pattern.subn(replacement, text)
        if n:
            notes.append(f"Redacted {n}x [{label}]")
        text = new_text

    return text


def _sanitize_value(obj: Any, notes: list[str]) -> Any:
    """Recursively walk and sanitize dicts, lists, and strings in-place."""
    if isinstance(obj, dict):
        for k, v in obj.items():
            obj[k] = _sanitize_value(v, notes)
    elif isinstance(obj, list):
        for i, item in enumerate(obj):
            obj[i] = _sanitize_value(item, notes)
    elif isinstance(obj, str):
        return _sanitize_str(obj, notes)
    return obj
