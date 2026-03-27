"""
tests/test_sanitizer.py
Pytest unit tests for core/sanitizer.py

Run with:  pytest tests/test_sanitizer.py -v
"""
import sys
import copy
from pathlib import Path

# Allow importing from repo root
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from core.sanitizer import sanitize_finding


# ---------------------------------------------------------------------------
# Helper
# ---------------------------------------------------------------------------

def _clean(payload: dict) -> dict:
    """Return sanitized payload, discarding notes."""
    safe, _ = sanitize_finding(payload)
    return safe


def _notes(payload: dict) -> list[str]:
    """Return only the redaction notes."""
    _, notes = sanitize_finding(payload)
    return notes


# ---------------------------------------------------------------------------
# 1. Original dict is NEVER mutated
# ---------------------------------------------------------------------------

def test_original_not_mutated():
    original = {
        "finding_text": "Device 192.168.1.10 has open port",
        "impact_bullets": ["Data from /Users/john/docs leaked"],
    }
    original_copy = copy.deepcopy(original)
    sanitize_finding(original)
    assert original == original_copy, "sanitize_finding must not mutate the original dict"


# ---------------------------------------------------------------------------
# 2. IPv4 redaction
# ---------------------------------------------------------------------------

def test_ipv4_redacted():
    payload = {"finding_text": "Connection from 192.168.1.105 detected"}
    result = _clean(payload)
    assert "192.168.1.105" not in result["finding_text"]
    assert "[IP_REDACTED]" in result["finding_text"]


def test_ipv4_multiple_occurrences():
    payload = {"finding_text": "Hosts: 10.0.0.1 and 172.16.0.254 are suspect"}
    result = _clean(payload)
    assert "10.0.0.1" not in result["finding_text"]
    assert "172.16.0.254" not in result["finding_text"]


# ---------------------------------------------------------------------------
# 3. MAC address redaction
# ---------------------------------------------------------------------------

def test_mac_colon_redacted():
    payload = {"finding_text": "Interface en0 MAC: aa:bb:cc:dd:ee:ff"}
    result = _clean(payload)
    assert "aa:bb:cc:dd:ee:ff" not in result["finding_text"]
    assert "[MAC_REDACTED]" in result["finding_text"]


def test_mac_dash_redacted():
    payload = {"finding_text": "MAC address 00-1A-2B-3C-4D-5E found"}
    result = _clean(payload)
    assert "00-1A-2B-3C-4D-5E" not in result["finding_text"]
    assert "[MAC_REDACTED]" in result["finding_text"]


# ---------------------------------------------------------------------------
# 4. Username / home path redaction
# ---------------------------------------------------------------------------

def test_unix_home_path_redacted():
    payload = {"finding_text": "File found at /Users/saumya/Library/sensitive.plist"}
    result = _clean(payload)
    assert "saumya" not in result["finding_text"]
    assert "[USERNAME]" in result["finding_text"]


def test_home_path_redacted():
    payload = {"finding_text": "Key stored in /home/ubuntu/keys/id_rsa"}
    result = _clean(payload)
    assert "ubuntu" not in result["finding_text"]
    assert "[USERNAME]" in result["finding_text"]


# ---------------------------------------------------------------------------
# 5. SSID / Wi-Fi network name redaction
# ---------------------------------------------------------------------------

def test_ssid_redacted():
    payload = {"finding_text": 'Connected to SSID: "HomeNetwork_5G"'}
    result = _clean(payload)
    assert "HomeNetwork_5G" not in result["finding_text"]
    assert "[NETWORK_NAME]" in result["finding_text"]


def test_ssid_equals_syntax():
    payload = {"finding_text": "Wi-Fi network ssid=CoffeeShopWifi is open"}
    result = _clean(payload)
    assert "CoffeeShopWifi" not in result["finding_text"]
    assert "[NETWORK_NAME]" in result["finding_text"]


# ---------------------------------------------------------------------------
# 6. Credential pattern redaction
# ---------------------------------------------------------------------------

def test_password_redacted():
    payload = {"finding_text": "Config contains password=MyS3cr3t!"}
    result = _clean(payload)
    assert "MyS3cr3t!" not in result["finding_text"]
    assert "[CREDENTIAL_REDACTED]" in result["finding_text"]


def test_api_key_redacted():
    payload = {"finding_text": "Found api_key=sk-abc123xyz in plist"}
    result = _clean(payload)
    assert "sk-abc123xyz" not in result["finding_text"]
    assert "[CREDENTIAL_REDACTED]" in result["finding_text"]


def test_token_redacted():
    payload = {"finding_text": "token=ghp_abcDEFGHIJKLMNOPQ1234567890 in env"}
    result = _clean(payload)
    assert "ghp_abcDEFGHIJKLMNOPQ1234567890" not in result["finding_text"]
    assert "[CREDENTIAL_REDACTED]" in result["finding_text"]


# ---------------------------------------------------------------------------
# 7. macOS sub-version trimming
# ---------------------------------------------------------------------------

def test_macos_subversion_trimmed():
    payload = {"macos_version": "macOS 14.5.2"}
    result = _clean(payload)
    assert result["macos_version"] == "macOS 14"


def test_macos_major_only_unchanged():
    payload = {"macos_version": "macOS 14"}
    result = _clean(payload)
    assert result["macos_version"] == "macOS 14"


def test_macos_version_in_nested_field():
    payload = {"finding_text": "Running macOS 13.6.1 on this device"}
    result = _clean(payload)
    assert "13.6.1" not in result["finding_text"]
    assert "macOS 13" in result["finding_text"]


# ---------------------------------------------------------------------------
# 8. UUID redaction
# ---------------------------------------------------------------------------

def test_uuid_redacted():
    payload = {"finding_text": "Device ID: 550e8400-e29b-41d4-a716-446655440000"}
    result = _clean(payload)
    assert "550e8400-e29b-41d4-a716-446655440000" not in result["finding_text"]
    assert "[HARDWARE_ID]" in result["finding_text"]


# ---------------------------------------------------------------------------
# 9. SSH fingerprint redaction
# ---------------------------------------------------------------------------

def test_ssh_fingerprint_redacted():
    payload = {"finding_text": "Key fingerprint: SHA256:ABC123xyz/something+here="}
    result = _clean(payload)
    assert "SHA256:ABC123xyz" not in result["finding_text"]
    assert "[SSH_KEY_REDACTED]" in result["finding_text"]


# ---------------------------------------------------------------------------
# 10. Safe fields are preserved
# ---------------------------------------------------------------------------

def test_safe_fields_preserved():
    payload = {
        "module_name": "Network Security",
        "risk_level": "CRITICAL",
        "finding_text": "Firewall is disabled",
        "impact_bullets": ["Direct network exposure"],
        "macos_version": "macOS 14",
    }
    result = _clean(payload)
    assert result["module_name"] == "Network Security"
    assert result["risk_level"] == "CRITICAL"
    assert result["finding_text"] == "Firewall is disabled"
    assert result["impact_bullets"] == ["Direct network exposure"]


# ---------------------------------------------------------------------------
# 11. Redaction notes are returned
# ---------------------------------------------------------------------------

def test_redaction_notes_populated():
    payload = {"finding_text": "IP 10.0.0.1 and MAC aa:bb:cc:dd:ee:ff"}
    notes = _notes(payload)
    assert len(notes) > 0


def test_no_notes_for_clean_payload():
    payload = {
        "module_name": "Encryption",
        "risk_level": "HIGH",
        "finding_text": "FileVault is disabled",
    }
    notes = _notes(payload)
    assert notes == []


# ---------------------------------------------------------------------------
# 12. Nested list sanitization
# ---------------------------------------------------------------------------

def test_nested_list_sanitized():
    payload = {
        "impact_bullets": [
            "Data from /Users/alice/secrets leaked",
            "Remote access from 203.0.113.5",
        ]
    }
    result = _clean(payload)
    assert "alice" not in result["impact_bullets"][0]
    assert "203.0.113.5" not in result["impact_bullets"][1]


# ---------------------------------------------------------------------------
# 13. Before / after diff demo
# ---------------------------------------------------------------------------

def test_before_after_diff_demo():
    """
    Demonstrates a full before/after diff of a realistic finding payload.
    This test always passes — it is documentation as much as verification.
    """
    before = {
        "module_name": "Network Security",
        "risk_level": "HIGH",
        "finding_text": (
            "Device hostname: MacBook-Pro-Saumya connected via SSID: \"HomeWifi5G\" "
            "from 192.168.1.42, MAC aa:bb:cc:dd:ee:ff. "
            "Process EpicGames (PID 3421) on port 24563. "
            "Credential token=ghp_secretABCDEFG detected in /Users/saumya/.env."
        ),
        "macos_version": "macOS 14.4.1",
        "impact_bullets": [
            "Sensitive data at /Users/saumya/Library/logs exposed",
            "api_key=sk-live-xyz123 found in plist",
        ],
    }

    after, notes = sanitize_finding(before)

    # Verify key redactions
    assert "MacBook-Pro-Saumya" not in str(after)
    assert "HomeWifi5G" not in str(after)
    assert "192.168.1.42" not in str(after)
    assert "aa:bb:cc:dd:ee:ff" not in str(after)
    assert "ghp_secretABCDEFG" not in str(after)
    assert "saumya" not in str(after)
    assert "sk-live-xyz123" not in str(after)
    assert after["macos_version"] == "macOS 14"

    # Notes should be non-empty
    assert len(notes) > 0

    # Safe fields preserved
    assert after["module_name"] == "Network Security"
    assert after["risk_level"] == "HIGH"
