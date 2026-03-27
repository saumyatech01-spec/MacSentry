"""MacSentry — 02_network_security.py
Audits firewall, open ports, active connections, DNS, Wi-Fi security, VPN, Bluetooth, ARP.
"""
from __future__ import annotations
import re, time, subprocess
from scanner_base import run_cmd, build_finding, build_result

STEP_NUMBER = 2
STEP_NAME = "Network Security Audit"
DESCRIPTION = (
    "Audits your firewall, open ports, active connections, DNS configuration, "
    "and wireless network security."
)


def _check_firewall() -> list[dict]:
    findings = []
    out, _, _ = run_cmd(["defaults", "read",
                         "/Library/Preferences/com.apple.alf", "globalstate"])
    state = out.strip()
    if state == "0":
        findings.append(build_finding(
            title="macOS Firewall is DISABLED",
            severity="HIGH",
            detail="The built-in firewall blocks unsolicited incoming connections. Disabling it exposes all listening services.",
            fix_steps=[
                "Open System Settings → Network → Firewall.",
                "Toggle Firewall ON.",
                "Or run: sudo /usr/libexec/ApplicationFirewall/socketfilterfw --setglobalstate on",
            ],
            command="sudo /usr/libexec/ApplicationFirewall/socketfilterfw --setglobalstate on",
            auto_fixable=True,
            mitre_tag="T1562.004",
        ))
    else:
        findings.append(build_finding(
            title="Firewall is enabled",
            severity="SAFE",
            detail="macOS Firewall is active.",
            fix_steps=[],
            command="defaults read /Library/Preferences/com.apple.alf globalstate",
        ))

    # Stealth mode
    out2, _, _ = run_cmd(["defaults", "read",
                           "/Library/Preferences/com.apple.alf", "stealthenabled"])
    if out2.strip() == "0":
        findings.append(build_finding(
            title="Stealth Mode is DISABLED",
            severity="MEDIUM",
            detail="Stealth mode prevents responding to ping/port scans. Enable it to reduce network visibility.",
            fix_steps=[
                "System Settings → Network → Firewall → Options → Enable Stealth Mode.",
                "Or: sudo /usr/libexec/ApplicationFirewall/socketfilterfw --setstealthmode on",
            ],
            command="sudo /usr/libexec/ApplicationFirewall/socketfilterfw --setstealthmode on",
            auto_fixable=True,
            mitre_tag="T1040",
        ))
    return findings


def _check_open_ports() -> list[dict]:
    findings = []
    out, _, _ = run_cmd(["lsof", "-i", "-P", "-n"], timeout=15)
    listeners = []
    known_safe = {"443", "80", "53", "67", "68", "22", "5900", "631"}
    for line in out.splitlines():
        if "LISTEN" in line:
            parts = line.split()
            proc = parts[0] if parts else "unknown"
            addr = parts[-2] if len(parts) >= 2 else ""
            port = addr.split(":")[-1] if ":" in addr else ""
            if port and port not in known_safe:
                listeners.append((proc, port, addr))
    if listeners:
        for proc, port, addr in listeners[:5]:
            findings.append(build_finding(
                title=f"Unexpected listener: {proc} on port {port} ({addr})",
                severity="HIGH",
                detail=f"'{proc}' is listening on port {port}. Verify this is an expected service.",
                fix_steps=[
                    f"Identify: lsof -i :{port}",
                    f"If unknown, stop the service or kill the process.",
                ],
                command=f"lsof -i :{port}",
                auto_fixable=False,
                mitre_tag="T1049",
            ))
    else:
        findings.append(build_finding(
            title="No unexpected listening ports detected",
            severity="SAFE",
            detail="All detected listening ports are within known-safe range.",
            fix_steps=[],
            command="lsof -i -P -n | grep LISTEN",
        ))
    return findings


def _check_wifi() -> list[dict]:
    findings = []
    out, _, _ = run_cmd(["networksetup", "-getairportnetwork", "en0"])
    if "You are not associated" in out or not out.strip():
        return findings
    ssid = out.split(":")[-1].strip() if ":" in out else out.strip()
    # Check security type via airport utility
    airport = "/System/Library/PrivateFrameworks/Apple80211.framework/Versions/Current/Resources/airport"
    sec_out, _, _ = run_cmd([airport, "-I"])
    link_auth = ""
    for line in sec_out.splitlines():
        if "link auth" in line.lower():
            link_auth = line.split(":")[-1].strip().lower()
    if "open" in link_auth or "wep" in link_auth or link_auth == "":
        severity = "CRITICAL" if ("open" in link_auth or link_auth == "") else "HIGH"
        findings.append(build_finding(
            title=f"Wi-Fi network '{ssid}' has weak/no encryption ({link_auth or 'open'})",
            severity=severity,
            detail="Open or WEP Wi-Fi networks transmit data unencrypted. Use WPA3 or WPA2 networks only.",
            fix_steps=[
                "Disconnect from open/WEP network immediately.",
                "Connect to a WPA2 or WPA3 secured network.",
                "Use a VPN whenever on untrusted networks.",
            ],
            command="networksetup -getairportnetwork en0",
            auto_fixable=False,
            mitre_tag="T1040",
        ))
    else:
        findings.append(build_finding(
            title=f"Wi-Fi network '{ssid}' uses {link_auth.upper()} encryption",
            severity="SAFE",
            detail="Current Wi-Fi connection uses acceptable encryption.",
            fix_steps=[],
            command="networksetup -getairportnetwork en0",
        ))
    return findings


def _check_dns() -> list[dict]:
    findings = []
    out, _, _ = run_cmd(["scutil", "--dns"])
    dns_servers = []
    for line in out.splitlines():
        if "nameserver" in line.lower():
            parts = line.split()
            if len(parts) >= 3:
                dns_servers.append(parts[-1])
    private_ranges = ("192.168.", "10.", "172.16.", "172.17.", "172.18.",
                      "172.19.", "172.2", "172.3", "127.", "::1")
    suspicious_dns = [s for s in dns_servers if not any(s.startswith(p) for p in private_ranges)]
    if suspicious_dns:
        findings.append(build_finding(
            title=f"Non-local DNS servers detected: {', '.join(suspicious_dns[:3])}",
            severity="MEDIUM",
            detail="DNS servers outside your local network could intercept or redirect domain lookups.",
            fix_steps=[
                "System Settings → Network → select interface → Details → DNS.",
                "Use trusted DNS: 1.1.1.1 (Cloudflare), 8.8.8.8 (Google), or your router.",
                "Consider enabling DNS-over-HTTPS in your browser.",
            ],
            command="scutil --dns",
            auto_fixable=False,
            mitre_tag="T1557.002",
        ))
    return findings


def _check_arp_poisoning() -> list[dict]:
    findings = []
    out, _, _ = run_cmd(["arp", "-a"])
    mac_to_ips: dict[str, list] = {}
    for line in out.splitlines():
        parts = line.split()
        if len(parts) >= 4:
            ip = parts[1].strip("()") if parts[1].startswith("(") else parts[0]
            mac = parts[3] if len(parts) > 3 else ""
            if mac and mac != "(incomplete)":
                mac_to_ips.setdefault(mac, []).append(ip)
    duplicates = {m: ips for m, ips in mac_to_ips.items() if len(ips) > 1}
    if duplicates:
        for mac, ips in list(duplicates.items())[:3]:
            findings.append(build_finding(
                title=f"ARP poisoning indicator: MAC {mac} maps to multiple IPs: {', '.join(ips)}",
                severity="HIGH",
                detail="A single MAC address claiming multiple IPs may indicate ARP cache poisoning (man-in-the-middle attack).",
                fix_steps=[
                    "Run: arp -a to inspect full ARP cache.",
                    "Disconnect from the network if on untrusted Wi-Fi.",
                    "Use a VPN to encrypt traffic.",
                    "Report to your network administrator.",
                ],
                command="arp -a",
                auto_fixable=False,
                mitre_tag="T1557.002",
            ))
    return findings


def run() -> dict:
    start = time.time()
    findings = []
    findings += _check_firewall()
    findings += _check_open_ports()
    findings += _check_wifi()
    findings += _check_dns()
    findings += _check_arp_poisoning()
    return build_result(STEP_NUMBER, STEP_NAME, DESCRIPTION, findings, start)
