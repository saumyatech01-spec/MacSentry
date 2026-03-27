# 🛡️ MacSentry — macOS Security Scanner v1.0

Production-grade, **read-only** security audit tool for Apple Silicon and Intel MacBook Pro running macOS 13 Ventura and above.

![Python](https://img.shields.io/badge/Python-3.12+-blue) ![Swift](https://img.shields.io/badge/SwiftUI-macOS%2013+-orange) ![License](https://img.shields.io/badge/License-MIT-green) ![Platform](https://img.shields.io/badge/Platform-macOS%2013%2B-lightgrey)

---

## 🏗️ Architecture

```
MacSentry/
├── core/
│   ├── scanner_engine.py        # Async orchestrator (asyncio)
│   ├── permission_manager.py    # macOS TCC gating (FDA, network disclosure)
│   ├── risk_scorer.py           # CVSS-inspired scoring
│   └── report_generator.py      # PDF (ReportLab) + JSON export
├── scanners/
│   ├── scanner_base.py          # Shared utilities (run_cmd, build_finding)
│   ├── 01_system_integrity.py   # SIP, Gatekeeper, XProtect, SSV
│   ├── 02_network_security.py   # Firewall, ports, DNS, Wi-Fi, ARP
│   ├── 03_user_auth.py          # Login, sudo, SSH, screen lock
│   ├── 04_encryption.py         # FileVault, Keychain, certs
│   ├── 05_app_permissions.py    # TCC DB audit, App Sandbox
│   ├── 06_malware_indicators.py # LaunchAgents, kexts, cron, IOCs
│   ├── 07_process_audit.py      # DYLD injection, root processes, CPU
│   ├── 08_startup_persistence.py# Login Items, shell profiles, NMH
│   ├── 09_browser_security.py   # Extensions, CVEs, Safe Browsing
│   └── 10_patch_compliance.py   # OSV.dev/NVD CVE lookup, Homebrew
├── ui/                          # SwiftUI native macOS dashboard
│   ├── MacSentryApp.swift
│   ├── ScanStateModel.swift     # @MainActor ViewModel + Python bridge
│   ├── DashboardView.swift      # Main layout (HSplitView)
│   ├── ScanCardView.swift       # Animated per-step cards
│   ├── RemediationPanel.swift   # Slide-in fix guide with auto-fix
│   ├── FindingsSummaryView.swift
│   └── Color+Hex.swift
└── tests/
    ├── test_risk_scorer.py      # 7 unit tests
    └── test_scanners.py         # 10 integration tests (subprocess mocked)
```

---

## 📋 Requirements

```bash
# Python 3.12+
pip install psutil reportlab

# Optional (for CVE scanning)
pip install requests

# macOS 13+ (Ventura or later)
# Xcode 15+ for SwiftUI build
```

---

## 🚀 Quick Start — CLI

### 1. Clone the repo
```bash
git clone https://github.com/saumyatech01-spec/MacSentry.git
cd MacSentry
```

### 2. Set up Python environment
```bash
python3.12 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

### 3. Run scans
```bash
# Full scan (all 10 steps)
python3 core/scanner_engine.py --mode full --verbose

# Quick scan of selected steps
python3 core/scanner_engine.py --mode quick --steps 1,2,4

# Single module
python3 core/scanner_engine.py --step network --verbose

# Skip CVE network lookup
python3 core/scanner_engine.py --no-cve

# Custom output path
python3 core/scanner_engine.py --output ~/Desktop/audit.json
```

---

## 🔒 Permissions Required

| Permission | When | Why |
|---|---|---|
| **Full Disk Access** | Steps 5, 6, 8 | Read TCC.db copy, LaunchDaemons, shell profiles |
| **Network** | Step 10 (user-disclosed) | OSV.dev CVE API, NVD API |

> No other system permissions are requested.
> Zero telemetry — all data stays in `~/Library/Application Support/MacSentry/scans/`

---

## 🖥️ SwiftUI Build (Xcode)

1. Create new macOS App target in Xcode (Swift, SwiftUI)
2. Add `ui/*.swift` files to the Xcode target
3. Copy `core/` and `scanners/` into `Resources/` within the `.app` bundle
4. In `Info.plist` add:
```xml
<key>NSAppleEventsUsageDescription</key>
<string>MacSentry uses AppleScript to read Login Items</string>
```
5. Enable **Hardened Runtime** + **Disable Library Validation** for Python subprocess

---

## 🧪 Run Tests

```bash
# Unit tests
python3 -m pytest tests/test_risk_scorer.py -v

# Integration tests (no real commands run)
python3 -m pytest tests/test_scanners.py -v

# All tests
python3 -m pytest tests/ -v --tb=short
```

---

## 🛡️ Safety Model

- ✅ **100% read-only** — zero file writes during scan
- ✅ TCC.db accessed via **temporary copy only** — never opened directly
- ✅ Every auto-fix requires a **confirmation dialog** with password prompt
- ✅ Auto-fix uses `NSAppleScript` with `administrator privileges` (user must authenticate)
- ✅ All elevated ops produce a **local audit log** in `~/Library/Logs/MacSentry/`
- ✅ **Zero telemetry** — only OSV.dev/NVD API queries (disclosed before Step 10)
- ✅ User can **skip any step** via `--steps` flag or UI toggle
- ✅ Results saved **locally only** to `~/Library/Application Support/MacSentry/scans/`

---

## 📊 Severity Scale

| Level | Score Weight | Color |
|---|---|---|
| CRITICAL | 10.0 | `#FF3B30` |
| HIGH | 7.0 | `#FF9500` |
| MEDIUM | 4.0 | `#FFCC00` |
| LOW | 1.0 | `#34C759` |
| SAFE | 0.0 | `#8E8E93` |

**Overall Score** = `max(0, 100 − (sum_of_penalties / max_possible × 100))`

| Score Range | Band |
|---|---|
| 90–100 | Excellent |
| 70–89 | Good |
| 50–69 | Fair |
| 30–49 | Poor |
| 0–29 | Critical |

---

## 🔍 MITRE ATT&CK Coverage

| Technique | Scanner Module |
|---|---|
| T1543.004 — LaunchDaemon persistence | 06, 08 |
| T1574.006 — DYLD injection | 07 |
| T1078 — Valid accounts / auto-login | 03 |
| T1053 — Cron/AT jobs | 06, 08 |
| T1176 — Browser extensions | 08, 09 |
| T1059.004 — Shell backdoors | 08 |
| T1040 — Network sniffing | 02 |
| T1557.002 — ARP poisoning | 02 |
| T1486 — No FileVault | 04 |
| T1496 — Cryptomining | 07 |
| T1203 — Browser exploits | 09 |
| T1195 — Outdated packages | 10 |

---

## 📁 10 Scan Modules

| # | Module | Key Checks |
|---|---|---|
| 1 | System Integrity | SIP, Gatekeeper, XProtect, Secure Boot, SSV |
| 2 | Network Security | Firewall, open ports, DNS, Wi-Fi security, ARP |
| 3 | User Authentication | Auto-login, sudo NOPASSWD, SSH keys, screen lock |
| 4 | Encryption | FileVault 2, Keychain lock, expired certs |
| 5 | App Permissions | TCC DB audit, Full Disk Access, Accessibility |
| 6 | Malware Indicators | LaunchAgents/Daemons, kexts, cron, IOC matching |
| 7 | Process Audit | DYLD injection, unsigned root procs, high-CPU |
| 8 | Startup Persistence | Login Items, shell profiles, native messaging hosts |
| 9 | Browser Security | Extensions, outdated versions, Safe Browsing |
| 10 | Patch Compliance | OSV.dev CVE lookup, Homebrew, Python/Node EOL |

---

## 📦 Auto Bootstrap

```bash
# Run the bootstrap script to auto-setup everything on your Mac
chmod +x bootstrap_macsentry.sh
./bootstrap_macsentry.sh
```

---

*Built with Python 3.12 + SwiftUI · macOS 13 Ventura+ · Apple Silicon & Intel*
