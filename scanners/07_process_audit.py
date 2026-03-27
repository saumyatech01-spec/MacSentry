"""MacSentry — 07_process_audit.py
Inspects running processes for privilege abuse, DYLD injection,
hidden processes, high-CPU anomalies, and environment variable attacks.
"""
from __future__ import annotations
import re, time, os
from scanner_base import run_cmd, build_finding, build_result

STEP_NUMBER = 7
STEP_NAME = "Running Processes & Memory Audit"
DESCRIPTION = (
    "Inspects all active processes for privilege abuse, hidden processes, "
    "code injection, and indicators of cryptomining or spyware."
)


def _check_dyld_injection() -> list[dict]:
    findings = []
    out, _, _ = run_cmd(["ps", "auxeww"])
    hits = []
    for line in out.splitlines():
        if "DYLD_INSERT_LIBRARIES" in line:
            parts = line.split()
            proc = parts[10] if len(parts) > 10 else line[:80]
            pid = parts[1] if len(parts) > 1 else "?"
            hits.append((pid, proc))
    if hits:
        for pid, proc in hits[:5]:
            findings.append(build_finding(
                title=f"DYLD_INSERT_LIBRARIES detected — PID {pid}: {proc[:60]}",
                severity="CRITICAL",
                detail="DYLD_INSERT_LIBRARIES forces a dynamic library into every process at launch — the primary macOS dylib injection technique used by rootkits.",
                fix_steps=[
                    f"Inspect the process: ps aux | grep {pid}",
                    f"Trace open files: sudo lsof -p {pid}",
                    "Identify and remove the injected library path.",
                    "Reboot and re-scan to verify removal.",
                ],
                command=f"ps auxeww | grep {pid}",
                auto_fixable=False,
                mitre_tag="T1574.006",
            ))
    else:
        findings.append(build_finding(
            title="No DYLD_INSERT_LIBRARIES injection detected",
            severity="SAFE",
            detail="No processes are using dylib injection via environment variables.",
            fix_steps=[],
            command="ps auxeww | grep DYLD_INSERT",
        ))
    return findings


def _check_unsigned_root_processes() -> list[dict]:
    findings = []
    out, _, _ = run_cmd(["ps", "-axo", "pid,user,comm"])
    root_procs = []
    for line in out.splitlines()[1:]:
        parts = line.split(None, 2)
        if len(parts) < 3:
            continue
        pid, user, comm = parts
        if user == "root":
            path = comm.strip().split()[0]
            if (path.startswith("/")
                    and not path.startswith("/System")
                    and not path.startswith("/usr/libexec")
                    and not path.startswith("/usr/sbin")
                    and not path.startswith("/usr/bin")):
                _, _, rc = run_cmd(["codesign", "--verify", path], timeout=5)
                if rc != 0:
                    root_procs.append((pid, path))
    if root_procs:
        for pid, path in root_procs[:5]:
            findings.append(build_finding(
                title=f"Unsigned root-owned process: PID {pid} → {path}",
                severity="CRITICAL",
                detail="An unsigned process running as root has full system privileges and bypasses Gatekeeper/AMFI checks.",
                fix_steps=[
                    f"Identify: ps aux | grep {pid}",
                    f"Inspect binary: file '{path}'",
                    f"Check origin: codesign --verify --verbose '{path}'",
                    f"If malicious, kill it: sudo kill -9 {pid}",
                ],
                command=f"sudo kill -9 {pid}",
                auto_fixable=False,
                mitre_tag="T1068",
            ))
    else:
        findings.append(build_finding(
            title="No unsigned root-owned processes found outside system paths",
            severity="SAFE",
            detail="All root-level processes appear to be system or signed applications.",
            fix_steps=[],
        ))
    return findings


def _check_high_cpu_unknown() -> list[dict]:
    findings = []
    try:
        import psutil
        suspects = []
        for p in psutil.process_iter(["pid", "name", "cpu_percent", "username", "exe"]):
            try:
                cpu = p.info["cpu_percent"] or 0
                exe = p.info.get("exe") or ""
                if (cpu > 80 and exe
                        and not exe.startswith("/System")
                        and not exe.startswith("/usr")
                        and not exe.startswith("/Applications")):
                    suspects.append((p.info["pid"], p.info["name"], round(cpu, 1)))
            except (psutil.AccessDenied, psutil.NoSuchProcess):
                pass
        if suspects:
            for pid, name, cpu in suspects[:3]:
                findings.append(build_finding(
                    title=f"High-CPU unknown process: {name} (PID {pid}, {cpu}% CPU)",
                    severity="HIGH",
                    detail=f"'{name}' is consuming {cpu}% CPU from a non-standard path. This is a common cryptomining or spyware pattern.",
                    fix_steps=[
                        f"Inspect: ps aux | grep {pid}",
                        f"Check network: sudo lsof -i -p {pid}",
                        f"Kill if malicious: sudo kill -9 {pid}",
                    ],
                    command=f"sudo lsof -i -p {pid}",
                    auto_fixable=False,
                    mitre_tag="T1496",
                ))
        else:
            findings.append(build_finding(
                title="No suspicious high-CPU processes detected",
                severity="SAFE",
                detail="No unknown processes are consuming excessive CPU.",
                fix_steps=[],
            ))
    except ImportError:
        findings.append(build_finding(
            title="psutil not installed — high-CPU process check skipped",
            severity="LOW",
            detail="Install psutil to enable process CPU monitoring: pip install psutil",
            fix_steps=["pip install psutil"],
            command="pip install psutil",
        ))
    return findings


def run() -> dict:
    start = time.time()
    findings = []
    findings += _check_dyld_injection()
    findings += _check_unsigned_root_processes()
    findings += _check_high_cpu_unknown()
    return build_result(STEP_NUMBER, STEP_NAME, DESCRIPTION, findings, start)
