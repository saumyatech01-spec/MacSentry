"""
MacSentry - core/scanner_engine.py
Async orchestrator: runs all 10 scanner modules, emits JSON progress.

Usage:
  python3 core/scanner_engine.py --mode full
  python3 core/scanner_engine.py --mode quick --steps 1,2,4
  python3 core/scanner_engine.py --step network --verbose
  python3 core/scanner_engine.py --output ~/Desktop/report.json
  python3 core/scanner_engine.py --no-cve
"""
from __future__ import annotations
import argparse
import asyncio
import importlib.util
import json
import os
import sys
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

# Add scanners/ to path so modules can import scanner_base
BASE_DIR = Path(__file__).parent.parent
SCANNERS_DIR = BASE_DIR / "scanners"
sys.path.insert(0, str(SCANNERS_DIR))
sys.path.insert(0, str(BASE_DIR / "core"))

STEP_MODULES = [
    "01_system_integrity",
    "02_network_security",
    "03_user_auth",
    "04_encryption",
    "05_app_permissions",
    "06_malware_indicators",
    "07_process_audit",
    "08_startup_persistence",
    "09_browser_security",
    "10_patch_compliance",
]

STEP_NAME_MAP = {
    "network": "02_network_security",
    "auth": "03_user_auth",
    "encryption": "04_encryption",
    "permissions": "05_app_permissions",
    "malware": "06_malware_indicators",
    "process": "07_process_audit",
    "startup": "08_startup_persistence",
    "browser": "09_browser_security",
    "patch": "10_patch_compliance",
    "integrity": "01_system_integrity",
}


def load_module(module_name: str):
    """Dynamically load a scanner module by name."""
    path = SCANNERS_DIR / f"{module_name}.py"
    spec = importlib.util.spec_from_file_location(module_name, path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def run_step(module_name: str, no_cve: bool = False) -> dict:
    """Load and run a single scanner module. Returns the result dict."""
    try:
        mod = load_module(module_name)
        if no_cve and hasattr(mod, "SKIP_CVE"):
            mod.SKIP_CVE = True
        return mod.run()
    except Exception as e:
        step_num = int(module_name.split("_")[0]) if module_name[0].isdigit() else 0
        return {
            "step_number": step_num,
            "step_name": module_name,
            "description": "Scanner module error",
            "status": "skipped",
            "completion_pct": 0.0,
            "findings": [],
            "risk_level": "SAFE",
            "scan_duration_ms": 0,
            "error": str(e),
        }


async def run_scan(
    steps: list[str],
    no_cve: bool = False,
    verbose: bool = False,
    output_path: str | None = None,
) -> dict:
    """Run selected scanner steps asynchronously, emit JSON per step."""
    loop = asyncio.get_event_loop()
    all_findings = []
    results = []
    scan_start = time.time()

    with ThreadPoolExecutor(max_workers=1) as executor:
        for module_name in steps:
            # Emit scanning status
            step_num = int(module_name.split("_")[0]) if module_name[0].isdigit() else 0
            scanning_status = {
                "step_number": step_num,
                "step_name": module_name.replace("_", " ").title(),
                "description": "Running...",
                "status": "scanning",
                "completion_pct": 0.0,
                "findings": [],
                "risk_level": "SAFE",
                "scan_duration_ms": 0,
            }
            print(json.dumps(scanning_status), flush=True)

            result = await loop.run_in_executor(
                executor, run_step, module_name, no_cve
            )
            results.append(result)
            all_findings.extend(result.get("findings", []))

            # Emit completed step result
            print(json.dumps(result), flush=True)
            if verbose:
                print(
                    f"[Step {step_num}] {result.get('step_name')} — "
                    f"{result.get('risk_level')} — "
                    f"{len(result.get('findings', []))} findings "
                    f"({result.get('scan_duration_ms')}ms)",
                    file=sys.stderr,
                )

    # Calculate overall score
    try:
        from risk_scorer import calculate_overall_score
        overall = calculate_overall_score(all_findings)
    except ImportError:
        overall = {"score": 0, "band": "Unknown", "critical_count": 0, "high_count": 0,
                   "medium_count": 0, "low_count": 0, "safe_count": 0, "total_findings": 0}

    summary = {
        "overall": overall,
        "steps": results,
        "total_duration_ms": int((time.time() - scan_start) * 1000),
    }
    print(json.dumps(summary), flush=True)

    # Save report
    save_path = output_path or _default_save_path()
    _save_report(summary, save_path)
    if verbose:
        print(f"\nReport saved to: {save_path}", file=sys.stderr)

    return summary


def _default_save_path() -> str:
    reports_dir = Path.home() / "Library/Application Support/MacSentry/scans"
    reports_dir.mkdir(parents=True, exist_ok=True)
    ts = time.strftime("%Y%m%d_%H%M%S")
    return str(reports_dir / f"scan_{ts}.json")


def _save_report(summary: dict, path: str) -> None:
    try:
        with open(path, "w") as f:
            json.dump(summary, f, indent=2)
    except Exception as e:
        print(f"Warning: Could not save report: {e}", file=sys.stderr)


def main() -> None:
    parser = argparse.ArgumentParser(
        description="MacSentry — macOS Security Scanner",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "--mode", choices=["full", "quick"], default="full",
        help="full = all 10 steps; quick = selected steps via --steps"
    )
    parser.add_argument(
        "--steps", type=str, default=None,
        help="Comma-separated step numbers, e.g. 1,2,4"
    )
    parser.add_argument(
        "--step", type=str, default=None,
        help="Single step name, e.g. network, auth, browser"
    )
    parser.add_argument(
        "--no-cve", action="store_true",
        help="Skip network CVE lookup in Step 10"
    )
    parser.add_argument(
        "--verbose", "-v", action="store_true",
        help="Print step summaries to stderr"
    )
    parser.add_argument(
        "--output", type=str, default=None,
        help="Custom path for JSON report output"
    )
    args = parser.parse_args()

    # Determine which steps to run
    if args.step:
        module_name = STEP_NAME_MAP.get(args.step.lower())
        if not module_name:
            print(f"Unknown step name: {args.step}", file=sys.stderr)
            sys.exit(1)
        selected = [module_name]
    elif args.steps:
        nums = [int(n.strip()) for n in args.steps.split(",")]
        selected = [STEP_MODULES[n - 1] for n in nums if 1 <= n <= 10]
    else:
        selected = STEP_MODULES

    asyncio.run(
        run_scan(
            steps=selected,
            no_cve=args.no_cve,
            verbose=args.verbose,
            output_path=args.output,
        )
    )


if __name__ == "__main__":
    main()
