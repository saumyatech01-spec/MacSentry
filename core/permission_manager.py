"""
MacSentry - core/permission_manager.py
macOS TCC permission gating before scan steps that need elevated access.
"""
from __future__ import annotations
import os
import shutil
import subprocess
from pathlib import Path

# Steps that require Full Disk Access
FDA_REQUIRED_STEPS = {5, 6, 8}
# Steps that require network (user-disclosed)
NETWORK_REQUIRED_STEPS = {10}

TCC_DB_PATH = Path.home() / "Library/Application Support/com.apple.TCC/TCC.db"
TMP_TCC_COPY = Path("/tmp/macsentry_tcc_copy.db")


def check_full_disk_access() -> bool:
    """Check if the process has Full Disk Access by reading TCC.db."""
    try:
        with open(TCC_DB_PATH, "rb") as f:
            f.read(1)
        return True
    except PermissionError:
        return False
    except FileNotFoundError:
        return False


def get_tcc_db_copy() -> Path | None:
    """
    Copy TCC.db to a temp location for safe read-only access.
    Never opens the original TCC.db directly.
    Returns path to copy, or None if not accessible.
    """
    if not check_full_disk_access():
        return None
    try:
        shutil.copy2(TCC_DB_PATH, TMP_TCC_COPY)
        os.chmod(TMP_TCC_COPY, 0o400)  # read-only
        return TMP_TCC_COPY
    except Exception:
        return None


def cleanup_tcc_copy() -> None:
    """Remove the temporary TCC.db copy."""
    try:
        TMP_TCC_COPY.unlink(missing_ok=True)
    except Exception:
        pass


def requires_fda(step_number: int) -> bool:
    """Return True if the given step requires Full Disk Access."""
    return step_number in FDA_REQUIRED_STEPS


def requires_network(step_number: int) -> bool:
    """Return True if the given step requires network access."""
    return step_number in NETWORK_REQUIRED_STEPS


def gate_step(step_number: int) -> dict:
    """
    Check permissions for a step before running it.
    Returns {"allowed": bool, "reason": str}
    """
    if requires_fda(step_number) and not check_full_disk_access():
        return {
            "allowed": False,
            "reason": (
                f"Step {step_number} requires Full Disk Access. "
                "Grant it in System Settings → Privacy & Security → Full Disk Access."
            ),
        }
    return {"allowed": True, "reason": ""}
