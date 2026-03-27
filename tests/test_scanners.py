"""
Integration tests with mocked subprocess calls.
Tests each scanner's output schema and severity logic.
"""
import sys, os, unittest
from unittest.mock import patch, MagicMock

SCANNERS_DIR = os.path.join(os.path.dirname(__file__), "..", "scanners")
sys.path.insert(0, SCANNERS_DIR)

REQUIRED_KEYS = {
    "step_number", "step_name", "description",
    "status", "completion_pct", "findings",
    "risk_level", "scan_duration_ms"
}
FINDING_KEYS = {
    "title", "severity", "detail", "fix_steps",
    "command", "auto_fixable", "mitre_tag"
}
VALID_SEVERITIES = {"CRITICAL", "HIGH", "MEDIUM", "LOW", "SAFE"}
VALID_STATUSES = {"scanning", "complete", "issues_found", "skipped"}


def _validate_result(tc: unittest.TestCase, r: dict, step: int):
    tc.assertEqual(r["step_number"], step)
    for key in REQUIRED_KEYS:
        tc.assertIn(key, r, f"Missing key '{key}' in step {step}")
    tc.assertIsInstance(r["completion_pct"], float)
    tc.assertIn(r["status"], VALID_STATUSES)
    for f in r["findings"]:
        for fkey in FINDING_KEYS:
            tc.assertIn(fkey, f, f"Finding missing key '{fkey}'")
        tc.assertIn(f["severity"], VALID_SEVERITIES)


# Patch subprocess.run globally so no real commands execute
MOCK_CMD = MagicMock()
MOCK_CMD.stdout = ""
MOCK_CMD.stderr = ""
MOCK_CMD.returncode = 0


@patch("subprocess.run", return_value=MOCK_CMD)
class TestAllScanners(unittest.TestCase):

    def _run_module(self, filename: str, step: int, mock_run):
        import importlib.util
        path = os.path.join(SCANNERS_DIR, filename)
        if not os.path.exists(path):
            self.skipTest(f"{filename} not found")
        spec = importlib.util.spec_from_file_location(f"s{step}", path)
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        result = mod.run()
        _validate_result(self, result, step)
        return result

    def test_01_system_integrity(self, _):
        self._run_module("01_system_integrity.py", 1, _)

    def test_02_network_security(self, _):
        self._run_module("02_network_security.py", 2, _)

    def test_03_user_auth(self, _):
        self._run_module("03_user_auth.py", 3, _)

    def test_04_encryption(self, _):
        self._run_module("04_encryption.py", 4, _)

    def test_05_app_permissions(self, _):
        self._run_module("05_app_permissions.py", 5, _)

    def test_06_malware_indicators(self, _):
        self._run_module("06_malware_indicators.py", 6, _)

    def test_07_process_audit(self, _):
        self._run_module("07_process_audit.py", 7, _)

    def test_08_startup_persistence(self, _):
        self._run_module("08_startup_persistence.py", 8, _)

    def test_09_browser_security(self, _):
        self._run_module("09_browser_security.py", 9, _)

    def test_10_patch_compliance(self, _):
        self._run_module("10_patch_compliance.py", 10, _)


if __name__ == "__main__":
    unittest.main(verbosity=2)
