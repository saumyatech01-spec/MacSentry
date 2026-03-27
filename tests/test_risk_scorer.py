"""Unit tests — risk_scorer.py"""
import sys, os, unittest
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "core"))
from risk_scorer import calculate_overall_score, score_to_risk_level, color_for_severity


class TestRiskScorer(unittest.TestCase):

    def test_empty_findings_perfect_score(self):
        r = calculate_overall_score([])
        self.assertEqual(r["score"], 100)
        self.assertEqual(r["band"], "Excellent")

    def test_all_critical_zero_score(self):
        f = [{"severity": "CRITICAL"}] * 5
        r = calculate_overall_score(f)
        self.assertEqual(r["score"], 0)
        self.assertEqual(r["band"], "Critical")
        self.assertEqual(r["critical_count"], 5)

    def test_all_safe_perfect_score(self):
        f = [{"severity": "SAFE"}] * 10
        r = calculate_overall_score(f)
        self.assertEqual(r["score"], 100)

    def test_mixed_severity_band_good(self):
        f = [{"severity": "HIGH"}, {"severity": "SAFE"}, {"severity": "SAFE"},
             {"severity": "LOW"}, {"severity": "SAFE"}]
        r = calculate_overall_score(f)
        self.assertGreaterEqual(r["score"], 70)

    def test_score_to_risk_level(self):
        self.assertEqual(score_to_risk_level(95), "LOW")
        self.assertEqual(score_to_risk_level(75), "MEDIUM")
        self.assertEqual(score_to_risk_level(55), "HIGH")
        self.assertEqual(score_to_risk_level(20), "CRITICAL")

    def test_color_for_severity(self):
        self.assertEqual(color_for_severity("CRITICAL"), "#FF3B30")
        self.assertEqual(color_for_severity("safe"), "#8E8E93")

    def test_counts_correct(self):
        f = [{"severity": "CRITICAL"}, {"severity": "HIGH"}, {"severity": "MEDIUM"},
             {"severity": "LOW"}, {"severity": "SAFE"}]
        r = calculate_overall_score(f)
        self.assertEqual(r["critical_count"], 1)
        self.assertEqual(r["high_count"], 1)
        self.assertEqual(r["medium_count"], 1)
        self.assertEqual(r["low_count"], 1)
        self.assertEqual(r["safe_count"], 1)


if __name__ == "__main__":
    unittest.main(verbosity=2)
