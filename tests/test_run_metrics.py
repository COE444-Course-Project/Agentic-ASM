import unittest

from run_live import metrics


class RunMetricsTests(unittest.TestCase):
    def test_growth_missing_and_unverified_results_do_not_inflate_repairs(self):
        before = {"findings": [{"id": name, "verdict": True} for name in ("a", "b", "c", "d")], "summary": {}}
        after = {"findings": [{"id": "a", "verdict": False}, {"id": "b", "verdict": False},
                              {"id": "c", "verdict": None}, {"id": "new", "verdict": True}], "summary": {}}
        defense = {"plans": [{"finding_id": "a", "applied": True, "verified": True, "status": "patched"}], "applied": 1, "verified": 1}
        result = metrics(before, defense, after)
        self.assertEqual(result["remediation_rate"], .25)
        self.assertEqual(result["original_vulnerabilities_unresolved"], 2)
        self.assertEqual(result["new_vulnerabilities_during_agents"], 1)

    def test_no_vulnerabilities_is_not_a_hundred_percent_repair_rate(self):
        result = metrics({"findings": [], "summary": {}}, {"plans": [], "applied": 0, "verified": 0}, {"findings": [], "summary": {}})
        self.assertIsNone(result["remediation_rate"])
