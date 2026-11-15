import asyncio
from pathlib import Path
import tempfile
import unittest

from fastapi.testclient import TestClient

from core import state_store as store
from core.lab_policy import read_policy
from core.metrics import write_loop_report
from lab.app import Settings, create_app
from orchestrator import run_closed_loop

TARGET = "http://testserver"


class ClosedLoopTests(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.root = Path(temp.name)
        original = store.STATE_DIR
        self.addCleanup(store.configure, original)
        store.configure(self.root / "agent")
        self.policy = self.root / "policy.json"

    def lab(self, **overrides):
        settings = Settings(state_file=self.root / "scenario.json", policy_file=self.policy, growth_seconds=0,
                            initial_collections=2, max_collections=4, **overrides)
        return TestClient(create_app(settings))

    def loop(self, client, **kwargs):
        return asyncio.run(run_closed_loop(TARGET, self.policy, client, seed=7, **kwargs))

    def test_rounds_grow_surface_and_remediate_everything_found(self):
        with self.lab(vulnerability_probability=.5) as client:
            result = self.loop(client, rounds=3, grow_per_round=3)
            totals = result["totals"]
            self.assertEqual(result["status"], "done")
            self.assertEqual(totals["rounds_completed"], 3)
            self.assertEqual(totals["collections_final"], 11)
            self.assertGreater(totals["vulnerabilities_detected"], 0)
            self.assertEqual(totals["verified_repairs"], totals["vulnerabilities_detected"])
            self.assertEqual(totals["remediation_rate"], 1)
            self.assertEqual(totals["open_after_last_round"], 0)
            self.assertEqual(totals["legit_checks_passed"], totals["legit_checks_total"])
            self.assertEqual([len(r["new_collections"]) for r in result["rounds"]], [5, 3, 3])
            self.assertEqual(sum(len(r["new_exposure"]) for r in result["rounds"]), totals["vulnerabilities_detected"])
            self.assertFalse(client.get("/admin/growth").json()["paused"])
            persisted = store.get_loop()
            self.assertEqual(persisted["current"]["phase"], "finished")
            self.assertNotIn("evidence", persisted)
            phases = [r.get("loop_phase") for r in store.get_rounds()]
            self.assertEqual(phases, ["attack", "verify"] * 3)

    def test_drift_regressions_are_detected_and_repaired(self):
        with self.lab(vulnerability_probability=1) as client:
            result = self.loop(client, rounds=3, grow_per_round=1, drift=1)
            totals = result["totals"]
            self.assertEqual(totals["regressions_detected"], 2)
            self.assertEqual(totals["regressions_repaired"], 2)
            self.assertEqual([len(r["drifted"]) for r in result["rounds"]], [0, 1, 1])
            for r in result["rounds"][1:]:
                self.assertEqual(r["regressions"], [d["collection"] for d in r["drifted"]])
            self.assertEqual(totals["open_after_last_round"], 0)
            self.assertEqual(len(read_policy(self.policy)["collections"]), 5)

    def test_stop_ends_loop_between_rounds_and_report_is_written(self):
        with self.lab() as client:
            def stop_after_first_round():
                loop = store.get_loop()
                return bool(loop and loop["rounds"] and loop["rounds"][0]["metrics"])

            result = self.loop(client, rounds=4, grow_per_round=1, should_stop=stop_after_first_round)
            self.assertEqual(result["status"], "stopped")
            self.assertEqual(result["totals"]["rounds_completed"], 1)
            folder = self.root / "run"
            write_loop_report(folder, result)
            self.assertIn("Closed attacker-defender loop", (folder / "SUMMARY.md").read_text())
            self.assertTrue((folder / "round-1-defender.json").exists())

    def test_lab_restarts_after_loop_grew_past_configured_cap(self):
        with self.lab() as client:
            self.loop(client, rounds=2, grow_per_round=3)
            self.assertEqual(client.get("/admin/growth").json()["collections"], 8)
        with self.lab() as client:
            status = client.get("/admin/growth").json()
            self.assertEqual((status["collections"], status["max_collections"]), (8, 8))


if __name__ == "__main__":
    unittest.main()

