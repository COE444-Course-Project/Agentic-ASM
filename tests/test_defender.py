import asyncio
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from core import state_store as store
from orchestrator import run_defender_round


class DefenderDraftTests(unittest.TestCase):
    def test_target_isolation_unknown_recipe_and_no_fake_patch(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            with patch.multiple(store, STATE_DIR=root, FINDINGS_PATH=root / "findings.json",
                                EVENTS_PATH=root / "events.jsonl", DEFENDER_PATH=root / "defender.json"):
                target = "http://vampi-vulnerable:5000"
                for base in (target, "http://vampi-secure:5000"):
                    for module, verdict in (("bola-book", True), ("unknown", True), ("safe", False), ("uncertain", None)):
                        store.upsert_finding({"id": store.finding_id(base, module), "module_id": module,
                                              "target": base, "verdict": verdict}, 1)
                store.upsert_finding({"id": "legacy", "verdict": True}, 1)
                before = store.get_findings()
                report = asyncio.run(run_defender_round(target))
                self.assertEqual(len(report["plans"]), 2)
                self.assertEqual({p["status"] for p in report["plans"]}, {"proposed", "needs_review"})
                self.assertTrue(all(not p["applied"] and not p["verified"] for p in report["plans"]))
                self.assertEqual(store.get_findings(), before)
                self.assertTrue(store.DEFENDER_PATH.exists())
                self.assertEqual(asyncio.run(run_defender_round("http://unknown"))["plans"], [])


if __name__ == "__main__":
    unittest.main()
