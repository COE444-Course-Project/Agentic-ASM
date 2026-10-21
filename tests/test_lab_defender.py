import asyncio
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from fastapi.testclient import TestClient

from agents import responder
from core import state_store as store
from core.lab_checks import assess, probe
from core.lab_policy import read_policy, write_policy
from lab.app import Settings, create_app
from orchestrator import run_defender_round
from run_harness import evaluate


class LabDefenderTests(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.root = Path(temp.name)
        original = store.STATE_DIR
        self.addCleanup(store.configure, original)
        store.configure(self.root / "agent")
        self.settings = Settings(state_file=self.root / "scenario.json", policy_file=self.root / "policy.json", growth_seconds=0)

    def test_harness_validates_growth_and_one_defender_pass(self):
        report = evaluate()
        self.assertTrue(report["passed"], report["failures"])
        self.assertEqual(report["classification"]["true_positives"], 3)
        self.assertEqual(report["defender"]["verified"], 3)

    def test_failed_verification_rolls_back_and_does_not_close(self):
        with TestClient(create_app(self.settings)) as client:
            assessment = assess(client, "http://testserver")
            finding = next(f for f in assessment["findings"] if f["verdict"])
            original_probe = responder.probe
            calls = 0

            def broken_verification(http, name):
                nonlocal calls
                calls += 1
                if calls == 2:
                    raise RuntimeError("Injected verification outage")
                return original_probe(http, name)

            with patch.object(responder, "probe", side_effect=broken_verification):
                report = asyncio.run(run_defender_round("http://testserver", self.settings.policy_file, client))
            self.assertTrue(report["plans"][0]["rolled_back"])
            self.assertFalse(report["plans"][0]["verified"])
            self.assertEqual(store.get_findings()[finding["id"]]["status"], "open")
            self.assertTrue(probe(client, finding["collection"])["verdict"])
            self.assertEqual(read_policy(self.settings.policy_file)["collections"], {})

    def test_wrong_policy_path_cannot_produce_verified_patch(self):
        with TestClient(create_app(self.settings)) as client:
            assess(client, "http://testserver")
            report = asyncio.run(run_defender_round("http://testserver", self.root / "wrong.json", client))
            self.assertEqual(report["verified"], 0)
            self.assertTrue(report["plans"][0]["rolled_back"])

    def test_invalid_policy_fails_closed_and_is_not_overwritten(self):
        self.settings.policy_file.write_text('{"version": 1, "collections": {"collection_0001": false}}')
        with TestClient(create_app(self.settings)) as client:
            self.assertEqual(client.get("/api/collection_0001/items/1", headers={"Authorization": "Bearer alice-token"}).status_code, 503)

    def test_regression_reopens_finding_and_new_growth_is_unpatched(self):
        app = create_app(self.settings)
        with TestClient(app) as client:
            baseline = assess(client, "http://testserver")
            finding = next(f for f in baseline["findings"] if f["verdict"])
            asyncio.run(run_defender_round("http://testserver", self.settings.policy_file, client))
            self.assertEqual(store.get_findings()[finding["id"]]["status"], "patched")
            write_policy(self.settings.policy_file, {"version": 1, "collections": {}})
            assess(client, "http://testserver")
            self.assertEqual(store.get_findings()[finding["id"]]["status"], "open")
            client.portal.call(app.state.scenario.add_collection, app)
            client.portal.call(app.state.scenario.add_collection, app)
            self.assertEqual({probe(client, name)["verdict"] for name in ("collection_0003", "collection_0004")}, {True, False})


if __name__ == "__main__":
    unittest.main()
