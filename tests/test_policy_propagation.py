import tempfile
from pathlib import Path
import unittest
from unittest.mock import patch

from fastapi.testclient import TestClient

from agents.responder import settled_probe
from core.lab_policy import read_policy, write_policy
from lab.app import Settings, create_app


class PolicyPropagationTests(unittest.TestCase):
    def test_transient_missing_file_is_retried(self):
        with patch.object(Path, "read_text", side_effect=[FileNotFoundError(), '{"version":1,"collections":{"collection_0001":true}}']), patch("core.lab_policy.time.sleep"):
            self.assertTrue(read_policy(Path("unused"), allow_missing=False)["collections"]["collection_0001"])

    def test_missing_established_policy_fails_closed(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            policy = root / "policy.json"
            write_policy(policy, {"version": 1, "collections": {"collection_0001": True}})
            app = create_app(Settings(template_ids=("legacy",), state_file=root / "scenario.json", policy_file=policy, growth_seconds=0))
            with TestClient(app) as client:
                policy.unlink()
                with patch("core.lab_policy.time.sleep"):
                    response = client.get("/api/collection_0001/items/2", headers={"Authorization": "Bearer alice-token"})
                self.assertEqual(response.status_code, 503)

    def test_verifier_waits_for_mount_and_preserves_failure(self):
        pending = {"verdict": None, "verified_secure": False}
        secure = {"verdict": False, "verified_secure": True}
        with patch("agents.responder.probe", side_effect=[pending, pending, secure]), patch("agents.responder.time.sleep"):
            self.assertEqual(settled_probe(None, "collection_0001", expect_secure=True), secure)
        with patch("agents.responder.probe", return_value=pending) as probe_mock, patch("agents.responder.time.sleep"):
            self.assertEqual(settled_probe(None, "collection_0001", expect_secure=True), pending)
            self.assertEqual(probe_mock.call_count, 8)
