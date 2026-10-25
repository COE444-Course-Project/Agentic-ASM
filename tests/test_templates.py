import asyncio
import json
from pathlib import Path
import tempfile
import unittest

from fastapi.testclient import TestClient

from core import state_store as store
from core.lab_checks import assess, probe
from core.lab_policy import read_policy, write_policy
from core.template_catalog import TEMPLATES
from core.template_checks import template_for
from lab.app import Settings, create_app
from orchestrator import run_defender_round


class TemplateTests(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.root = Path(temp.name)
        previous = store.STATE_DIR
        self.addCleanup(store.configure, previous)
        store.configure(self.root / "agent")

    def settings(self, **kwargs):
        return Settings(state_file=self.root / "scenario.json", policy_file=self.root / "policy.json", growth_seconds=0, **kwargs)

    def fixed_cases(self):
        entries = []
        for template in TEMPLATES:
            for vulnerable in (True, False):
                entries.append({"name": f"collection_{len(entries)+1:04d}", "stage": len(entries)+1,
                                "introduced_at": 0, "template": template, "vulnerable": vulnerable})
        settings = self.settings()
        settings.state_file.write_text(json.dumps({"version": 1, "seed": 444, "collections": entries}))
        return settings, entries

    def test_every_type_detected_fixed_verified_and_persistent(self):
        settings, entries = self.fixed_cases()
        with TestClient(create_app(settings)) as client:
            result = assess(client, "http://testserver")
            self.assertEqual(result["summary"], {"vulnerable": 8, "patched": 0, "defended": 8, "inconclusive": 0})
            for entry in entries:
                with self.subTest(template=entry["template"], vulnerable=entry["vulnerable"]):
                    self.assertIs(probe(client, entry["name"])["verdict"], entry["vulnerable"])
            defense = asyncio.run(run_defender_round("http://testserver", settings.policy_file, client))
            self.assertEqual(defense["verified"], 8, defense)
            for entry in entries:
                self.assertTrue(probe(client, entry["name"])["verified_secure"], entry)
            # All 16 collections now probe secure, but only the 8 that were
            # actually vulnerable and then patched should count as "patched";
            # the 8 that were secure from the start must not be miscounted as
            # defender output.
            reassessment = assess(client, "http://testserver", policy_file=settings.policy_file)
            self.assertEqual(reassessment["summary"], {"vulnerable": 0, "patched": 8, "defended": 16, "inconclusive": 0})
            # Positive changes and malicious attempts are cleaned up by the probes.
            for user, id in (("alice", 1), ("bob", 2)):
                response = client.get(f"/api/collection_0009/items/{id}", headers={"Authorization": f"Bearer {user}-token"})
                self.assertEqual(response.json()["content"], f"{user}'s private collection_0009 document")
        with TestClient(create_app(settings)) as restarted:
            for entry in entries:
                self.assertTrue(probe(restarted, entry["name"])["verified_secure"])
        policy = read_policy(settings.policy_file)
        self.assertEqual(len(policy["collections"]), 8)
        self.assertTrue(all(len(value) == 1 for value in policy["collections"].values()))

    def test_patched_survives_a_findings_history_reset(self):
        """The dashboard's "Reset state" button clears findings.json (this
        process's own assessment history) but never touches the lab policy
        file. A reassessment afterwards must still report "patched" for a
        collection the defender genuinely fixed, not fall back to counting
        it as merely "defended" just because the local history is gone --
        see state_store.upsert_finding()'s policy_patched parameter."""
        settings, entries = self.fixed_cases()
        with TestClient(create_app(settings)) as client:
            assess(client, "http://testserver")
            asyncio.run(run_defender_round("http://testserver", settings.policy_file, client))
            # Simulate "Reset state": this dashboard process has amnesia, but
            # the policy file -- the actual source of truth -- is untouched.
            store.configure(self.root / "agent-after-reset")
            reassessment = assess(client, "http://testserver", policy_file=settings.policy_file)
            self.assertEqual(reassessment["summary"], {"vulnerable": 0, "patched": 8, "defended": 16, "inconclusive": 0})
            # Without the policy file, the same reset leaves no way to tell
            # "patched" from "always secure" apart -- documenting the
            # fallback, not asserting it's wrong.
            store.configure(self.root / "agent-after-reset-no-policy")
            blind_reassessment = assess(client, "http://testserver")
            self.assertEqual(blind_reassessment["summary"], {"vulnerable": 0, "patched": 0, "defended": 16, "inconclusive": 0})

    def test_random_assignment_reproducible_without_all_types_on_each_resource(self):
        settings = self.settings(initial_collections=64)
        app = create_app(settings)
        entries = app.state.scenario.manifest["collections"]
        original = [(e["template"], e["vulnerable"]) for e in entries]
        self.assertEqual({e["template"] for e in entries}, set(TEMPLATES))
        self.assertEqual({e["vulnerable"] for e in entries}, {True, False})
        self.assertEqual(original, [(e["template"], e["vulnerable"]) for e in create_app(settings).state.scenario.manifest["collections"]])
        schema = app.openapi()
        self.assertNotIn('"vulnerable"', json.dumps(schema))
        for entry in entries:
            self.assertEqual(template_for(schema["paths"], entry["name"]), entry["template"])
            if entry["template"] != "B4":
                self.assertNotIn(f"/api/{entry['name']}/documents/batch", schema["paths"])
        other = create_app(Settings(state_file=self.root / "other.json", policy_file=settings.policy_file,
                                    seed=445, growth_seconds=0, initial_collections=64))
        self.assertNotEqual(original, [(e["template"], e["vulnerable"]) for e in other.state.scenario.manifest["collections"]])

    def test_policy_for_wrong_operation_does_not_fix_vulnerability(self):
        settings, _ = self.fixed_cases()
        write_policy(settings.policy_file, {"version": 1, "collections": {"collection_0003": {"B1": True}}})
        with TestClient(create_app(settings)) as client:
            self.assertTrue(probe(client, "collection_0003")["verdict"])
            self.assertEqual(client.get("/api/collection_0003/documents/2", headers={"Authorization": "Bearer alice-token"}).status_code, 403)

    def test_probability_zero_produces_only_secure_cases(self):
        app = create_app(self.settings(initial_collections=16, vulnerability_probability=0))
        with TestClient(app) as client:
            result = assess(client, "http://testserver")
            self.assertEqual(result["summary"], {"vulnerable": 0, "patched": 0, "defended": 16, "inconclusive": 0})
