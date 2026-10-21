import asyncio
import json
from pathlib import Path
import tempfile
import unittest

from fastapi.testclient import TestClient

from lab.app import Settings, create_app


class GrowingLabTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.path = Path(self.directory.name) / "scenario.json"

    def app(self, **kwargs):
        return create_app(Settings(state_file=self.path, policy_file=self.path.with_name("policy.json"), growth_seconds=0, **kwargs))

    def test_growth_updates_routes_and_cached_schema_and_survives_restart(self):
        app = self.app()
        with TestClient(app) as client:
            before = client.get("/openapi.json").json()["paths"]
            client.portal.call(app.state.scenario.add_collection, app)
            after = client.get("/openapi.json").json()["paths"]
            self.assertEqual(len(after), len(before) + 2)
            self.assertEqual(client.get("/api/collection_0003/items", headers={
                "Authorization": "Bearer alice-token"}).status_code, 200)
        with TestClient(self.app()) as client:
            self.assertEqual(set(client.get("/openapi.json").json()["paths"]), set(after))

    def test_secure_and_vulnerable_routes_and_ground_truth_is_private(self):
        app = self.app()
        with TestClient(app) as client:
            token = client.post("/auth/login", json={"username": "alice", "password": "lab-password"}).json()["access_token"]
            headers = {"Authorization": f"Bearer {token}"}
            variants = set()
            for entry in app.state.scenario.manifest["collections"]:
                variants.add(entry["vulnerable"])
                url = f"/api/{entry['name']}/items"
                self.assertEqual(client.get(url + "/1").status_code, 401)
                self.assertEqual(client.get(url + "/1", headers=headers).status_code, 200)
                self.assertEqual(client.get(url + "/2", headers=headers).status_code,
                                 200 if entry["vulnerable"] else 403)
                self.assertEqual(client.get(url + "/999", headers=headers).status_code, 404)
                self.assertEqual([x["owner"] for x in client.get(url, headers=headers).json()], ["alice"])
            self.assertEqual(variants, {True, False})
            self.assertEqual(client.get("/scenario.json").status_code, 404)
            self.assertNotIn("vulnerable", client.get("/openapi.json").text)
            self.assertEqual(client.post("/auth/login", json={"username": "alice", "password": "wrong"}).status_code, 401)

    def test_timer_reaches_cap_and_stops(self):
        app = create_app(Settings(state_file=self.path, growth_seconds=.01, max_collections=4))
        with TestClient(app) as client:
            async def wait_until_grown():
                for _ in range(100):
                    if len(app.state.scenario.manifest["collections"]) == 4:
                        return
                    await asyncio.sleep(.01)
                raise AssertionError("timer did not grow the surface")
            client.portal.call(wait_until_grown)
            self.assertFalse(client.portal.call(app.state.scenario.add_collection, app))
        self.assertEqual(len(json.loads(self.path.read_text())["collections"]), 4)

    def test_seed_reproducibility_and_mismatch_rejection(self):
        first = self.app()
        other = create_app(Settings(state_file=self.path.with_name("other.json"), growth_seconds=0))
        labels = lambda app: [(e["name"], e["vulnerable"]) for e in app.state.scenario.manifest["collections"]]
        self.assertEqual(labels(first), labels(other))
        with self.assertRaises(ValueError):
            self.app(seed=999)


if __name__ == "__main__":
    unittest.main()
