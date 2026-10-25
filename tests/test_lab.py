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
        return create_app(Settings(template_ids=("legacy",), state_file=self.path, policy_file=self.path.with_name("policy.json"), growth_seconds=0, **kwargs))

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
        app = create_app(Settings(template_ids=("legacy",), state_file=self.path, growth_seconds=.01, max_collections=4))
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
        other = create_app(Settings(template_ids=("legacy",), state_file=self.path.with_name("other.json"), growth_seconds=0))
        labels = lambda app: [(e["name"], e["vulnerable"]) for e in app.state.scenario.manifest["collections"]]
        self.assertEqual(labels(first), labels(other))
        with self.assertRaises(ValueError):
            self.app(seed=999)

    def test_admin_growth_reads_and_validates(self):
        app = self.app(max_collections=4)
        with TestClient(app) as client:
            snap = client.get("/admin/growth").json()
            self.assertEqual(snap, {"growth_seconds": 0, "max_collections": 4,
                                     "vulnerability_probability": .5, "template_ids": ["legacy"],
                                     "paused": False, "collections": 2, "seed": 444})
            self.assertEqual(client.post("/admin/growth", json={"vulnerability_probability": 2}).status_code, 400)
            self.assertEqual(client.post("/admin/growth", json={"template_ids": []}).status_code, 400)
            self.assertEqual(client.post("/admin/growth", json={"max_collections": -1}).status_code, 400)
            # A rejected update must not have partially applied.
            self.assertEqual(client.get("/admin/growth").json()["max_collections"], 4)

    def test_admin_growth_resumes_live_without_restart(self):
        app = create_app(Settings(template_ids=("legacy",), state_file=self.path, growth_seconds=0, max_collections=3))
        with TestClient(app) as client:
            async def wait_for(n, timeout=2.0):
                for _ in range(int(timeout / .01)):
                    if len(app.state.scenario.manifest["collections"]) == n:
                        return
                    await asyncio.sleep(.01)
                raise AssertionError(f"never reached {n} collections")

            # Frozen at growth_seconds=0: nothing grows on its own.
            client.portal.call(asyncio.sleep, .05)
            self.assertEqual(len(app.state.scenario.manifest["collections"]), 2)

            # Un-pausing with a short interval resumes growth live and hits
            # the original cap -- no container restart needed.
            self.assertEqual(client.post("/admin/growth", json={"growth_seconds": .01}).status_code, 200)
            client.portal.call(wait_for, 3)
            client.portal.call(asyncio.sleep, .05)
            self.assertEqual(len(app.state.scenario.manifest["collections"]), 3,
                              "growth must stop at the original cap, not just because it resumed")

            # Raising the cap resumes growth again past the old limit.
            self.assertEqual(client.post("/admin/growth", json={"max_collections": 5}).status_code, 200)
            client.portal.call(wait_for, 5)

            # Pausing stops it even though growth_seconds is still > 0.
            self.assertEqual(client.post("/admin/growth", json={"paused": True}).status_code, 200)
            client.portal.call(asyncio.sleep, .05)
            self.assertEqual(len(app.state.scenario.manifest["collections"]), 5)

    def test_admin_reset_clears_routes_and_reseeds(self):
        app = self.app(max_collections=0)
        with TestClient(app) as client:
            client.portal.call(app.state.scenario.add_collection, app)
            client.portal.call(app.state.scenario.add_collection, app)
            self.assertEqual(len(app.state.scenario.manifest["collections"]), 4)
            self.assertEqual(client.get("/api/collection_0004/items",
                                         headers={"Authorization": "Bearer alice-token"}).status_code, 200)

            res = client.post("/admin/reset")
            self.assertEqual(res.status_code, 200)
            body = res.json()
            self.assertEqual(body["collections"], 2)  # back to initial_collections
            self.assertEqual(len(app.state.scenario.manifest["collections"]), 2)
            self.assertEqual([e["name"] for e in app.state.scenario.manifest["collections"]],
                              ["collection_0001", "collection_0002"])

            # The old collection's routes are genuinely gone, not just hidden from the manifest.
            self.assertEqual(client.get("/api/collection_0004/items",
                                         headers={"Authorization": "Bearer alice-token"}).status_code, 404)
            # The re-seeded collection_0001 works and is a fresh route registration.
            self.assertEqual(client.get("/api/collection_0001/items",
                                         headers={"Authorization": "Bearer alice-token"}).status_code, 200)
            self.assertNotIn("collection_0003", client.get("/openapi.json").text)
            self.assertNotIn("collection_0004", client.get("/openapi.json").text)

        # Persisted: a fresh process reconstruction sees the reset state, not the old 4.
        self.assertEqual(len(json.loads(self.path.read_text())["collections"]), 2)

    def test_admin_reset_keeps_growth_controls_and_is_seed_reproducible(self):
        app = create_app(Settings(template_ids=("legacy",), state_file=self.path, policy_file=self.path.with_name("policy.json"),
                                   growth_seconds=7, max_collections=0, vulnerability_probability=.3))
        with TestClient(app) as client:
            client.portal.call(app.state.scenario.add_collection, app)
            before_reset = [(e["name"], e.get("vulnerable")) for e in app.state.scenario.manifest["collections"]]

            client.post("/admin/reset")
            snap = client.get("/admin/growth").json()
            # Growth controls (pace/odds/cap) survive a reset untouched.
            self.assertEqual(snap["growth_seconds"], 7)
            self.assertEqual(snap["vulnerability_probability"], .3)

            # Re-growing after reset reproduces the exact same assignments,
            # since they're a pure function of (seed, index).
            client.portal.call(app.state.scenario.add_collection, app)
            after_reset = [(e["name"], e.get("vulnerable")) for e in app.state.scenario.manifest["collections"]]
            self.assertEqual(before_reset, after_reset)


if __name__ == "__main__":
    unittest.main()
