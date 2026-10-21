"""Evaluate growth and one defender pass in an isolated ASGI lab; no agent loop.

The evaluator alone reads ground truth. Assessment/defender see only HTTP and
the operational policy. No running Docker target or dashboard state is modified.
"""
import argparse
import asyncio
import json
import math
from pathlib import Path
import tempfile
import time

from fastapi.testclient import TestClient

from core import state_store as store
from core.lab_checks import assess, discover, probe
from lab.app import Settings, create_app
from orchestrator import run_defender_round


def evaluate(collections=6, growth_seconds=.05, timeout=10, seed=444) -> dict:
    if (collections < 4 or not math.isfinite(growth_seconds) or not math.isfinite(timeout)
            or growth_seconds <= 0 or timeout <= 0):
        raise ValueError("Need at least 4 collections and positive interval/timeout")
    report = {"version": 1, "transport": "ASGI TestClient", "seed": seed,
              "scope": "one ownership template, two fixed identities, one defender pass",
              "checks": {}, "failures": []}

    def check(name, condition):
        report["checks"][name] = bool(condition)
        if not condition:
            report["failures"].append(name)

    previous_dir = store.STATE_DIR
    try:
        with tempfile.TemporaryDirectory(prefix="asm-harness-") as directory:
            root = Path(directory)
            store.configure(root / "agent-state")
            settings = Settings(state_file=root / "scenario.json", policy_file=root / "policy.json",
                                seed=seed, max_collections=collections, growth_seconds=growth_seconds)
            app = create_app(settings)
            seen = {}
            with TestClient(app) as client:
                initial = discover(client)  # prime the OpenAPI cache before growth
                check("initial_surface", len(initial) == 2)
                deadline = time.monotonic() + timeout
                while True:
                    names = discover(client)
                    for name in names:
                        seen.setdefault(name, time.time())
                    if len(names) >= collections or time.monotonic() >= deadline:
                        break
                    time.sleep(min(.02, growth_seconds))
                check("timed_growth", len(names) == collections)
                check("existing_routes_retained", set(initial) <= set(names))
                schema = client.get("/openapi.json").json()
                check("two_routes_per_collection", len(schema["paths"]) == 2 + 2 * collections)
                check("no_ground_truth_endpoint", client.get("/scenario.json").status_code == 404)
                check("no_labels_in_schema", "vulnerable" not in json.dumps(schema))
                # Only the evaluator knows labels, after black-box assessment.
                baseline = assess(client, "http://testserver")
                report["baseline"] = baseline
                manifest_before = json.loads(settings.state_file.read_text())
                truth = {e["name"]: e["vulnerable"] for e in manifest_before["collections"]}
                check("mixed_security_cases", set(truth.values()) == {True, False})
                counts = {"true_positives": 0, "true_negatives": 0, "false_positives": 0,
                          "false_negatives": 0, "inconclusive": 0}
                for finding in baseline["findings"]:
                    actual, expected = finding["verdict"], truth[finding["collection"]]
                    if actual is None:
                        counts["inconclusive"] += 1
                    else:
                        key = ("true_" if actual == expected else "false_") + ("positives" if actual else "negatives")
                        counts[key] += 1
                report["classification"] = counts
                check("baseline_matches_ground_truth", counts["false_positives"] == counts["false_negatives"] == counts["inconclusive"] == 0)
                report["discovery_delay_seconds"] = {
                    e["name"]: max(0, seen[e["name"]] - e["introduced_at"])
                    for e in manifest_before["collections"] if e["name"] in seen}
                start = time.monotonic()
                defender = asyncio.run(run_defender_round("http://testserver", settings.policy_file, client))
                report["defender"] = defender
                report["defender_duration_seconds"] = time.monotonic() - start
                expected_patches = sum(truth.values())
                check("all_vulnerable_collections_patched", defender["verified"] == expected_patches)
                check("secure_collections_not_selected", len(defender["plans"]) == expected_patches)
                # Independent HTTP assertions, rather than trusting responder labels.
                for name in names:
                    prefix = f"/api/{name}/items"
                    for user, owned, other in (("alice", 1, 2), ("bob", 2, 1)):
                        headers = {"Authorization": f"Bearer {user}-token"}
                        owner = client.get(f"{prefix}/{owned}", headers=headers)
                        check(f"{name}.{user}.owner_preserved", owner.status_code == 200 and owner.json().get("owner") == user)
                        check(f"{name}.{user}.cross_blocked", client.get(f"{prefix}/{other}", headers=headers).status_code == 403)
                report["remediation_rate"] = defender["verified"] / expected_patches if expected_patches else None
                check("ground_truth_unchanged", json.loads(settings.state_file.read_text()) == manifest_before)
            # New app process state, same files: routes and authorization survive.
            with TestClient(create_app(settings)) as restarted:
                check("surface_survives_restart", discover(restarted) == names)
                check("patches_survive_restart", all(probe(restarted, name)["verified_secure"] for name in names))
            report["final_findings"] = list(store.get_findings().values())
    except Exception as exc:
        report["failures"].append(f"{type(exc).__name__}: {exc}")
    finally:
        store.configure(previous_dir)
    report["passed"] = not report["failures"]
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, default=Path("reports/lab-validation.json"))
    parser.add_argument("--collections", type=int, default=6)
    parser.add_argument("--growth-seconds", type=float, default=.05)
    parser.add_argument("--timeout", type=float, default=10)
    parser.add_argument("--seed", type=int, default=444)
    args = parser.parse_args()
    report = evaluate(args.collections, args.growth_seconds, args.timeout, args.seed)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, indent=2))
    print(json.dumps({"passed": report["passed"], "checks": len(report["checks"]),
                      "failures": report["failures"], "report": str(args.output)}, indent=2))
    raise SystemExit(0 if report["passed"] else 1)


if __name__ == "__main__":
    main()
