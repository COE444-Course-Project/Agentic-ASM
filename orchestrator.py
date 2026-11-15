"""
Orchestrator: "Decides whose turn it is and carries memory between
rounds." Attacker rounds execute Scout -> Planner -> Operator. Defender
passes execute Watcher -> Analyst -> Responder. Dry run is the default;
explicit lab apply mode patches and verifies authorization policy.

run_closed_loop() alternates the two sides against the growing custom API:
each round the surface changes (new scenarios, optional policy drift), then
discover -> attack -> defend -> independent verification. Rounds are bounded
and lab timer growth is paused so every change happens at a round boundary.
"""
from __future__ import annotations

import asyncio
import copy
import fcntl
import random
import time
from pathlib import Path
from typing import Callable, Optional

from agents import operator, planner, scout
from core import state_store as store

PHASES = ("grow", "discover", "attack", "defend", "verify")


async def run_attacker_round(base: str, model: str, should_stop: Optional[Callable[[], bool]] = None) -> dict:
    round_id = store.start_round(base)
    store.log_event("orchestrator", f"round {round_id} started against {base}", round_id)

    surface = scout.run(base, round_id)
    findings_so_far = store.get_findings()
    queue = planner.plan(surface, operator.MODULES, round_id, findings_so_far)
    findings = await operator.run_queue(base, queue, model, round_id, should_stop=should_stop)

    # See core/lab_checks.py's assess() for why "patched" (a verified defender
    # fix still in effect) is broken out from "defended" (merely not currently
    # vulnerable) -- VAmPI has no remediation adapter, so "patched" is always
    # 0 here, but the schema stays identical across both assessment paths.
    summary = {
        "vulnerable": sum(1 for f in findings if f["verdict"] is True),
        "patched": sum(1 for f in findings if f["verdict"] is False and f.get("status") == "patched"),
        "defended": sum(1 for f in findings if f["verdict"] is False),
        "inconclusive": sum(1 for f in findings if f["verdict"] is None),
    }
    status = "stopped" if should_stop and should_stop() else "done"
    store.finish_round(round_id, summary, status=status)
    store.log_event("orchestrator", f"round {round_id} {status}: {summary}", round_id)
    return {"round": round_id, "surface": surface, "findings": findings, "summary": summary, "status": status}


async def run_defender_round(base: str, policy_file=None, client=None) -> dict:
    """One defender pass. A policy file explicitly opts into lab remediation."""
    from agents import analyst, responder, watcher

    base = base.rstrip("/")
    mode = "apply" if policy_file is not None else "dry_run"
    store.log_event("orchestrator", f"defender {mode} started for {base}")
    plans = analyst.triage(watcher.observe(base))
    if policy_file is None:
        results = responder.draft(plans)
    elif client is not None:
        results = responder.apply_lab(plans, client, policy_file)
    else:
        import httpx
        with httpx.Client(base_url=base, timeout=10) as http:
            results = responder.apply_lab(plans, http, policy_file)
    report = {"target": base, "mode": mode, "plans": results,
              "applied": sum(p["applied"] for p in results),
              "verified": sum(p["verified"] for p in results)}
    store.save_defender_report(report)
    store.log_event("orchestrator", f"defender {mode} finished for {base}")
    return report


# ------------------------------------------------------------- closed loop

def _lab(client, method: str, path: str, body: Optional[dict] = None) -> dict:
    response = client.request(method, path, json=body) if body is not None else client.request(method, path)
    response.raise_for_status()
    return response.json()


def inject_drift(policy_file: Path, count: int, rng: random.Random) -> list[dict]:
    """Simulate a configuration regression (e.g. a deploy that reverts part of
    the authorization config) by revoking `count` verified patches. The loop
    must then detect each one as a regression and repair it again."""
    from core.lab_policy import read_policy, write_policy

    with policy_file.with_suffix(".lock").open("a") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        try:
            policy = read_policy(policy_file)
            entries = sorted((name, template) for name, value in policy["collections"].items()
                             if isinstance(value, dict) for template in value)
            chosen = rng.sample(entries, min(count, len(entries)))
            if not chosen:
                return []
            updated = copy.deepcopy(policy)
            for name, template in chosen:
                updated["collections"][name].pop(template)
                if not updated["collections"][name]:
                    del updated["collections"][name]
            write_policy(policy_file, updated)
        finally:
            fcntl.flock(lock, fcntl.LOCK_UN)
    return [{"collection": name, "template": template} for name, template in chosen]


def _tiles(before: dict, defense: dict, after: dict, new: set, drifted: set) -> list[dict]:
    plans = {p["finding_id"]: p for p in defense["plans"]}
    final = {f["id"]: f for f in after["findings"]}
    return [{"collection": f["collection"], "template": f.get("template", "legacy"),
             "new": f["collection"] in new, "drifted": f["collection"] in drifted,
             "attack": f["verdict"], "defense": plans.get(f["id"], {}).get("status"),
             "final": final.get(f["id"], {}).get("verdict"),
             "patched": final.get(f["id"], {}).get("status") == "patched"}
            for f in before["findings"]]


def loop_totals(rounds: list[dict]) -> dict:
    complete = [r for r in rounds if r.get("metrics")]
    detected = sum(r["metrics"]["initially_vulnerable"] for r in complete)
    repaired = sum(r["metrics"]["verified_repairs_still_secure"] for r in complete)
    passed = sum(r["metrics"]["owner_checks_passed"] for r in complete)
    total = sum(r["metrics"]["owner_checks_total"] for r in complete)
    regressed = [c for r in complete for c in r["regressions"]]
    last = complete[-1] if complete else None
    return {
        "rounds_completed": len(complete),
        "collections_final": last["surface"]["collections"] if last else 0,
        "vulnerabilities_detected": detected,
        "verified_repairs": repaired,
        "remediation_rate": repaired / detected if detected else None,
        "new_exposure": sum(len(r["new_exposure"]) for r in complete),
        "regressions_detected": len(regressed),
        "regressions_repaired": sum(t["drifted"] and t["attack"] is True and t["final"] is False
                                    for r in complete for t in r["tiles"]),
        "defender_failed": sum(r["metrics"]["defender_failed"] for r in complete),
        "defender_rolled_back": sum(r["metrics"]["defender_rolled_back"] for r in complete),
        "legit_checks_passed": passed, "legit_checks_total": total,
        "legit_preservation_rate": passed / total if total else None,
        "open_after_last_round": last["metrics"]["after"]["vulnerable"] if last else None,
        "inconclusive_after_last_round": last["metrics"]["after"]["inconclusive"] if last else None,
        "mean_round_seconds": (sum(sum(r["durations"].values()) for r in complete) / len(complete)) if complete else None,
    }


async def run_closed_loop(target: str, policy_file, client, *, rounds: int = 3, grow_per_round: int = 3,
                          drift: int = 0, llm_sample: int = 0, model: str = "qwen2.5",
                          seed: Optional[int] = None, phase_delay: float = 0.0,
                          should_stop: Optional[Callable[[], bool]] = None) -> dict:
    """Bounded attacker/defender rounds against the custom API lab.

    `client` is bound to `target`. `phase_delay` pauses between phases so a
    live audience can follow along; it is excluded from phase durations."""
    from core.lab_checks import assess, discover
    from core.metrics import metrics

    target = target.rstrip("/")
    policy_file = Path(policy_file)
    rng = random.Random(seed)
    stopped = lambda: bool(should_stop and should_stop())
    loop = {"id": f"loop-{int(time.time() * 1000)}", "target": target, "status": "running",
            "started_at": time.time(), "finished_at": None, "error": None,
            "config": {"rounds": rounds, "grow_per_round": grow_per_round, "drift": drift,
                       "llm_sample": llm_sample, "model": model if llm_sample else None, "seed": seed},
            "current": {"round": 0, "phase": "setup"}, "rounds": [], "totals": None}
    evidence: dict[int, dict] = {}
    save = lambda: store.set_loop(loop)
    save()
    store.log_event("orchestrator", f"closed loop started: {rounds} round(s) against {target}")

    if not policy_file.exists():
        # A lab that has seen a policy fails closed (503) when it disappears; start from an empty one.
        from core.lab_policy import write_policy
        write_policy(policy_file, {"version": 1, "collections": {}})
    growth = _lab(client, "GET", "/admin/growth")
    if not growth["paused"]:
        _lab(client, "POST", "/admin/growth", {"paused": True})
        store.log_event("orchestrator", "paused lab timer growth; the loop grows the API at round boundaries")

    def enter(entry: dict, phase: str):
        loop["current"] = {"round": entry["round"], "phase": phase, "since": time.time()}
        save()

    async def timed(entry: dict, phase: str, work):
        enter(entry, phase)
        start = time.monotonic()
        result = work()
        if asyncio.iscoroutine(result):
            result = await result
        entry["durations"][phase] = time.monotonic() - start
        save()
        if phase_delay and not stopped():
            await asyncio.sleep(phase_delay)
        return result

    seen: set[str] = set()
    previous_final: dict[str, Optional[bool]] = {}
    try:
        for number in range(1, rounds + 1):
            if stopped():
                break
            entry = {"round": number, "started_at": time.time(), "finished_at": None, "durations": {},
                     "grown": 0, "drifted": [], "new_collections": [], "new_exposure": [], "regressions": [],
                     "tiles": [], "metrics": None}
            loop["rounds"].append(entry)

            def grow():
                if grow_per_round <= 0:
                    return
                status = _lab(client, "GET", "/admin/growth")
                needed = status["collections"] + grow_per_round
                if status["max_collections"] and needed > status["max_collections"]:
                    _lab(client, "POST", "/admin/growth", {"max_collections": needed})
                entry["grown"] = _lab(client, "POST", "/admin/grow", {"count": grow_per_round})["added"]
                if drift and number > 1:
                    entry["drifted"] = inject_drift(policy_file, drift, rng)
                store.log_event("orchestrator", f"loop round {number}: API grew by {entry['grown']} scenario(s)"
                                + (f", {len(entry['drifted'])} patch(es) reverted by simulated drift" if entry["drifted"] else ""))
            await timed(entry, "grow", grow)

            def discover_surface():
                surface = scout.run(target, None, client=client)
                names = discover(client)
                entry["surface"] = {"collections": len(names), "endpoints": len(surface["endpoints"])}
                entry["new_collections"] = sorted(set(names) - seen)
                seen.update(names)
            await timed(entry, "discover", discover_surface)

            def attack():
                result = assess(client, target, should_stop=should_stop, policy_file=policy_file)
                store.update_round(result["round"], loop_id=loop["id"], loop_round=number, loop_phase="attack")
                return result
            before = await timed(entry, "attack", attack)
            entry["attack_round"] = before["round"]
            if llm_sample and not stopped():
                from agents.lab_operator import run_llm_sample
                candidates = [(f["collection"], f["template"]) for f in before["findings"] if f.get("template")]
                llm = await run_llm_sample(target, model, candidates, before["round"], llm_sample,
                                           rng_seed=seed, should_stop=should_stop, policy_file=policy_file)
                entry["llm_summary"] = {"vulnerable": sum(f["verdict"] is True for f in llm),
                                        "defended": sum(f["verdict"] is False for f in llm),
                                        "inconclusive": sum(f["verdict"] is None for f in llm)}
            if before["status"] == "stopped" or stopped():
                entry["finished_at"] = time.time()
                break

            defense = await timed(entry, "defend",
                                  lambda: run_defender_round(target, policy_file, client))

            def verify():
                result = assess(client, target, should_stop=should_stop, policy_file=policy_file)
                store.update_round(result["round"], loop_id=loop["id"], loop_round=number, loop_phase="verify")
                return result
            after = await timed(entry, "verify", verify)
            entry["verify_round"] = after["round"]

            new = set(entry["new_collections"])
            drifted = {d["collection"] for d in entry["drifted"]}
            entry.update(
                metrics=metrics(before, defense, after),
                new_exposure=sorted(f["collection"] for f in before["findings"]
                                    if f["collection"] in new and f["verdict"] is True),
                regressions=sorted(f["collection"] for f in before["findings"]
                                   if previous_final.get(f["id"]) is False and f["verdict"] is True),
                tiles=_tiles(before, defense, after, new, drifted),
                finished_at=time.time())
            evidence[number] = {"assessment-before": before, "defender": defense, "assessment-after": after}
            previous_final = {f["id"]: f["verdict"] for f in after["findings"]}
            m = entry["metrics"]
            store.log_event("orchestrator", f"loop round {number} done: {m['initially_vulnerable']} found, "
                            f"{m['verified_repairs_still_secure']} verified fixed, {m['after']['vulnerable']} still open, "
                            f"{len(entry['regressions'])} regression(s)")
            loop["totals"] = loop_totals(loop["rounds"])
            save()
        loop["status"] = "stopped" if stopped() else "done"
    except Exception as exc:
        loop.update(status="error", error=str(exc))
        store.log_event("orchestrator", f"closed loop failed: {exc}", level="warn")
        raise
    finally:
        if not growth["paused"]:
            try:
                _lab(client, "POST", "/admin/growth", {"paused": False})
            except Exception as exc:
                store.log_event("orchestrator", f"could not resume lab growth: {exc}", level="warn")
        loop["totals"] = loop_totals(loop["rounds"])
        loop["current"] = {"round": len(loop["rounds"]), "phase": "finished", "since": time.time()}
        loop["finished_at"] = time.time()
        save()
    store.log_event("orchestrator", f"closed loop {loop['status']}: {loop['totals']}")
    return {**loop, "evidence": evidence}
