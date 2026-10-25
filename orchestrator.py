"""
Orchestrator: "Decides whose turn it is and carries memory between
rounds." Attacker rounds execute Scout -> Planner -> Operator. Defender
passes execute Watcher -> Analyst -> Responder. Dry run is the default;
explicit lab apply mode patches and verifies ownership policy. No automatic
alternation or attacker-defender loop is implemented.
"""
from __future__ import annotations

from typing import Callable, Optional

from agents import operator, planner, scout
from core import state_store as store


async def run_attacker_round(base: str, model: str, should_stop: Optional[Callable[[], bool]] = None) -> dict:
    round_id = store.start_round(base)
    store.log_event("orchestrator", f"round {round_id} started against {base}", round_id)

    surface = scout.run(base, round_id)
    findings_so_far = store.get_findings()
    queue = planner.plan(surface, operator.MODULES, round_id, findings_so_far)
    findings = await operator.run_queue(base, queue, model, round_id, should_stop=should_stop)

    summary = {
        "vulnerable": sum(1 for f in findings if f["verdict"] is True),
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
