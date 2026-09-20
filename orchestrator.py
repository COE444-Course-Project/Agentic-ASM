"""
Orchestrator: "Decides whose turn it is and carries memory between
rounds." Today there is only an attacker side, so a round is just
Scout -> Planner -> Operator. The state store (core/state_store.py) is
what a future run_defender_round() would read (findings as telemetry) and
write to (patch status) -- so adding the defender later means adding one
function here and interleaving the two calls in run_attacker.py's loop,
not redesigning Scout/Planner/Operator.
"""
from __future__ import annotations

from agents import operator, planner, scout
from core import state_store as store


async def run_attacker_round(base: str, model: str) -> dict:
    round_id = store.start_round(base)
    store.log_event("orchestrator", f"round {round_id} started against {base}", round_id)

    surface = scout.run(base, round_id)
    findings_so_far = store.get_findings()
    queue = planner.plan(surface, operator.MODULES, round_id, findings_so_far)
    findings = await operator.run_queue(base, queue, model, round_id)

    summary = {
        "vulnerable": sum(1 for f in findings if f["verdict"] is True),
        "defended": sum(1 for f in findings if f["verdict"] is False),
        "inconclusive": sum(1 for f in findings if f["verdict"] is None),
    }
    store.finish_round(round_id, summary)
    store.log_event("orchestrator", f"round {round_id} finished: {summary}", round_id)
    return {"round": round_id, "surface": surface, "findings": findings, "summary": summary}


# Next milestone (M6: "Defender agent triages and patches"). Deliberately
# left unimplemented rather than stubbed with fake behaviour -- when it
# exists it will read store.get_findings() as its telemetry and call
# store.upsert_finding(..., status="patched") once it remediates one, and
# run_attacker.py will alternate run_attacker_round() / run_defender_round()
# across N rounds.
#
# async def run_defender_round(base: str, model: str) -> dict: ...
