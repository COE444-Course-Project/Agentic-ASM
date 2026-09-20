"""
Planner (attacker): "Ranks the findings and decides what is worth
exploiting, and in what order." Filters Operator's module catalog against
whatever Scout actually found on the wire, then orders what's left.

Ordering today is a simple, deterministic heuristic (near-free
deterministic checks before the LLM-driven exploit chains) -- which is
deliberate: this is exactly where the proposal's "stronger reasoning model
for planning, cheaper one for routine steps" slots in later. Swap this
function's body for an LLM call that reads the same attack surface +
module catalog + prior findings and still returns an ordered list of
module ids; Scout and Operator don't need to change.
"""
from __future__ import annotations

from core import state_store as store


def _endpoint_paths(surface: dict) -> set[str]:
    return {e["path"] for e in surface.get("endpoints", [])}


def plan(surface: dict, modules: list[dict], round_id: int, findings: dict) -> list[dict]:
    paths = _endpoint_paths(surface)
    applicable = []
    for m in modules:
        # If Scout couldn't reach the target at all, don't let an empty
        # surface silently skip every module -- fail open and let Operator
        # try (and report) rather than fail closed and report nothing.
        missing = [p for p in m["requires"] if p not in paths]
        if missing and paths:
            store.log_event("planner", f"skipping '{m['title']}': surface is missing {missing}", round_id, level="warn")
            continue
        applicable.append(m)

    # Deterministic checks first (near-free), then read-only LLM missions,
    # then anything flagged `mutates` (changes shared account state, e.g.
    # a password) last -- so a mutating module never invalidates the
    # seeded credentials another module's setup still needs this round.
    applicable.sort(key=lambda m: (m["kind"] != "deterministic", bool(m.get("mutates"))))

    store.log_event(
        "planner",
        f"queued {len(applicable)} module(s): " + ", ".join(m["id"] for m in applicable),
        round_id,
        data={"order": [m["id"] for m in applicable]},
    )
    return applicable
