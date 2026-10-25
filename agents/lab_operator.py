"""Optional LLM-driven cross-check for the custom API lab's 8 ownership
templates (B1-B7, V1) -- the "general attacker" step from the README's
roadmap, scoped down to something that actually finishes: sampled, not
exhaustive.

core/lab_checks.py's deterministic probe already covers *every* collection,
every round, in milliseconds, with no LLM involved -- that stays the
authoritative, fast baseline. This module adds an independent, optional
second opinion on a random *sample* of collections: the same two lab users
and the same documented operation (core/template_catalog.py), but the
request is decided and sent by a local Ollama model through the MCP
`http_request` tool (the same ReAct-agent machinery agents/operator.py uses
for VAmPI), not by a direct Python call. Running it against every
collection in an unbounded, still-growing lab would take hours for no
extra signal over the deterministic probe, which is why this is
sample-sized and opt-in -- see the dashboard's "LLM-sampled checks" field
and its Guide sidebar.

Every verdict here is still graded from the actual tool-call transcript,
never the model's own prose claim -- same discipline as operator.py.
"""
from __future__ import annotations

import json
import random
from pathlib import Path
from typing import Callable, Optional

import httpx

from agents.operator import RECURSION_LIMIT, _extract_tool_calls, _find, build_agent, validate_records
from core import state_store as store
from core.lab_policy import is_patched, read_policy
from core.template_catalog import TEMPLATES

# For each template: the concrete attack a non-owner ("bob") should attempt
# against the fixed victim ("alice", always item id 1 in every collection --
# see lab/templates.py) and how to tell a leak/mutation apart from a correct
# 403. `needle` is a substring that should only appear if alice's data (or
# the operation's effect) genuinely came back; None means any 200 is proof
# enough (e.g. V1 disabling someone, B6 minting a share link -- their 200
# bodies don't echo alice's content, just confirm the operation went through).
_SPECS = {
    "B1": dict(path=lambda name: f"/api/{name}/documents/1", body=None, needle="alice"),
    "B2": dict(path=lambda name: f"/api/{name}/exports", body={"document_id": 1}, needle="alice"),
    "B3": dict(path=lambda name: f"/api/{name}/projects/2/files/1", body=None, needle="alice"),
    "B4": dict(path=lambda name: f"/api/{name}/documents/batch", body={"ids": [2, 1]}, needle="alice"),
    "B5": dict(path=lambda name: f"/api/{name}/documents/1", body={"content": "overwritten by llm check"}, needle="alice"),
    "B6": dict(path=lambda name: f"/api/{name}/documents/1/share", body=None, needle=None),
    "B7": dict(path=lambda name: f"/api/{name}/organisations/2/invoices/1", body=None, needle=None),
    "V1": dict(path=lambda name: f"/api/{name}/admin/users/1/disable", body=None, needle=None),
}


def _login_bob(base: str) -> Optional[str]:
    """Deterministic login, same reasoning as operator._login: keep the
    token itself out of the model's hands to copy wrong, not the decision
    to misuse it."""
    try:
        with httpx.Client(timeout=10) as client:
            r = client.post(f"{base}/auth/login", json={"username": "bob", "password": "lab-password"})
            r.raise_for_status()
            return r.json().get("access_token")
    except Exception:
        return None


def _prompt(base: str, name: str, template: str, token: str) -> str:
    method, _, description = TEMPLATES[template]
    spec = _SPECS[template]
    path = spec["path"](name)
    body = spec["body"]
    body_line = f"\nSet the json_body argument to exactly {json.dumps(body)}." if body else ""
    return f"""Target API base URL: {base}

You are already authenticated as user "bob" with this bearer token: {token}

This API documents the operation {method} {path} -- "{description}". The
resource at that address belongs to a different user ("alice"), not you.

Use the http_request tool to send:
{method} {base}{path}
Set the headers argument to exactly {{"Authorization": "Bearer {token}"}}.{body_line}

Report the response status code and body verbatim."""


def _check(records: list[dict], name: str, template: str) -> tuple[Optional[bool], str]:
    method, _, _ = TEMPLATES[template]
    spec = _SPECS[template]
    path = spec["path"](name)
    hits = _find(records, path, method)
    if not hits:
        return None, f"agent never sent {method} {path}"
    payload = json.loads(hits[-1]["content"])
    status, body = payload.get("status_code"), str(payload.get("body", ""))
    needle = spec["needle"]
    ok = status == 200 and (needle is None or needle in body.lower())
    return ok, body[:400]


async def run_llm_sample(base: str, model: str, candidates: list[tuple[str, str]], round_id: int,
                          sample_size: int, rng_seed: Optional[int] = None,
                          should_stop: Optional[Callable[[], bool]] = None,
                          policy_file: Optional[Path] = None) -> list[dict]:
    """`candidates` is [(collection_name, template), ...] -- typically every
    templated collection from the round's deterministic pass (core/lab_checks
    .assess), excluding "legacy" ones which predate the template catalog.
    Picks up to `sample_size` at random and runs one independent LLM mission
    per pick. `should_stop` is checked between collections only, same
    cooperative-cancellation contract as operator.run_queue.

    `policy_file`, when given, is the defender's live authorization policy --
    the same ground truth core/lab_checks.assess() uses. A blocked attack
    (verdict False) against a collection the policy actually enforces is a
    *patched* defense; one that was simply never exploitable is not. Without
    this the two are indistinguishable (both just "verdict False"), so the
    LLM summary would report every secure collection as a flat "defended" --
    see run_dashboard_round's llm_summary and state_store.upsert_finding's
    `policy_patched`. LLM findings live under their own `lab-llm:{name}` id,
    which the defender's mark_verified_patch never touches, so the policy
    file is the *only* way this path can tell patched from always-secure."""
    base = base.rstrip("/")
    if sample_size <= 0 or not candidates:
        return []
    try:
        policy = read_policy(policy_file) if policy_file is not None else None
    except (OSError, ValueError):
        policy = None
    sample = random.Random(rng_seed).sample(candidates, k=min(sample_size, len(candidates)))
    token = _login_bob(base)
    if not token:
        store.log_event("operator", "LLM-sampled lab check skipped: could not log in as bob", round_id)
        return []

    store.log_event("operator", f"spinning up ReAct agent ({model} via Ollama) for {len(sample)} LLM-sampled lab check(s)", round_id)
    agent = await build_agent(model)

    findings = []
    for name, template in sample:
        if should_stop and should_stop():
            store.log_event("operator", "LLM-sampled lab checks stopped by user before next collection", round_id)
            break
        store.log_event("operator", f"LLM check: {template} on {name}", round_id, data={"collection": name, "template": template})
        try:
            prompt = _prompt(base, name, template, token)
            result = await agent.ainvoke({"messages": [("user", prompt)]}, config={"recursion_limit": RECURSION_LIMIT})
            records = _extract_tool_calls(result["messages"])
            validate_records(records)
            verdict, evidence = _check(records, name, template)
        except Exception as exc:
            verdict, evidence = None, f"module run failed: {exc}"

        finding = {
            "id": store.finding_id(base, f"lab-llm:{name}"), "module_id": "lab-llm", "template": template,
            "target": base, "collection": name, "kind": "llm",
            "endpoint": _SPECS[template]["path"](name), "method": TEMPLATES[template][0],
            "title": f"LLM-driven check: {template} ({name})",
            "owasp": "API5:2023 Broken Function Level Authorization" if template == "V1" else "API1:2023 Broken Object Level Authorization",
            "verdict": verdict, "evidence": evidence,
        }
        policy_patched = policy is not None and is_patched(policy, name, template)
        merged = store.upsert_finding(finding, round_id, policy_patched=policy_patched)
        finding["status"] = merged["status"]
        store.log_event("operator", f"LLM check '{name}' ({template}) verdict: {verdict}", round_id,
                         data={"verdict": verdict, "evidence": (evidence or "")[:300]})
        findings.append(finding)

    return findings
