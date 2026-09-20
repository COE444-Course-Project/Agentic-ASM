"""
Scout (attacker / recon): "Enumerates hosts, open ports, exposed services
and endpoints" per the proposal. For a single HTTP API target that
collapses to "paths and methods" -- Scout reads the target's OpenAPI spec
and records what it finds into the shared attack-surface state. It sends
no exploit payloads; that's Operator's job, once Planner has decided what
is worth trying.
"""
from __future__ import annotations

import time

import httpx

from core import state_store as store


def run(base: str, round_id: int) -> dict:
    store.log_event("scout", f"enumerating attack surface at {base}", round_id)
    endpoints: list[dict] = []
    try:
        with httpx.Client(timeout=10) as client:
            r = client.get(f"{base}/openapi.json")
            spec = r.json()
        for path, methods in spec.get("paths", {}).items():
            for method, op in methods.items():
                if method.lower() not in ("get", "post", "put", "delete", "patch"):
                    continue
                endpoints.append({
                    "path": path,
                    "method": method.upper(),
                    "summary": op.get("summary", ""),
                    "auth_required": "security" in op,
                })
        store.log_event("scout", f"discovered {len(endpoints)} endpoint/method pairs from /openapi.json", round_id)
    except Exception as exc:
        store.log_event("scout", f"could not fetch /openapi.json ({exc}); surface will be empty", round_id, level="warn")

    surface = {"target": base, "endpoints": endpoints, "discovered_at": time.time()}
    store.set_attack_surface(surface)
    return surface
