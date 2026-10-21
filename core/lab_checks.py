"""Fixture-based HTTP assessment. No access to scenario labels or policy files.

This is a deterministic lab adapter, not general autonomous discovery. It uses
two supplied lab identities and validates both directions of object ownership.
"""
import re

from core import state_store as store

PATH = re.compile(r"/api/(collection_[0-9]{4,})/items/\{item_id\}")


def discover(client) -> list[str]:
    response = client.get("/openapi.json")
    response.raise_for_status()
    return sorted({match[1] for path, operations in response.json()["paths"].items()
                   if (match := PATH.fullmatch(path)) and "get" in operations})


def probe(client, collection: str) -> dict:
    if not re.fullmatch(r"collection_[0-9]{4,}", collection):
        raise ValueError("Unsupported collection name")
    prefix = f"/api/{collection}/items"
    headers, records, checks = {}, {}, {}
    for user in ("alice", "bob"):
        response = client.post("/auth/login", json={"username": user, "password": "lab-password"})
        response.raise_for_status()
        headers[user] = {"Authorization": f"Bearer {response.json()['access_token']}"}
        response = client.get(prefix, headers=headers[user])
        response.raise_for_status()
        items = response.json()
        if len(items) != 1 or items[0].get("owner") != user:
            raise ValueError("Lab fixture listing is not one owned record")
        records[user] = items[0]
        response = client.get(f"{prefix}/{items[0]['id']}", headers=headers[user])
        checks[f"{user}_owner_ok"] = response.status_code == 200 and response.json() == items[0]
    checks["anonymous_blocked"] = client.get(f"{prefix}/{records['alice']['id']}").status_code == 401
    for actor, owner in (("alice", "bob"), ("bob", "alice")):
        response = client.get(f"{prefix}/{records[owner]['id']}", headers=headers[actor])
        checks[f"{actor}_cross_status"] = response.status_code
        checks[f"{actor}_cross_leak"] = response.status_code == 200 and response.json() == records[owner]
    healthy = all(checks[key] for key in ("alice_owner_ok", "bob_owner_ok", "anonymous_blocked"))
    blocked = all(checks[f"{user}_cross_status"] == 403 for user in ("alice", "bob"))
    leaked = any(checks[f"{user}_cross_leak"] for user in ("alice", "bob"))
    verdict = (True if leaked else False if blocked else None) if healthy else None
    return {"collection": collection, "verdict": verdict, "checks": checks,
            "verified_secure": healthy and blocked}


def assess(client, target: str) -> dict:
    """One assessment pass; save endpoint-scoped findings for the defender."""
    target = target.rstrip("/")
    names = discover(client)
    round_id = store.start_round(target)
    findings = []
    for name in names:
        try:
            evidence = probe(client, name)
        except Exception as exc:
            evidence = {"collection": name, "verdict": None, "error": str(exc)}
        finding = {"id": store.finding_id(target, f"lab-bola:{name}"), "module_id": "lab-bola",
                   "target": target, "collection": name, "endpoint": f"/api/{name}/items/{{item_id}}",
                   "method": "GET", "kind": "deterministic", "title": f"Object ownership: {name}",
                   "owasp": "API1:2023 Broken Object Level Authorization",
                   "verdict": evidence["verdict"], "evidence": evidence}
        store.upsert_finding(finding, round_id)
        store.log_event("operator", f"lab assessment {name}: {finding['verdict']}", round_id)
        findings.append(finding)
    summary = {"vulnerable": sum(f["verdict"] is True for f in findings),
               "defended": sum(f["verdict"] is False for f in findings),
               "inconclusive": sum(f["verdict"] is None for f in findings)}
    store.finish_round(round_id, summary)
    return {"round": round_id, "target": target, "findings": findings, "summary": summary}
