"""Fixture-based HTTP assessment. No access to scenario labels or policy files.

This is a deterministic lab adapter, not general autonomous discovery. It uses
supplied lab identities and validates supported operation effects and cleanup.
"""
import re
from typing import Callable, Optional

from core import state_store as store
from core.template_catalog import TEMPLATES
from core.template_checks import template_for, probe_template

PATH = re.compile(r"/api/(collection_[0-9]{4,})/items/\{item_id\}")


def discover(client) -> list[str]:
    response = client.get("/openapi.json")
    response.raise_for_status()
    return sorted({match[1] for path, operations in response.json()["paths"].items()
                   if (match := PATH.fullmatch(path)) and "get" in operations})


def probe(client, collection: str, template=None) -> dict:
    if not re.fullmatch(r"collection_[0-9]{4,}", collection):
        raise ValueError("Unsupported collection name")
    if template is None:
        response = client.get("/openapi.json")
        response.raise_for_status()
        template = template_for(response.json()["paths"], collection)
    if template != "legacy":
        return probe_template(client, collection, template)
    return probe_legacy(client, collection)


def probe_legacy(client, collection: str) -> dict:
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


def assess(client, target: str, should_stop: Optional[Callable[[], bool]] = None) -> dict:
    """One assessment pass; save endpoint-scoped findings for the defender.

    `should_stop` is checked between collections only: the probe already in
    flight for the current collection always finishes first."""
    target = target.rstrip("/")
    names = discover(client)
    spec = client.get("/openapi.json")
    spec.raise_for_status()
    paths = spec.json()["paths"]
    round_id = store.start_round(target)
    findings = []
    stopped = False
    for name in names:
        if should_stop and should_stop():
            store.log_event("operator", "round stopped by user before next collection", round_id)
            stopped = True
            break
        template = template_for(paths, name)
        try:
            evidence = probe(client, name, template)
        except Exception as exc:
            evidence = {"collection": name, "verdict": None, "error": str(exc)}
        finding = {"id": store.finding_id(target, f"lab-bola:{name}"), "module_id": "lab-bola",
                   "target": target, "collection": name, "endpoint": f"/api/{name}/items/{{item_id}}",
                   "method": "GET", "kind": "deterministic", "title": f"Object ownership: {name}",
                   "owasp": "API1:2023 Broken Object Level Authorization",
                   "verdict": evidence["verdict"], "evidence": evidence}
        if template != "legacy":
            method, suffix, title = TEMPLATES[template]
            finding.update(id=store.finding_id(target, f"lab-{template}:{name}"),
                           module_id=f"lab-{template}", template=template,
                           endpoint=f"/api/{name}{suffix}", method=method, title=f"{template}: {title} ({name})",
                           owasp="API5:2023 Broken Function Level Authorization" if template == "V1" else finding["owasp"])
        store.upsert_finding(finding, round_id)
        store.log_event("operator", f"lab assessment {name}: {finding['verdict']}", round_id)
        findings.append(finding)
    summary = {"vulnerable": sum(f["verdict"] is True for f in findings),
               "defended": sum(f["verdict"] is False for f in findings),
               "inconclusive": sum(f["verdict"] is None for f in findings)}
    status = "stopped" if stopped else "done"
    store.finish_round(round_id, summary, status=status)
    return {"round": round_id, "target": target, "findings": findings, "summary": summary, "status": status}
