"""Known-fixture exploit/verification adapters. No private manifest access."""
import secrets

from core.template_catalog import TEMPLATES


def template_for(paths, name):
    prefix = f"/api/{name}"
    # PATCH must be checked before GET on the same document resource.
    for template in ("B5", "B6", "B2", "B3", "B4", "B7", "V1", "B1"):
        method, suffix, _ = TEMPLATES[template]
        if method.lower() in paths.get(prefix + suffix, {}):
            return template
    return "legacy"


def probe_template(client, name, template):
    prefix = f"/api/{name}"
    headers, records, checks = {}, {}, {}
    for user in ("alice", "bob", "admin") if template == "V1" else ("alice", "bob"):
        response = client.post("/auth/login", json={"username": user, "password": "lab-password"})
        response.raise_for_status()
        headers[user] = {"Authorization": f"Bearer {response.json()['access_token']}"}
        if user == "admin":
            continue
        response = client.get(prefix + "/items", headers=headers[user])
        response.raise_for_status()
        items = response.json()
        if len(items) != 1 or items[0].get("owner") != user:
            raise ValueError("Unexpected lab fixture listing")
        records[user] = items[0]

    def action(actor, owner, *, attack, anonymous=False):
        """Return actual effect, not merely status. Restore every mutable fixture."""
        target = records[owner]
        id = target["id"]
        auth = {} if anonymous else headers[actor]
        own_id = records.get(actor, target)["id"]
        if template == "B1":
            r = client.get(f"{prefix}/documents/{id}", headers=auth)
            effect = r.status_code == 200 and r.json() == target
        elif template == "B2":
            r = client.post(prefix + "/exports", json={"document_id": id}, headers=auth)
            effect = r.status_code == 200 and r.json().get("document") == target
        elif template == "B3":
            r = client.get(f"{prefix}/projects/{own_id}/files/{id}", headers=auth)
            effect = r.status_code == 200 and r.json().get("owner") == owner and r.json().get("project_id") == id
        elif template == "B4":
            ids = [own_id, id] if attack else [id]
            r = client.post(prefix + "/documents/batch", json={"ids": ids}, headers=auth)
            effect = r.status_code == 200 and target in r.json()
        elif template == "B5":
            changed = f"probe-{secrets.token_hex(8)}"
            try:
                r = client.patch(f"{prefix}/documents/{id}", json={"content": changed}, headers=auth)
                read = client.get(f"{prefix}/items/{id}", headers=headers[owner])
                read.raise_for_status()
                effect = read.json().get("content") == changed
            finally:
                restore = client.patch(f"{prefix}/documents/{id}", json={"content": target["content"]}, headers=headers[owner])
                restore.raise_for_status()
                restored = client.get(f"{prefix}/items/{id}", headers=headers[owner])
                if restored.status_code != 200 or restored.json() != target:
                    raise RuntimeError("Document cleanup failed")
        elif template == "B6":
            r = client.post(f"{prefix}/documents/{id}/share", headers=auth)
            effect = False
            if r.status_code == 200:
                token = r.json()["token"]
                # Use only local paths; never follow arbitrary links from responses.
                if not isinstance(token, str) or not token.replace("-", "").replace("_", "").isalnum():
                    raise ValueError("Invalid share token")
                try:
                    shared = client.get(f"{prefix}/shares/{token}")
                    effect = shared.status_code == 200 and shared.json() == target
                finally:
                    client.delete(f"{prefix}/shares/{token}", headers=headers[owner]).raise_for_status()
                    if client.get(f"{prefix}/shares/{token}").status_code != 404:
                        raise RuntimeError("Share cleanup failed")
        elif template == "B7":
            r = client.get(f"{prefix}/organisations/{own_id}/invoices/{id}", headers=auth)
            effect = r.status_code == 200 and r.json().get("owner") == owner and r.json().get("org_id") == id
        elif template == "V1":
            try:
                r = client.post(f"{prefix}/admin/users/{id}/disable", headers=auth)
                state = client.get(f"{prefix}/users/{id}", headers=headers["admin"])
                state.raise_for_status()
                effect = state.json().get("disabled") is True
                if effect:
                    effect = client.get(prefix + "/items", headers=headers[owner]).status_code == 403
            finally:
                client.post(f"{prefix}/admin/users/{id}/enable", headers=headers["admin"]).raise_for_status()
                state = client.get(f"{prefix}/users/{id}", headers=headers["admin"])
                if state.status_code != 200 or state.json().get("disabled") is not False:
                    raise RuntimeError("Account cleanup failed")
        else:
            raise ValueError("Unsupported template")
        return r.status_code, effect

    for user in ("alice", "bob"):
        # V1's positive control is an administrator performing the operation.
        status, effect = action("admin" if template == "V1" else user, user, attack=False)
        checks[f"{user}_owner_ok"] = status == 200 and effect
    status, effect = action("alice", "bob", attack=True, anonymous=True)
    checks["anonymous_blocked"] = status == 401 and not effect
    for actor, owner in (("alice", "bob"), ("bob", "alice")):
        status, effect = action(actor, owner, attack=True)
        checks[f"{actor}_cross_status"] = status
        checks[f"{actor}_cross_leak"] = effect  # includes unauthorized state changes
        if template in ("B2", "B5", "B6"):
            checks[f"{actor}_direct_read_blocked"] = client.get(
                f"{prefix}/documents/{records[owner]['id']}", headers=headers[actor]).status_code == 403
        if template in ("B3", "B7"):
            foreign = records[owner]["id"]
            suffix = f"/projects/{foreign}/files/{foreign}" if template == "B3" else f"/organisations/{foreign}/invoices/{foreign}"
            r = client.get(prefix + suffix, headers=headers[actor])
            checks[f"{actor}_foreign_scope_status"] = r.status_code
            checks[f"{actor}_foreign_scope_leak"] = r.status_code == 200 and r.json().get("owner") == owner

    healthy = all(checks[k] for k in ("alice_owner_ok", "bob_owner_ok", "anonymous_blocked"))
    healthy = healthy and all(v for k, v in checks.items() if k.endswith("direct_read_blocked"))
    statuses = [v for k, v in checks.items() if k.endswith("_status")]
    leaks = [v for k, v in checks.items() if k.endswith("_leak")]
    blocked = all(status == 403 for status in statuses) and not any(leaks)
    verdict = (True if any(leaks) else False if blocked else None) if healthy else None
    return {"collection": name, "template": template, "verdict": verdict,
            "checks": checks, "cleanup_ok": True, "verified_secure": healthy and blocked}
