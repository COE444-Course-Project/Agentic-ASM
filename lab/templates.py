"""One operation family per collection; all auxiliary operations are protected."""
import secrets

from fastapi import Depends, HTTPException
from pydantic import BaseModel


class ExportBody(BaseModel):
    document_id: int


class BatchBody(BaseModel):
    ids: list[int]


class UpdateBody(BaseModel):
    content: str


def register_template(app, entry, current_user, enforced):
    name, template = entry["name"], entry["template"]
    prefix = f"/api/{name}"
    documents = {i: {"id": i, "owner": owner, "content": f"{owner}'s private {name} document"}
                 for i, owner in ((1, "alice"), (2, "bob"))}
    disabled = {1: False, 2: False}
    shares = {}

    async def active_user(user: str = Depends(current_user)):
        if user in ("alice", "bob") and disabled[1 if user == "alice" else 2]:
            raise HTTPException(403, "Account is disabled in this scenario")
        return user

    def resource(id):
        if id not in documents:
            raise HTTPException(404, "Resource not found")
        return documents[id]

    def owns(user, document):
        if document["owner"] != user:
            raise HTTPException(403, "Resource belongs to another user")

    def admin(user):
        if user != "admin":
            raise HTTPException(403, "Administrator role required")

    async def protected():
        # Read policy even on initially secure variants: broken policy fails closed.
        policy_enforced = await enforced(template)
        return policy_enforced or not entry["vulnerable"]

    def route(path, handler, method):
        app.add_api_route(prefix + path, handler, methods=[method], tags=[name],
                          name=f"{name}_{handler.__name__}")

    async def listing(user: str = Depends(active_user)):
        return [dict(d) for d in documents.values() if d["owner"] == user]

    async def owned_item(item_id: int, user: str = Depends(active_user)):
        d = resource(item_id)
        owns(user, d)
        return dict(d)

    # Stable, always-protected fixture discovery for the known lab adapter.
    route("/items", listing, "GET")
    route("/items/{item_id}", owned_item, "GET")

    async def read_document(id: int, user: str = Depends(active_user)):
        d = resource(id)
        if template != "B1" or await protected():
            owns(user, d)
        return dict(d)

    # Direct reads remain protected for export/update/share scenarios.
    if template in ("B1", "B2", "B5", "B6"):
        route("/documents/{id}", read_document, "GET")

    if template == "B2":
        async def export(body: ExportBody, user: str = Depends(active_user)):
            d = resource(body.document_id)
            if await protected():
                owns(user, d)
            return {"document": dict(d)}
        route("/exports", export, "POST")

    elif template == "B3":
        async def file(project_id: int, file_id: int, user: str = Depends(active_user)):
            # Membership is always enforced; only the relationship check varies.
            owns(user, resource(project_id))
            d = resource(file_id)
            if await protected() and file_id != project_id:
                raise HTTPException(403, "File is outside this project")
            return {**d, "project_id": file_id}
        route("/projects/{project_id}/files/{file_id}", file, "GET")

    elif template == "B4":
        async def batch(body: BatchBody, user: str = Depends(active_user)):
            selected = [resource(id) for id in body.ids]
            check_all = await protected()
            for d in selected if check_all else selected[:1]:
                owns(user, d)
            return [dict(d) for d in selected]
        route("/documents/batch", batch, "POST")

    elif template == "B5":
        async def update(id: int, body: UpdateBody, user: str = Depends(active_user)):
            d = resource(id)
            if await protected():
                owns(user, d)
            d["content"] = body.content
            return dict(d)
        route("/documents/{id}", update, "PATCH")

    elif template == "B6":
        async def share(id: int, user: str = Depends(active_user)):
            d = resource(id)
            if await protected():
                owns(user, d)
            token = secrets.token_urlsafe(24)
            shares[token] = id
            return {"token": token, "url": f"{prefix}/shares/{token}"}

        async def shared(token: str):
            if token not in shares:
                raise HTTPException(404, "Share not found")
            return dict(resource(shares[token]))

        async def revoke(token: str, user: str = Depends(active_user)):
            if token not in shares:
                raise HTTPException(404, "Share not found")
            owns(user, resource(shares[token]))
            del shares[token]
            return {"revoked": True}
        route("/documents/{id}/share", share, "POST")
        route("/shares/{token}", shared, "GET")
        route("/shares/{token}", revoke, "DELETE")

    elif template == "B7":
        async def invoice(org_id: int, id: int, user: str = Depends(active_user)):
            if user not in ("alice", "bob"):
                raise HTTPException(403, "Billing role required")
            d = resource(id)
            if await protected():
                owns(user, resource(org_id))
                if id != org_id:
                    raise HTTPException(403, "Invoice is outside this organisation")
            return {**d, "org_id": id}
        route("/organisations/{org_id}/invoices/{id}", invoice, "GET")

    elif template == "V1":
        async def disable(id: int, user: str = Depends(active_user)):
            resource(id)
            if await protected():
                admin(user)
            disabled[id] = True
            return {"disabled": True}

        async def enable(id: int, user: str = Depends(active_user)):
            resource(id)
            admin(user)
            disabled[id] = False
            return {"disabled": False}

        async def status(id: int, user: str = Depends(active_user)):
            d = resource(id)
            if user != "admin":
                owns(user, d)
            return {"id": id, "disabled": disabled[id]}
        route("/admin/users/{id}/disable", disable, "POST")
        route("/admin/users/{id}/enable", enable, "POST")
        route("/users/{id}", status, "GET")
