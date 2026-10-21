"""Single-worker lab with persistent, seeded growth and private ground truth.

Each collection adds two actual routes. All route mutations run on the event
loop; neither labels nor the evaluator manifest are served to the attacker.
"""
from __future__ import annotations

import asyncio
from contextlib import asynccontextmanager, suppress
from dataclasses import dataclass
import hashlib
import json
import logging
import math
import os
from pathlib import Path
import time

from fastapi import Depends, FastAPI, HTTPException
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from pydantic import BaseModel

LOG = logging.getLogger("uvicorn.error")
AUTH = HTTPBearer(auto_error=False)


@dataclass(frozen=True)
class Settings:
    state_file: Path = Path("lab-state/scenario.json")
    policy_file: Path = Path("lab-policy/policy.json")
    seed: int = 444
    initial_collections: int = 2
    growth_seconds: float = 60
    max_collections: int = 100  # 0 explicitly enables unbounded growth

    def __post_init__(self):
        if self.initial_collections < 1 or not math.isfinite(self.growth_seconds) or self.growth_seconds < 0 or self.max_collections < 0:
            raise ValueError("initial must be >= 1; interval and maximum must be >= 0")
        if self.max_collections and self.initial_collections > self.max_collections:
            raise ValueError("initial collections exceed maximum")

    @classmethod
    def from_env(cls):
        return cls(
            state_file=Path(os.getenv("LAB_STATE_FILE", "lab-state/scenario.json")),
            policy_file=Path(os.getenv("LAB_POLICY_FILE", "lab-policy/policy.json")),
            seed=int(os.getenv("LAB_SEED", "444")),
            initial_collections=int(os.getenv("LAB_INITIAL_COLLECTIONS", "2")),
            growth_seconds=float(os.getenv("LAB_GROWTH_SECONDS", "60")),
            max_collections=int(os.getenv("LAB_MAX_COLLECTIONS", "100")),
        )


class Login(BaseModel):
    username: str
    password: str


class Item(BaseModel):
    id: int
    owner: str
    content: str


def current_user(credentials: HTTPAuthorizationCredentials | None = Depends(AUTH)) -> str:
    if credentials and credentials.credentials in ("alice-token", "bob-token"):
        return credentials.credentials.removesuffix("-token")
    raise HTTPException(401, "Valid bearer token required", headers={"WWW-Authenticate": "Bearer"})


class Scenario:
    def __init__(self, settings: Settings):
        self.settings = settings
        self.policy_seen = settings.policy_file.exists()
        if settings.state_file.exists():
            self.manifest = json.loads(settings.state_file.read_text())
            if self.manifest.get("version") != 1 or self.manifest.get("seed") != settings.seed:
                raise ValueError("Existing scenario version/seed differs; use a new state file or volume")
            if settings.max_collections and len(self.manifest["collections"]) > settings.max_collections:
                raise ValueError("Saved scenario exceeds configured maximum")
        else:
            self.manifest = {"version": 1, "seed": settings.seed, "collections": []}

    def persist(self):
        path = self.settings.state_file
        path.parent.mkdir(parents=True, exist_ok=True)
        temporary = path.with_suffix(".tmp")
        temporary.write_text(json.dumps(self.manifest, indent=2))
        temporary.replace(path)

    def add_collection(self, app: FastAPI) -> bool:
        collections = self.manifest["collections"]
        if self.settings.max_collections and len(collections) >= self.settings.max_collections:
            return False
        index = len(collections) + 1
        # Seed controls which half of each pair is vulnerable: repeatable and
        # balanced, with no vulnerability marker in names or OpenAPI metadata.
        parity = hashlib.sha256(f"{self.settings.seed}:{(index - 1) // 2}".encode()).digest()[0] % 2
        entry = {"name": f"collection_{index:04d}", "introduced_at": time.time(),
                 "stage": index, "vulnerable": index % 2 == parity}
        collections.append(entry)
        try:
            self.persist()
        except Exception:
            collections.pop()
            raise
        self.register(app, entry)
        LOG.info("Lab stage %s: added %s", index, entry["name"])
        return True

    def register(self, app: FastAPI, entry: dict):
        name = entry["name"]
        records = {
            1: Item(id=1, owner="alice", content=f"Alice's private {name} record"),
            2: Item(id=2, owner="bob", content=f"Bob's private {name} record"),
        }

        async def list_items(user: str = Depends(current_user)) -> list[Item]:
            return [item for item in records.values() if item.owner == user]

        async def read_item(item_id: int, user: str = Depends(current_user)) -> Item:
            item = records.get(item_id)
            if item is None:
                raise HTTPException(404, "Item not found")
            # An operational policy overlay fixes ownership without changing the
            # evaluator's original vulnerability label. Invalid policies fail closed.
            from core.lab_policy import read_policy
            try:
                policy = await asyncio.to_thread(read_policy, self.settings.policy_file,
                                                allow_missing=not self.policy_seen)
                if policy["collections"] or self.settings.policy_file.exists():
                    self.policy_seen = True
                enforce = policy["collections"].get(name, False)
            except (OSError, ValueError) as exc:
                LOG.warning("Policy read failed (%s): %s", type(exc).__name__, exc)
                raise HTTPException(503, "Authorization policy unavailable") from exc
            if (enforce or not entry["vulnerable"]) and item.owner != user:
                raise HTTPException(403, "Item belongs to another user")
            return item

        prefix = f"/api/{name}/items"
        app.add_api_route(prefix, list_items, methods=["GET"], tags=[name],
                          name=f"list_{name}", response_model=list[Item])
        app.add_api_route(prefix + "/{item_id}", read_item, methods=["GET"], tags=[name],
                          name=f"read_{name}", response_model=Item)
        app.openapi_schema = None


def create_app(settings: Settings | None = None) -> FastAPI:
    settings = settings or Settings.from_env()
    scenario = Scenario(settings)

    async def grow(app):
        while True:
            await asyncio.sleep(settings.growth_seconds)
            if not scenario.add_collection(app):
                return

    @asynccontextmanager
    async def lifespan(app):
        task = asyncio.create_task(grow(app)) if settings.growth_seconds > 0 else None
        if task:
            # Report persistence or growth failures immediately instead of silently
            # leaving a seemingly healthy server with a frozen surface.
            def report_failure(done):
                if not done.cancelled() and done.exception():
                    LOG.error("Lab growth stopped: %s", done.exception())
            task.add_done_callback(report_failure)
        try:
            yield
        finally:
            if task:
                task.cancel()
                with suppress(asyncio.CancelledError):
                    await task

    app = FastAPI(title="Growing Resource API", version="1.0", lifespan=lifespan)
    app.state.scenario = scenario  # evaluator/test access only, no HTTP route

    @app.get("/health")
    async def health():
        return {"status": "ok"}

    @app.post("/auth/login")
    async def login(body: Login):
        if body.username not in ("alice", "bob") or body.password != "lab-password":
            raise HTTPException(401, "Invalid credentials")
        return {"access_token": f"{body.username}-token", "token_type": "bearer"}

    for entry in scenario.manifest["collections"]:
        scenario.register(app, entry)
    while len(scenario.manifest["collections"]) < settings.initial_collections:
        scenario.add_collection(app)
    return app
