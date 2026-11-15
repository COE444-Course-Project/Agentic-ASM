"""Single-worker lab with persistent, seeded growth and private ground truth.

Each collection adds one randomly selected operation family and supporting routes. All route mutations run on the event
loop; neither labels nor the evaluator manifest are served to the attacker.
"""
from __future__ import annotations

import asyncio
from contextlib import asynccontextmanager, suppress
from dataclasses import dataclass, replace
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
from core.template_catalog import TEMPLATES

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
    template_ids: tuple[str, ...] = tuple(TEMPLATES)
    vulnerability_probability: float = .5

    def __post_init__(self):
        if self.initial_collections < 0 or not math.isfinite(self.growth_seconds) or self.growth_seconds < 0 or self.max_collections < 0:
            raise ValueError("initial, interval and maximum must be >= 0")
        if self.max_collections and self.initial_collections > self.max_collections:
            raise ValueError("initial collections exceed maximum")
        if not self.template_ids or any(t not in (*TEMPLATES, "legacy") for t in self.template_ids):
            raise ValueError("Unknown template selection")
        if not 0 <= self.vulnerability_probability <= 1:
            raise ValueError("Vulnerability probability must be between 0 and 1")

    @classmethod
    def from_env(cls):
        return cls(
            state_file=Path(os.getenv("LAB_STATE_FILE", "lab-state/scenario.json")),
            policy_file=Path(os.getenv("LAB_POLICY_FILE", "lab-policy/policy.json")),
            seed=int(os.getenv("LAB_SEED", "444")),
            initial_collections=int(os.getenv("LAB_INITIAL_COLLECTIONS", "2")),
            growth_seconds=float(os.getenv("LAB_GROWTH_SECONDS", "60")),
            max_collections=int(os.getenv("LAB_MAX_COLLECTIONS", "100")),
            template_ids=tuple(os.getenv("LAB_TEMPLATES", ",".join(TEMPLATES)).split(",")),
            vulnerability_probability=float(os.getenv("LAB_VULNERABILITY_PROBABILITY", ".5")),
        )


@dataclass
class Controls:
    """The subset of Settings that is safe to change while the lab is live:
    identity (seed, state/policy file, initial_collections) never moves once
    the manifest exists, but pace, cap, template mix and vulnerability odds
    only ever affect collections added *after* the change (see add_collection),
    so they're exposed as a mutable, admin-editable copy instead."""
    growth_seconds: float
    max_collections: int
    template_ids: tuple[str, ...]
    vulnerability_probability: float
    paused: bool = False

    def __post_init__(self):
        if not math.isfinite(self.growth_seconds) or self.growth_seconds < 0 or self.max_collections < 0:
            raise ValueError("interval and maximum must be >= 0")
        if not self.template_ids or any(t not in (*TEMPLATES, "legacy") for t in self.template_ids):
            raise ValueError("Unknown template selection")
        if not 0 <= self.vulnerability_probability <= 1:
            raise ValueError("Vulnerability probability must be between 0 and 1")


class Login(BaseModel):
    username: str
    password: str


class GrowthUpdate(BaseModel):
    growth_seconds: float | None = None
    max_collections: int | None = None
    vulnerability_probability: float | None = None
    template_ids: list[str] | None = None
    paused: bool | None = None


class GrowRequest(BaseModel):
    count: int | None = None


class Item(BaseModel):
    id: int
    owner: str
    content: str


def current_user(credentials: HTTPAuthorizationCredentials | None = Depends(AUTH)) -> str:
    if credentials and credentials.credentials in ("alice-token", "bob-token", "admin-token"):
        return credentials.credentials.removesuffix("-token")
    raise HTTPException(401, "Valid bearer token required", headers={"WWW-Authenticate": "Bearer"})


class Scenario:
    def __init__(self, settings: Settings):
        self.settings = settings
        self.controls = Controls(growth_seconds=settings.growth_seconds, max_collections=settings.max_collections,
                                  template_ids=settings.template_ids,
                                  vulnerability_probability=settings.vulnerability_probability)
        self.policy_seen = settings.policy_file.exists()
        if settings.state_file.exists():
            self.manifest = json.loads(settings.state_file.read_text())
            if self.manifest.get("version") != 1 or self.manifest.get("seed") != settings.seed:
                raise ValueError("Existing scenario version/seed differs; use a new state file or volume")
            saved = len(self.manifest["collections"])
            if settings.max_collections and saved > settings.max_collections:
                # The cap may have been raised live (dashboard or closed loop); keep the saved scenario and stop there.
                LOG.warning("Saved scenario has %s collections; raising max_collections from %s", saved, settings.max_collections)
                self.controls = replace(self.controls, max_collections=saved)
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
        controls = self.controls
        if controls.max_collections and len(collections) >= controls.max_collections:
            return False
        index = len(collections) + 1
        # Seed controls which half of each pair is vulnerable: repeatable and
        # balanced, with no vulnerability marker in names or OpenAPI metadata.
        parity = hashlib.sha256(f"{self.settings.seed}:{(index - 1) // 2}".encode()).digest()[0] % 2
        entry = {"name": f"collection_{index:04d}", "introduced_at": time.time(),
                 "stage": index, "vulnerable": index % 2 == parity}
        if controls.template_ids != ("legacy",):
            digest = hashlib.sha256(f"templates-v2:{self.settings.seed}:{index}".encode()).digest()
            template = controls.template_ids[int.from_bytes(digest[:8], "big") % len(controls.template_ids)]
            entry.update(template=template,
                         vulnerable=int.from_bytes(digest[8:16], "big") / 2**64 < controls.vulnerability_probability)
        collections.append(entry)
        try:
            self.persist()
        except Exception:
            collections.pop()
            raise
        self.register(app, entry)
        LOG.info("Lab stage %s: added %s", index, entry["name"])
        return True

    def grow_on_demand(self, app: FastAPI, count: int | None = None) -> int:
        """Add collections now, on request, instead of on the timer. With a
        `count`, adds up to that many; without one, grows up to the configured
        max_collections. Returns how many were actually added (fewer if the
        cap is reached first). This is the manual counterpart to the grow()
        timer in create_app: a lab left at growth_seconds=0 never grows on its
        own, so the dashboard's "Grow" button calls here to grow it to the
        user's chosen limit and stop. The caller guarantees a bound (a count,
        or a non-zero max_collections) so this never loops unbounded."""
        added = 0
        while count is None or added < count:
            if not self.add_collection(app):
                break  # hit max_collections
            added += 1
        return added

    def register(self, app: FastAPI, entry: dict):
        name = entry["name"]
        if entry.get("template", "legacy") != "legacy":
            from lab.templates import register_template
            async def enforced(template):
                from core.lab_policy import read_policy
                try:
                    policy = await asyncio.to_thread(read_policy, self.settings.policy_file,
                                                    allow_missing=not self.policy_seen)
                    if policy["collections"] or self.settings.policy_file.exists():
                        self.policy_seen = True
                    value = policy["collections"].get(name, {})
                    # Legacy whole-collection flags cannot silently fix a new type.
                    return isinstance(value, dict) and value.get(template) is True
                except (OSError, ValueError) as exc:
                    LOG.warning("Policy read failed (%s): %s", type(exc).__name__, exc)
                    raise HTTPException(503, "Authorization policy unavailable") from exc
            register_template(app, entry, current_user, enforced)
            app.openapi_schema = None
            return
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

    def reset(self, app: FastAPI):
        """Wipe every collection (routes + manifest) and reseed back to
        `initial_collections`, in place -- the live equivalent of deleting
        the scenario volume and restarting, without a container restart.
        Growth controls (pace/cap/template mix/odds) are left as currently
        configured; only the collections themselves are cleared.

        Does not touch the policy file: it's mounted read-only here (the
        native defender owns writes to it), and it may be intentionally
        reused across resets. Because collections are renumbered from 1
        again, a stale policy entry for an old `collection_0001` would
        silently re-apply to the *new* `collection_0001` -- clear or move
        the policy file yourself first if you also want a clean remediation
        slate (see the README)."""
        app.router.routes = [r for r in app.router.routes if not getattr(r, "path", "").startswith("/api/collection_")]
        self.manifest["collections"] = []
        self.persist()
        app.openapi_schema = None
        while len(self.manifest["collections"]) < self.settings.initial_collections:
            self.add_collection(app)


POLL_SECONDS = 1.0  # how promptly a paused/frozen lab notices growth_seconds/paused being changed back on


def _growth_snapshot(scenario: Scenario) -> dict:
    c = scenario.controls
    return {"growth_seconds": c.growth_seconds, "max_collections": c.max_collections,
            "vulnerability_probability": c.vulnerability_probability,
            "template_ids": list(c.template_ids), "paused": c.paused,
            "collections": len(scenario.manifest["collections"]), "seed": scenario.settings.seed}


def create_app(settings: Settings | None = None) -> FastAPI:
    settings = settings or Settings.from_env()
    scenario = Scenario(settings)
    wake = asyncio.Event()  # lets an admin change interrupt a stale sleep immediately

    async def grow(app):
        # Always running (even when frozen/paused) so a later admin update can
        # resume growth live, with no container restart -- the old behaviour of
        # never starting a task at growth_seconds=0 would have made that
        # permanent. A capped lab also keeps polling instead of exiting, so
        # raising max_collections later resumes growth instead of needing a
        # restart. `wake` is set on every admin update so a change (e.g.
        # un-pausing, or a shorter interval) takes effect on the next loop
        # iteration rather than waiting out whatever sleep was already in
        # progress under the old settings.
        while True:
            controls = scenario.controls
            interval = controls.growth_seconds if not controls.paused and controls.growth_seconds > 0 else POLL_SECONDS
            wake.clear()
            with suppress(asyncio.TimeoutError):
                await asyncio.wait_for(wake.wait(), timeout=interval)
            controls = scenario.controls
            if controls.paused or controls.growth_seconds <= 0:
                continue
            try:
                scenario.add_collection(app)
            except Exception as exc:
                # Persistence failures (e.g. the policy/state volume going
                # away) are surfaced instead of silently freezing the surface.
                LOG.error("Lab growth tick failed: %s", exc)

    @asynccontextmanager
    async def lifespan(app):
        task = asyncio.create_task(grow(app))

        def report_failure(done):
            if not done.cancelled() and done.exception():
                LOG.error("Lab growth task stopped unexpectedly: %s", done.exception())
        task.add_done_callback(report_failure)
        try:
            yield
        finally:
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
        if body.username not in ("alice", "bob", "admin") or body.password != "lab-password":
            raise HTTPException(401, "Invalid credentials")
        return {"access_token": f"{body.username}-token", "token_type": "bearer"}

    # Operational growth knobs only (pace, cap, template mix, vulnerability
    # odds, pause) -- never the evaluator-private vulnerability labels
    # themselves, and never the identity fields (seed, initial_collections,
    # state/policy file) that existing persisted collections depend on.
    @app.get("/admin/growth")
    async def get_growth():
        return _growth_snapshot(scenario)

    @app.post("/admin/growth")
    async def update_growth(body: GrowthUpdate):
        updates = body.model_dump(exclude_unset=True)
        if "template_ids" in updates:
            updates["template_ids"] = tuple(updates["template_ids"])
        try:
            scenario.controls = replace(scenario.controls, **updates)
        except ValueError as exc:
            raise HTTPException(400, str(exc))
        wake.set()
        return _growth_snapshot(scenario)

    @app.post("/admin/grow")
    async def grow_now(body: GrowRequest):
        """Grow the lab on demand (manual counterpart to the timer). With a
        `count`, add that many; without one, grow up to max_collections and
        stop. Refuses an unbounded request (no count and no cap) so it can
        never run away. Growth odds, templates and cap are whatever
        /admin/growth currently holds."""
        count = body.count
        if count is not None:
            if count < 1 or count > 10000:
                raise HTTPException(400, "count must be between 1 and 10000")
        elif not scenario.controls.max_collections:
            raise HTTPException(400, "Set a max collections limit (or pass a count) to grow on demand")
        try:
            added = scenario.grow_on_demand(app, count)
        except Exception as exc:
            raise HTTPException(503, f"Growth failed: {exc}")
        return {**_growth_snapshot(scenario), "added": added}

    @app.post("/admin/reset")
    async def reset_scenario():
        """Clear every collection and reseed to `initial_collections` --
        see Scenario.reset()'s docstring for exactly what this does and
        does not touch (notably: not the policy file). Growth pace/pause
        are untouched, so unlike /admin/growth this does NOT wake() the
        grow() loop: doing so would fire an extra tick immediately on top
        of the reseed whenever growth happened to already be live, landing
        on initial_collections + 1 instead of exactly initial_collections."""
        try:
            scenario.reset(app)
        except Exception as exc:
            raise HTTPException(503, f"Reset failed: {exc}")
        return _growth_snapshot(scenario)

    for entry in scenario.manifest["collections"]:
        scenario.register(app, entry)
    while len(scenario.manifest["collections"]) < settings.initial_collections:
        scenario.add_collection(app)
    return app
