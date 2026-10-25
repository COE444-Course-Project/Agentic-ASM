"""
Minimal live dashboard for the attacker agent -- exists so M4 ("attacker
agent discovers and reports findings") is something you can watch happen,
not just a Markdown file after the fact.

Reads the exact state/ files that orchestrator.py and run_attacker.py
write, so this process and the CLI are independent: leave the GUI open in
a browser tab while a round runs from a terminal, or click "Run a round"
here and it drives the same orchestrator in a background thread. When a
Defender agent exists, this same page is where its side of the loop shows
up too -- it reads the same state_store.snapshot().

    .venv/bin/python3 gui/server.py [--port 8765]
"""
from __future__ import annotations

import argparse
import asyncio
import json
import os
import sys
import threading
from pathlib import Path
from urllib.parse import urlparse

import httpx

from flask import Flask, Response, jsonify, request

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

import orchestrator  # noqa: E402
from agents.lab_operator import run_llm_sample  # noqa: E402
from core.vampi_setup import prepare_vampi
from core import state_store as store  # noqa: E402
from core.lab_checks import assess, PATH as LAB_PATH  # noqa: E402

MAX_LLM_SAMPLE = 50  # a hard ceiling on the dashboard's "LLM-sampled checks" field -- see run_dashboard_round

app = Flask(__name__, static_folder=None)

# Same env vars run_attacker.py reads. Native default hits VAmPI's
# port-mapped localhost URL; the dockerized compose setup overrides these
# to the in-network service name (e.g. http://vampi-vulnerable:5000) so the
# page's default fields are correct without editing this file.
DEFAULT_TARGET = os.environ.get("TARGET", "http://localhost:5002")
DEFAULT_MODEL = os.environ.get("MODEL", "qwen2.5")
# Ground truth for which custom-lab collections the defender has actually
# patched -- see core/lab_checks.assess()'s policy_file param. Only present
# when this process can see the host's lab-policy/ (mounted in docker-compose
# .yml); absent natively unless LAB_POLICY_FILE is set to match run_defender
# .py's --policy-file. Missing/unreadable is fine -- assess() falls back to
# its own history, same as before this existed.
LAB_POLICY_FILE = Path(os.environ.get("LAB_POLICY_FILE", ROOT / "lab-policy" / "policy.json"))

# Populates the target dropdown and the "what does this target do" sidebar.
# Each service has two addresses -- an in-network Docker service name and a
# host-published localhost port -- but only one of the two is actually
# reachable from wherever *this process* runs: inside the docker-compose
# network (TARGET already points at the in-network vampi-vulnerable host)
# "localhost" means the agent container itself, not your machine, so only
# the in-network names resolve; run gui/server.py natively and it's the
# other way around. `reachable` reflects that so the sidebar can say so
# instead of letting someone pick an address that silently fails. The field
# stays free text regardless -- this is known-good starting points, not a
# restriction. Port 8001 (an earlier default in planning conversation) and
# host port 5000 (claimed by macOS's AirPlay Receiver, not Docker) are
# deliberately not listed; see the sidebar guide.
_DOCKERIZED = "vampi-vulnerable" in DEFAULT_TARGET
KNOWN_TARGETS = [
    {"label": "VAmPI vulnerable", "scope": "internal", "kind": "vampi",
     "url": os.environ.get("VAMPI_VULNERABLE_INTERNAL", "http://vampi-vulnerable:5000"),
     "description": "Intentionally vulnerable VAmPI instance -- the main attack benchmark. Checks here should mostly come back VULNERABLE.",
     "reachable": _DOCKERIZED},
    {"label": "VAmPI vulnerable", "scope": "host", "kind": "vampi",
     "url": os.environ.get("VAMPI_VULNERABLE_HOST", "http://localhost:5002"),
     "description": "Same instance, reached via its published host port. Only reachable if this dashboard runs natively on your machine, not in Docker.",
     "reachable": not _DOCKERIZED},
    {"label": "VAmPI secure", "scope": "internal", "kind": "vampi",
     "url": os.environ.get("VAMPI_SECURE_INTERNAL", "http://vampi-secure:5000"),
     "description": "Hardened VAmPI instance -- used to confirm checks correctly come back defended/secure instead of always flagging VULNERABLE.",
     "reachable": _DOCKERIZED},
    {"label": "VAmPI secure", "scope": "host", "kind": "vampi",
     "url": os.environ.get("VAMPI_SECURE_HOST", "http://localhost:5001"),
     "description": "Same instance, reached via its published host port. Only reachable if this dashboard runs natively on your machine, not in Docker.",
     "reachable": not _DOCKERIZED},
    {"label": "Custom API lab", "scope": "internal", "kind": "custom",
     "url": os.environ.get("CUSTOM_API_INTERNAL", "http://growing-api:8000"),
     "description": "The self-growing FastAPI lab (compose.lab.yml) -- adds one of 8 ownership-vulnerability templates on a timer. Has its own growth controls below.",
     "reachable": _DOCKERIZED},
    {"label": "Custom API lab", "scope": "host", "kind": "custom",
     "url": os.environ.get("CUSTOM_API_HOST", "http://localhost:8000"),
     "description": "Same lab, reached via its published host port. Only reachable if this dashboard runs natively on your machine, not in Docker.",
     "reachable": not _DOCKERIZED},
]


def _valid_target(raw) -> str | None:
    """Normalize and validate a target URL, or return None if it isn't one."""
    if not isinstance(raw, str):
        return None
    target = raw.strip().rstrip("/")
    parsed = urlparse(target)
    if parsed.scheme not in ("http", "https") or not parsed.hostname:
        return None
    return target

_run_lock = threading.Lock()
_running = {"active": False, "target": None, "model": None, "mode": None, "llm_sample": 0, "error": None, "stopping": False}
# Cooperative cancellation only: set between modules/collections, never mid-request
# (an in-flight Ollama call or HTTP probe always finishes first -- see run_queue()/assess()).
_cancel_event = threading.Event()


async def run_dashboard_round(target: str, model: str, mode: str = "auto", should_stop=None, llm_sample: int = 0):
    """Route one assessment using the public API schema, without applying repairs.

    `llm_sample`, custom API only: after the deterministic pass covers every
    collection, also run `llm_sample` independent LLM-driven missions (same
    users, same documented operation, decided by `model` via Ollama) against
    that many randomly chosen collections, as an additional cross-check --
    see agents/lab_operator.py's module docstring for why this is sampled
    rather than exhaustive."""
    with httpx.Client(base_url=target, timeout=10) as client:
        response = client.get("/openapi.json")
        response.raise_for_status()
        paths = response.json().get("paths", {})
        detected = ("custom" if "/auth/login" in paths and any(LAB_PATH.fullmatch(p) for p in paths)
                    else "vampi" if "/users/v1/login" in paths else None)
        if detected is None:
            raise ValueError("Unsupported API: expected VAmPI or the custom API lab.")
        if mode != "auto" and mode != detected:
            raise ValueError(f"Selected {mode}, but this target exposes the {detected} API. Check the target URL.")
        _running["mode"] = detected
        store.log_event("orchestrator", f"Dashboard selected {detected} assessment for {target}")
        if detected == "custom":
            orchestrator.scout.run(target, None)
            result = assess(client, target, should_stop=should_stop,
                            policy_file=LAB_POLICY_FILE if LAB_POLICY_FILE.exists() else None)
            if llm_sample > 0 and not (should_stop and should_stop()):
                candidates = [(f["collection"], f["template"]) for f in result["findings"] if f.get("template")]
                store.log_event("orchestrator", f"Running up to {llm_sample} LLM-sampled cross-check(s) via {model}")
                llm_findings = await run_llm_sample(target, model, candidates, result["round"], llm_sample,
                                                     should_stop=should_stop)
                result = {**result, "llm_findings": llm_findings}
            return result
    prepare_vampi(target)
    store.log_event("orchestrator", f"VAmPI database reset and seeded accounts/books verified for {target}")
    return await orchestrator.run_attacker_round(target, model, should_stop=should_stop)


def _run_round_in_background(target: str, model: str, mode: str = "auto", llm_sample: int = 0) -> bool:
    with _run_lock:
        if _running["active"]:
            return False
        _cancel_event.clear()
        _running.update(active=True, target=target, model=model, mode=mode, llm_sample=llm_sample,
                         error=None, stopping=False)

    def _worker():
        try:
            asyncio.run(run_dashboard_round(target, model, mode, should_stop=_cancel_event.is_set, llm_sample=llm_sample))
        except Exception as exc:
            _running["error"] = str(exc)
        finally:
            with _run_lock:
                _running["active"] = False
                _running["stopping"] = False

    threading.Thread(target=_worker, daemon=True).start()
    return True


@app.get("/")
def index():
    html = (Path(__file__).parent / "static" / "index.html").read_text(encoding="utf-8")
    html = (html.replace("__DEFAULT_TARGET__", DEFAULT_TARGET)
                .replace("__DEFAULT_MODEL__", DEFAULT_MODEL)
                .replace("__KNOWN_TARGETS_JSON__", json.dumps(KNOWN_TARGETS)))
    return Response(html, mimetype="text/html")


@app.get("/api/state")
def api_state():
    snap = store.snapshot()
    snap["running"] = dict(_running)
    return jsonify(snap)


@app.post("/api/run")
def api_run():
    body = request.get_json(silent=True)
    if body is None:
        body = {}
    if not isinstance(body, dict):
        return jsonify({"ok": False, "error": "Expected a JSON object"}), 400
    model = body.get("model", DEFAULT_MODEL)
    mode = body.get("mode", "auto")
    llm_sample = body.get("llm_sample", 0)
    if not isinstance(model, str) or mode not in ("auto", "vampi", "custom"):
        return jsonify({"ok": False, "error": "Invalid target, model or assessment type"}), 400
    if not isinstance(llm_sample, int) or isinstance(llm_sample, bool) or not 0 <= llm_sample <= MAX_LLM_SAMPLE:
        return jsonify({"ok": False, "error": f"llm_sample must be an integer from 0 to {MAX_LLM_SAMPLE}"}), 400
    target = _valid_target(body.get("target", DEFAULT_TARGET))
    if target is None:
        return jsonify({"ok": False, "error": "Enter a valid HTTP or HTTPS target URL"}), 400
    if not _run_round_in_background(target, model, mode, llm_sample):
        return jsonify({"ok": False, "error": "a round is already running"}), 409
    return jsonify({"ok": True, "target": target, "model": model, "mode": mode, "llm_sample": llm_sample})


@app.post("/api/stop")
def api_stop():
    with _run_lock:
        if not _running["active"]:
            return jsonify({"ok": False, "error": "no round is running"}), 409
        if _running["stopping"]:
            return jsonify({"ok": False, "error": "stop already requested"}), 409
        _running["stopping"] = True
    _cancel_event.set()
    store.log_event("orchestrator", "stop requested from dashboard; finishing the in-flight module/collection")
    return jsonify({"ok": True})


@app.get("/api/lab-growth")
def api_lab_growth_get():
    """Proxy to the custom API lab's own /admin/growth, so the dashboard's
    browser never needs direct/CORS access to the lab -- it only ever talks
    to this backend, same as every other panel."""
    target = _valid_target(request.args.get("target", ""))
    if target is None:
        return jsonify({"ok": False, "error": "Enter a valid HTTP or HTTPS target URL"}), 400
    try:
        with httpx.Client(timeout=10) as client:
            response = client.get(f"{target}/admin/growth")
    except httpx.HTTPError as exc:
        return jsonify({"ok": False, "error": f"Could not reach {target}: {exc}"}), 502
    if response.status_code == 404:
        return jsonify({"ok": False, "error": "This target has no growth controls (not the custom API lab?)"}), 404
    if response.is_error:
        return jsonify({"ok": False, "error": response.text[:300]}), response.status_code
    return jsonify({"ok": True, **response.json()})


@app.post("/api/lab-growth")
def api_lab_growth_set():
    body = request.get_json(silent=True)
    if not isinstance(body, dict):
        return jsonify({"ok": False, "error": "Expected a JSON object"}), 400
    target = _valid_target(body.get("target"))
    if target is None:
        return jsonify({"ok": False, "error": "Enter a valid HTTP or HTTPS target URL"}), 400
    updates = {k: v for k, v in body.items() if k != "target"}
    try:
        with httpx.Client(timeout=10) as client:
            response = client.post(f"{target}/admin/growth", json=updates)
    except httpx.HTTPError as exc:
        return jsonify({"ok": False, "error": f"Could not reach {target}: {exc}"}), 502
    if response.status_code == 404:
        return jsonify({"ok": False, "error": "This target has no growth controls (not the custom API lab?)"}), 404
    if response.is_error:
        detail = response.text[:300]
        try:
            detail = response.json().get("detail", detail)
        except ValueError:
            pass
        return jsonify({"ok": False, "error": detail}), response.status_code
    return jsonify({"ok": True, **response.json()})


@app.post("/api/lab-reset")
def api_lab_reset():
    """Proxy to the custom API lab's /admin/reset: clears every collection
    and reseeds to its configured initial count, in place -- no scenario
    volume deletion or container restart needed. See lab/app.py's
    Scenario.reset() for exactly what is and isn't touched (notably: never
    the policy file, which isn't reachable from here)."""
    body = request.get_json(silent=True) or {}
    if not isinstance(body, dict):
        return jsonify({"ok": False, "error": "Expected a JSON object"}), 400
    target = _valid_target(body.get("target"))
    if target is None:
        return jsonify({"ok": False, "error": "Enter a valid HTTP or HTTPS target URL"}), 400
    with _run_lock:
        if _running["active"]:
            return jsonify({"ok": False, "error": "an assessment is currently running"}), 409
    try:
        with httpx.Client(timeout=10) as client:
            response = client.post(f"{target}/admin/reset")
    except httpx.HTTPError as exc:
        return jsonify({"ok": False, "error": f"Could not reach {target}: {exc}"}), 502
    if response.status_code == 404:
        return jsonify({"ok": False, "error": "This target has no reset endpoint (not the custom API lab?)"}), 404
    if response.is_error:
        detail = response.text[:300]
        try:
            detail = response.json().get("detail", detail)
        except ValueError:
            pass
        return jsonify({"ok": False, "error": detail}), response.status_code
    return jsonify({"ok": True, **response.json()})


@app.post("/api/reset")
def api_reset():
    with _run_lock:
        if _running["active"]:
            return jsonify({"ok": False, "error": "a round is currently running"}), 409
    store.reset_all()
    return jsonify({"ok": True})


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--port", type=int, default=8765)
    ap.add_argument("--host", default=os.environ.get("HOST", "127.0.0.1"),
                     help="Bind address. The Docker image overrides this to 0.0.0.0 so the published port reaches the container.")
    args = ap.parse_args()
    print(f"attacker-agent dashboard: http://localhost:{args.port}")
    app.run(host=args.host, port=args.port, debug=False)


if __name__ == "__main__":
    main()
