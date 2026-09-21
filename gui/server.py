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
import os
import sys
import threading
from pathlib import Path

from flask import Flask, Response, jsonify, request

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

import orchestrator  # noqa: E402
from core import state_store as store  # noqa: E402

app = Flask(__name__, static_folder=None)

# Same env vars run_attacker.py reads. Native default hits VAmPI's
# port-mapped localhost URL; the dockerized compose setup overrides these
# to the in-network service name (e.g. http://vampi-vulnerable:5000) so the
# page's default fields are correct without editing this file.
DEFAULT_TARGET = os.environ.get("TARGET", "http://localhost:5002")
DEFAULT_MODEL = os.environ.get("MODEL", "qwen2.5")

_run_lock = threading.Lock()
_running = {"active": False, "target": None, "model": None, "error": None}


def _run_round_in_background(target: str, model: str) -> bool:
    with _run_lock:
        if _running["active"]:
            return False
        _running.update(active=True, target=target, model=model, error=None)

    def _worker():
        try:
            asyncio.run(orchestrator.run_attacker_round(target, model))
        except Exception as exc:
            _running["error"] = str(exc)
        finally:
            with _run_lock:
                _running["active"] = False

    threading.Thread(target=_worker, daemon=True).start()
    return True


@app.get("/")
def index():
    html = (Path(__file__).parent / "static" / "index.html").read_text(encoding="utf-8")
    html = html.replace("__DEFAULT_TARGET__", DEFAULT_TARGET).replace("__DEFAULT_MODEL__", DEFAULT_MODEL)
    return Response(html, mimetype="text/html")


@app.get("/api/state")
def api_state():
    snap = store.snapshot()
    snap["running"] = dict(_running)
    return jsonify(snap)


@app.post("/api/run")
def api_run():
    body = request.get_json(silent=True) or {}
    target = body.get("target", DEFAULT_TARGET)
    model = body.get("model", DEFAULT_MODEL)
    if not _run_round_in_background(target, model):
        return jsonify({"ok": False, "error": "a round is already running"}), 409
    return jsonify({"ok": True, "target": target, "model": model})


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
