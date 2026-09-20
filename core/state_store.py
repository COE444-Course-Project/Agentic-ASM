"""
Shared persistent state for the attacker/defender agent loop.

This is the "Attack Surface" box from the proposal's architecture slide:
Scout writes discovered endpoints into it, Operator writes findings (the
slide's "Exploit" -> "Telemetry" arrow), the GUI reads it to show live
progress, and -- once a Defender agent exists -- it will read these same
findings as its telemetry feed and flip a finding's `status` from "open"
to "patched" here. That single shared file-store is what lets Planner
later skip or re-verify a patched finding on the next round without any
other module changing: Scout, Planner and Operator only ever talk to this
module, never directly to each other.

Everything is plain JSON on disk under STATE_DIR, so the GUI process and
any CLI/agent process share state without a database or a server between
them.
"""
from __future__ import annotations

import json
import threading
import time
from pathlib import Path
from typing import Any, Optional

STATE_DIR = Path(__file__).resolve().parent.parent / "state"
EVENTS_PATH = STATE_DIR / "events.jsonl"
FINDINGS_PATH = STATE_DIR / "findings.json"
SURFACE_PATH = STATE_DIR / "attack_surface.json"
ROUNDS_PATH = STATE_DIR / "rounds.json"

_lock = threading.Lock()


def _ensure_dir() -> None:
    STATE_DIR.mkdir(parents=True, exist_ok=True)


def _read_json(path: Path, default: Any) -> Any:
    if not path.exists():
        return default
    try:
        return json.loads(path.read_text())
    except Exception:
        return default


def _write_json(path: Path, data: Any) -> None:
    _ensure_dir()
    path.write_text(json.dumps(data, indent=2, default=str))


# --------------------------------------------------------------------- events

def log_event(source: str, message: str, round_id: Optional[int] = None,
               level: str = "info", data: Optional[dict] = None) -> None:
    """Append one line to the running telemetry log. `source` is one of
    'orchestrator' | 'scout' | 'planner' | 'operator' today, and will grow
    'watcher' | 'analyst' | 'responder' on the defender side later."""
    _ensure_dir()
    event = {
        "ts": time.time(),
        "round": round_id,
        "source": source,
        "level": level,
        "message": message,
        "data": data or {},
    }
    with _lock:
        with EVENTS_PATH.open("a") as f:
            f.write(json.dumps(event, default=str) + "\n")


def get_events(since_ts: float = 0.0, limit: int = 1000) -> list[dict]:
    if not EVENTS_PATH.exists():
        return []
    out = []
    with EVENTS_PATH.open() as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                ev = json.loads(line)
            except Exception:
                continue
            if ev.get("ts", 0) > since_ts:
                out.append(ev)
    return out[-limit:]


# ------------------------------------------------------------------ findings

def get_findings() -> dict:
    return _read_json(FINDINGS_PATH, {})


def upsert_finding(finding: dict, round_id: int) -> None:
    """`finding` must have an 'id'. `status` defaults to 'open' the first
    time a finding is seen -- a future Defender agent is the only thing
    expected to move it to 'patched'; Planner/Operator never write it."""
    with _lock:
        findings = _read_json(FINDINGS_PATH, {})
        fid = finding["id"]
        existing = findings.get(fid, {})
        merged = {
            **existing,
            **finding,
            "status": existing.get("status", "open"),
            "last_round": round_id,
            "updated_at": time.time(),
        }
        merged.setdefault("first_round", round_id)
        findings[fid] = merged
        _write_json(FINDINGS_PATH, findings)


# -------------------------------------------------------------- attack surface

def get_attack_surface() -> dict:
    return _read_json(SURFACE_PATH, {"target": None, "endpoints": [], "discovered_at": None})


def set_attack_surface(surface: dict) -> None:
    with _lock:
        _write_json(SURFACE_PATH, surface)


# ---------------------------------------------------------------------- rounds

def get_rounds() -> list[dict]:
    return _read_json(ROUNDS_PATH, [])


def start_round(target: str) -> int:
    with _lock:
        rounds = _read_json(ROUNDS_PATH, [])
        round_id = len(rounds) + 1
        rounds.append({
            "round": round_id, "target": target,
            "started_at": time.time(), "finished_at": None, "status": "running",
        })
        _write_json(ROUNDS_PATH, rounds)
    return round_id


def finish_round(round_id: int, summary: dict) -> None:
    with _lock:
        rounds = _read_json(ROUNDS_PATH, [])
        for r in rounds:
            if r["round"] == round_id:
                r["finished_at"] = time.time()
                r["status"] = "done"
                r.update(summary)
        _write_json(ROUNDS_PATH, rounds)


def snapshot() -> dict:
    """Everything the GUI needs in one call."""
    return {
        "attack_surface": get_attack_surface(),
        "findings": get_findings(),
        "rounds": get_rounds(),
        "events": get_events(),
    }


def reset_all() -> None:
    with _lock:
        for p in (EVENTS_PATH, FINDINGS_PATH, SURFACE_PATH, ROUNDS_PATH):
            if p.exists():
                p.unlink()
