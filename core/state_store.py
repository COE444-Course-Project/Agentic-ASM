"""
Shared persistent state for separate attacker and defender passes.

This is the "Attack Surface" box from the proposal's architecture slide:
Scout writes discovered endpoints into it, Operator writes findings (the
slide's "Exploit" -> "Telemetry" arrow), the GUI reads it to show live
progress. The defender consumes target-scoped findings and closes them
only after remediation verification. This shared file-store lets Planner
later skip or re-verify a patched finding on the next round without any
other module changing: Scout, Planner and Operator only ever talk to this
module, never directly to each other.

Everything is plain JSON on disk under STATE_DIR, so the GUI process and
any CLI/agent process share state without a database or a server between
them.
"""
from __future__ import annotations

import json
import os
import threading
import time
from pathlib import Path
from typing import Any, Optional

STATE_DIR = Path(os.environ.get("ASM_STATE_DIR", str(Path(__file__).resolve().parent.parent / "state")))
EVENTS_PATH = STATE_DIR / "events.jsonl"
FINDINGS_PATH = STATE_DIR / "findings.json"
SURFACE_PATH = STATE_DIR / "attack_surface.json"
ROUNDS_PATH = STATE_DIR / "rounds.json"
DEFENDER_PATH = STATE_DIR / "defender_plans.json"
LOOP_PATH = STATE_DIR / "loop.json"

_lock = threading.Lock()


def configure(state_dir: Path) -> None:
    """Select output storage at CLI startup only, before any worker starts."""
    global STATE_DIR, EVENTS_PATH, FINDINGS_PATH, SURFACE_PATH, ROUNDS_PATH, DEFENDER_PATH, LOOP_PATH
    STATE_DIR = Path(state_dir)
    EVENTS_PATH = STATE_DIR / "events.jsonl"
    FINDINGS_PATH = STATE_DIR / "findings.json"
    SURFACE_PATH = STATE_DIR / "attack_surface.json"
    ROUNDS_PATH = STATE_DIR / "rounds.json"
    DEFENDER_PATH = STATE_DIR / "defender_plans.json"
    LOOP_PATH = STATE_DIR / "loop.json"


def mark_verified_patch(fid: str, evidence: dict) -> None:
    if evidence.get("applied") is not True or evidence.get("verified") is not True:
        raise ValueError("Patch closure requires application and verification evidence")
    with _lock:
        findings = get_findings()
        findings[fid].update(status="patched", verdict=False,
                             detection_evidence=findings[fid].get("evidence"),
                             evidence=evidence.get("after"), remediation=evidence, updated_at=time.time())
        _write_json(FINDINGS_PATH, findings)


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
    # Atomic so the dashboard's frequent polling never reads a half-written file.
    _ensure_dir()
    temporary = path.with_name(f".{path.name}.{os.getpid()}.{threading.get_ident()}.tmp")
    temporary.write_text(json.dumps(data, indent=2, default=str))
    temporary.replace(path)


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


def finding_id(target: str, module_id: str) -> str:
    """Separate targets; adapters may include an endpoint identity in module_id."""
    return f"{target.rstrip('/')}::{module_id}"


def save_defender_report(report: dict) -> None:
    with _lock:
        reports = _read_json(DEFENDER_PATH, [])
        reports.append({**report, "created_at": time.time()})
        _write_json(DEFENDER_PATH, reports)


def upsert_finding(finding: dict, round_id: int, *, policy_patched: bool = False) -> dict:
    """`finding` must have an 'id'. `status` defaults to 'open' the first
    time a finding is seen. Positive reassessment reopens a previous patch;
    only mark_verified_patch can close it with remediation evidence. Returns
    the merged record so a caller can tell a fresh "never vulnerable" verdict
    apart from one that is secure because of a verified prior patch (its
    `status` stays "patched" here; see "patched" vs "defended" in round
    summaries below).

    `policy_patched`, when the caller already confirmed the live lab policy
    file covers this finding's collection/template, forces `status` to
    "patched" even if this process has no prior record of it -- findings.json
    is only *this dashboard's own* history and can be cleared independently
    of the policy file (e.g. the dashboard's "Reset state" button), so without
    this a patch that happened before a reset would wrongly look like it was
    never applied."""
    with _lock:
        findings = _read_json(FINDINGS_PATH, {})
        fid = finding["id"]
        existing = findings.get(fid, {})
        merged = {
            **existing,
            **finding,
            "status": ("open" if finding.get("verdict") is True
                       else "patched" if policy_patched
                       else existing.get("status", "open")),
            "last_round": round_id,
            "updated_at": time.time(),
        }
        merged.setdefault("first_round", round_id)
        findings[fid] = merged
        _write_json(FINDINGS_PATH, findings)
        return merged


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


def finish_round(round_id: int, summary: dict, status: str = "done") -> None:
    with _lock:
        rounds = _read_json(ROUNDS_PATH, [])
        for r in rounds:
            if r["round"] == round_id:
                r["finished_at"] = time.time()
                r["status"] = status
                r.update(summary)
        _write_json(ROUNDS_PATH, rounds)


def update_round(round_id: int, **fields) -> None:
    """Merge extra fields into an already-finished round without touching
    `finished_at`/`status`. Used for work that continues after the
    deterministic pass finish_round()s the round -- the custom lab's
    optional LLM-sampled cross-check -- so the dashboard can show that
    it's still running instead of the round looking instantly, silently
    "done" while real LLM calls are still in flight."""
    with _lock:
        rounds = _read_json(ROUNDS_PATH, [])
        for r in rounds:
            if r["round"] == round_id:
                r.update(fields)
        _write_json(ROUNDS_PATH, rounds)


# ------------------------------------------------------------- closed loop

def get_loop() -> Optional[dict]:
    return _read_json(LOOP_PATH, None)


def set_loop(loop: dict) -> None:
    """The most recent closed-loop run: config, live phase, per-round results."""
    with _lock:
        _write_json(LOOP_PATH, loop)


def snapshot() -> dict:
    """Everything the GUI needs in one call."""
    return {
        "attack_surface": get_attack_surface(),
        "findings": get_findings(),
        "rounds": get_rounds(),
        "events": get_events(),
        "defender_plans": _read_json(DEFENDER_PATH, []),
        "loop": get_loop(),
    }


def reset_all() -> None:
    with _lock:
        for p in (EVENTS_PATH, FINDINGS_PATH, SURFACE_PATH, ROUNDS_PATH, DEFENDER_PATH, LOOP_PATH):
            if p.exists():
                p.unlink()
