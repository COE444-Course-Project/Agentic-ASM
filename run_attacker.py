"""
CLI entry point for the attacker agent (Scout -> Planner -> Operator, via
orchestrator.run_attacker_round). Supersedes the standalone attack_agent.py
script -- same modules and checks, now split along the proposal's
Scout/Planner/Operator/Orchestrator architecture so a Defender agent and a
real attacker<->defender loop can be added later without touching this
file's structure.

Usage:
    .venv/bin/python3 run_attacker.py --target http://localhost:5002
    .venv/bin/python3 run_attacker.py --target http://localhost:5002 --rounds 3
    .venv/bin/python3 run_attacker.py --target http://localhost:5002 --skip-llm

Then browse the results live: .venv/bin/python3 gui/server.py
"""
from __future__ import annotations

import argparse
import asyncio
import os
import sys
from urllib.parse import urlparse

import httpx

import orchestrator
from agents import operator
from core import state_store as store

DEFAULT_MODEL = os.environ.get("MODEL", "qwen2.5")
# In the dockerized compose setup TARGET defaults to the VAmPI service name
# on the shared network (e.g. http://vampi-vulnerable:5000); running
# natively it defaults to the port-mapped localhost URL.
DEFAULT_TARGET = os.environ.get("TARGET", "http://localhost:5002")



# Hostnames that are always our own sandbox, whether we're running natively
# (VAmPI reached via localhost's mapped ports) or inside the docker-compose
# network in this repo (VAmPI reached by its compose service name -- see
# docker-compose.yml). Anything else needs --i-own-this-target.
SAFE_HOSTS = ("localhost", "127.0.0.1", "vampi-secure", "vampi-vulnerable", "growing-api")


def _guard_target(base: str, force: bool) -> None:
    host = urlparse(base).hostname or ""
    if host not in SAFE_HOSTS and not force:
        sys.exit(
            f"Refusing to attack '{base}': host '{host}' is not a recognized sandbox host.\n"
            "This script sends real exploit payloads (SQL injection, privilege escalation, "
            "account takeover). Only point it at a system you own or are explicitly authorized "
            "to test, then re-run with --i-own-this-target to confirm."
        )


def _print_round(result: dict) -> None:
    print(f"\n=== Round {result['round']} summary ===")
    for f in result["findings"]:
        icon = {True: "[!!]", False: "[ok]", None: "[??]"}[f["verdict"]]
        label = {True: "VULNERABLE", False: "defended", None: "inconclusive"}[f["verdict"]]
        print(f"{icon} {label:12s} {f['owasp']:45s} {f['title']}")


async def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--target", default=DEFAULT_TARGET, help="Base URL of the VAmPI instance to attack (default: %(default)s)")
    ap.add_argument("--model", default=DEFAULT_MODEL, help="Ollama model for the LLM-driven modules (default: %(default)s)")
    ap.add_argument("--rounds", type=int, default=1, help="Attacker-only rounds to run back to back. Without a defender yet, later rounds re-run against the same, still-unpatched surface -- this exercises the round-loop machinery ahead of M6.")
    ap.add_argument("--skip-llm", action="store_true", help="Run only the deterministic modules (no LLM, no Ollama needed)")
    ap.add_argument("--no-reset", action="store_true", help="Don't reset the target's DB via /createdb before starting")
    ap.add_argument("--fresh-state", action="store_true", help="Wipe state/ (events, findings, rounds) before starting")
    ap.add_argument("--i-own-this-target", action="store_true", help="Confirm you are authorized to attack a non-localhost target")
    args = ap.parse_args()

    base = args.target.rstrip("/")
    _guard_target(base, args.i_own_this_target)

    if args.fresh_state:
        store.reset_all()

    if args.skip_llm:
        operator.MODULES = [m for m in operator.MODULES if m["kind"] == "deterministic"]

    from core.vampi_setup import prepare_vampi
    for i in range(args.rounds):
        prepare_vampi(base, reset=not args.no_reset)
        print(f"\n--- attacker round {i + 1}/{args.rounds} ---")
        result = await orchestrator.run_attacker_round(base, args.model)
        _print_round(result)

    print("\nLive dashboard: .venv/bin/python3 gui/server.py   (reads the same state/ this run just wrote)")


if __name__ == "__main__":
    asyncio.run(main())
