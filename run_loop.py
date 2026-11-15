"""Run the bounded closed attacker-defender loop against the custom API lab.

Each round grows the API, rediscovers it, attacks every collection, applies
and verifies supported repairs, then independently reassesses. Results are
saved to runs/<timestamp>_loop/ and shown live in the dashboard.
"""
import argparse
import asyncio
from datetime import datetime
import json
from pathlib import Path
from zoneinfo import ZoneInfo

import httpx

from core.metrics import write_loop_report
from orchestrator import run_closed_loop
from run_attacker import _guard_target


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--target", default="http://localhost:8000")
    parser.add_argument("--policy-file", type=Path, default=Path("lab-policy/policy.json"))
    parser.add_argument("--rounds", type=int, default=3)
    parser.add_argument("--grow", type=int, default=3, help="Scenarios added at the start of each round")
    parser.add_argument("--drift", type=int, default=0, help="Verified patches reverted at each later round boundary")
    parser.add_argument("--llm-sample", type=int, default=0)
    parser.add_argument("--model", default="qwen2.5")
    parser.add_argument("--seed", type=int, default=444)
    parser.add_argument("--output-dir", type=Path)
    args = parser.parse_args()
    if not 1 <= args.rounds <= 20 or not 0 <= args.grow <= 50 or not 0 <= args.drift <= 20 or not 0 <= args.llm_sample <= 50:
        parser.error("rounds 1-20, grow 0-50, drift 0-20, llm-sample 0-50")
    _guard_target(args.target, False)
    folder = args.output_dir or Path("runs") / (datetime.now(ZoneInfo("Asia/Dubai")).strftime("%Y-%m-%d_%H-%M-%S") + "_loop")
    with httpx.Client(base_url=args.target.rstrip("/"), timeout=30) as client:
        result = asyncio.run(run_closed_loop(args.target, args.policy_file, client, rounds=args.rounds,
                                             grow_per_round=args.grow, drift=args.drift, llm_sample=args.llm_sample,
                                             model=args.model, seed=args.seed))
    write_loop_report(folder, result)
    print(json.dumps({"folder": str(folder), "status": result["status"], "totals": result["totals"]}, indent=2))


if __name__ == "__main__":
    main()
