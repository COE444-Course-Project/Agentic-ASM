"""One defender pass: preview plans or explicitly apply and verify lab remediation."""
import argparse
import asyncio
import json
from pathlib import Path

from orchestrator import run_defender_round
from run_attacker import _guard_target


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--target", required=True, help="Exact target URL recorded by the attacker")
    parser.add_argument("--apply", action="store_true", help="Apply supported lab policies and verify")
    parser.add_argument("--policy-file", type=Path, help="Policy file mounted into the lab; required with --apply")
    args = parser.parse_args()
    if args.apply != (args.policy_file is not None):
        parser.error("Use --apply and --policy-file together")
    if args.apply:
        _guard_target(args.target, False)
    report = asyncio.run(run_defender_round(args.target.rstrip("/"), args.policy_file))
    print(json.dumps(report, indent=2))
    if any(p["status"] in ("failed", "unsupported") for p in report["plans"]):
        raise SystemExit(1)


if __name__ == "__main__":
    main()
