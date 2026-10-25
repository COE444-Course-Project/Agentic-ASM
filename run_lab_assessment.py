"""Run one deterministic two-user assessment of the growing lab; no loop."""
import argparse
import json
from pathlib import Path

import httpx

from core.lab_checks import assess
from run_attacker import _guard_target


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--target", default="http://localhost:8000")
    parser.add_argument("--policy-file", type=Path, default=None,
                         help="lab-policy/policy.json from a prior run_defender.py --apply; "
                              "when given, the summary's 'patched' count reflects it even if "
                              "this is a fresh process with no prior assessment history.")
    args = parser.parse_args()
    _guard_target(args.target, False)
    policy_file = args.policy_file if args.policy_file and args.policy_file.exists() else None
    with httpx.Client(base_url=args.target.rstrip("/"), timeout=10) as client:
        print(json.dumps(assess(client, args.target, policy_file=policy_file), indent=2))


if __name__ == "__main__":
    main()
