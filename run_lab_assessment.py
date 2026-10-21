"""Run one deterministic two-user assessment of the growing lab; no loop."""
import argparse
import json

import httpx

from core.lab_checks import assess
from run_attacker import _guard_target


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--target", default="http://localhost:8000")
    args = parser.parse_args()
    _guard_target(args.target, False)
    with httpx.Client(base_url=args.target.rstrip("/"), timeout=10) as client:
        print(json.dumps(assess(client, args.target), indent=2))


if __name__ == "__main__":
    main()
