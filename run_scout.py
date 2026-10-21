"""Watch OpenAPI discovery without running VAmPI-specific attack modules."""
import argparse
import time

from agents import scout


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--target", default="http://localhost:8000")
    parser.add_argument("--interval", type=float, default=5, help="Seconds between scans; 0 runs once")
    args = parser.parse_args()
    if args.interval < 0:
        parser.error("--interval must be >= 0")
    try:
        while True:
            surface = scout.run(args.target.rstrip("/"), None)
            print(f"Discovered {len(surface['endpoints'])} endpoint/method pairs", flush=True)
            if not args.interval:
                return
            time.sleep(args.interval)
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
