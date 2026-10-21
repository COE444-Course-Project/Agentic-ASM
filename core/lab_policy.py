"""Operational authorization policy, separate from evaluator ground truth."""
import json
from pathlib import Path
import re
import time

COLLECTION = re.compile(r"collection_[0-9]{4,}")


def read_policy(path: Path, *, allow_missing: bool = True) -> dict:
    # Docker Desktop bind mounts can briefly report ENOENT during host rename.
    # Once an API has seen a policy, missing files must not disable enforcement.
    for attempt in range(5):
        try:
            data = json.loads(path.read_text())
            break
        except FileNotFoundError:
            if allow_missing:
                return {"version": 1, "collections": {}}
            if attempt == 4:
                raise
        except (OSError, json.JSONDecodeError):
            if attempt == 4:
                raise
        time.sleep(.05)
    if (not isinstance(data, dict) or data.get("version") != 1
            or not isinstance(data.get("collections"), dict)
            or any(not COLLECTION.fullmatch(k) or v is not True
                   for k, v in data["collections"].items())):
        raise ValueError("Invalid lab policy")
    return data


def write_policy(path: Path, data: dict):
    """Atomic replacement; caller serializes writers with an advisory lock."""
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(".tmp")
    temporary.write_text(json.dumps(data, indent=2))
    temporary.replace(path)
