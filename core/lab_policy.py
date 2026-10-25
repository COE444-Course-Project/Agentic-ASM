"""Operational authorization policy, separate from evaluator ground truth."""
import json
from pathlib import Path
import re
import time
from core.template_catalog import TEMPLATES

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
            or any(not COLLECTION.fullmatch(k) or not (v is True or (
                       isinstance(v, dict) and all(t in TEMPLATES and enabled is True for t, enabled in v.items())))
                   for k, v in data["collections"].items())):
        raise ValueError("Invalid lab policy")
    return data


def write_policy(path: Path, data: dict):
    """Atomic replacement; caller serializes writers with an advisory lock."""
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(".tmp")
    temporary.write_text(json.dumps(data, indent=2))
    temporary.replace(path)


def is_patched(policy: dict, collection: str, template: str) -> bool:
    """True if `policy` (as returned by read_policy) currently enforces
    authorization for this collection/template -- the ground truth for
    "a defender patch is actually in effect", independent of any assessment
    history. `template` may be "legacy" for a pre-template-catalog finding,
    where a bare `True` entry (not a per-template dict) is the patch."""
    entry = policy.get("collections", {}).get(collection)
    if template == "legacy":
        return entry is True
    return isinstance(entry, dict) and entry.get(template) is True
