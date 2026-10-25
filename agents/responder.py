"""Defender responder: dry-run proposals or a verified lab policy remediation.

Legacy ownership and B1–B7/V1 adapters are executable. It reads no evaluator ground truth.
An advisory file lock serializes policy writers through verification/rollback.
"""
import copy
import fcntl
import time
from pathlib import Path

from core import state_store as store
from core.lab_checks import probe
from core.lab_policy import COLLECTION, read_policy, write_policy
from core.template_catalog import TEMPLATES


def settled_probe(client, name: str, *, expect_secure=False) -> dict:
    """Bounded verification window for bind-mount propagation, not an agent loop."""
    for attempt in range(8):
        result = probe(client, name)
        ready = result["verified_secure"] if expect_secure else result["verdict"] is not None
        if ready:
            return result
        if attempt < 7:
            time.sleep(.15)
    return result


def draft(plans: list[dict]) -> list[dict]:
    results = [{**plan, "execution": "dry_run", "applied": False,
                "verified": False, "blocked_by": "No remediation adapter implemented"}
               for plan in plans]
    store.log_event("responder", f"recorded {len(results)} dry-run proposals; no patches applied")
    return results


def apply_lab(plans: list[dict], client, policy_file: Path) -> list[dict]:
    results = []
    policy_file = Path(policy_file)
    policy_file.parent.mkdir(parents=True, exist_ok=True)
    for plan in plans:
        result = {**plan, "execution": "apply", "applied": False, "verified": False}
        name = plan.get("collection")
        supported = plan.get("module_id") == "lab-bola" or (plan.get("template") in TEMPLATES and plan.get("module_id") == f"lab-{plan['template']}")
        if not supported or not isinstance(name, str) or not COLLECTION.fullmatch(name):
            result.update(status="unsupported", blocked_by="No executable adapter for this finding")
            results.append(result)
            continue
        with policy_file.with_suffix(".lock").open("a") as lock:
            fcntl.flock(lock, fcntl.LOCK_EX)
            previous = None
            wrote = False
            try:
                before = settled_probe(client, name)
                result["before"] = before
                if before["verdict"] is None:
                    raise RuntimeError("Pre-remediation checks remained inconclusive")
                if before["verdict"] is not True:
                    result.update(status="not_reproduced", blocked_by="Fresh probe did not reproduce the finding")
                else:
                    previous = read_policy(policy_file)
                    policy = copy.deepcopy(previous)
                    template = before.get("template", "legacy")
                    if template != plan.get("template", "legacy") and not (template == "legacy" and plan.get("template") is None):
                        raise RuntimeError("Finding template does not match the live operation")
                    if template == "legacy":
                        policy["collections"][name] = True
                    else:
                        existing = policy["collections"].get(name, {})
                        if not isinstance(existing, dict):
                            raise ValueError("Legacy policy cannot be reused for a typed scenario")
                        policy["collections"][name] = {**existing, template: True}
                    write_policy(policy_file, policy)
                    wrote = True
                    result["applied"] = True
                    after = settled_probe(client, name, expect_secure=True)
                    result["after"] = after
                    if not after["verified_secure"]:
                        raise RuntimeError("Exploit replay or legitimate-user verification failed")
                    result.update(status="patched", verified=True)
                    store.mark_verified_patch(plan["finding_id"], result)
            except Exception as exc:
                result.update(status="failed", verified=False, error=str(exc))
                if wrote:
                    try:
                        write_policy(policy_file, previous)
                        result.update(applied=False, rolled_back=True)
                    except Exception as rollback_exc:
                        result.update(rolled_back=False, rollback_error=str(rollback_exc))
            finally:
                fcntl.flock(lock, fcntl.LOCK_UN)
        store.log_event("responder", f"{name}: {result['status']}", data=result)
        results.append(result)
    return results
