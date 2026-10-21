"""Defender intake: select reported vulnerabilities for one explicit target."""
from core import state_store as store


def observe(target: str) -> list[dict]:
    target = target.rstrip("/")
    findings = [f for f in store.get_findings().values()
                if f.get("target", "").rstrip("/") == target
                and f.get("verdict") is True and f.get("status", "open") == "open"]
    store.log_event("watcher", f"selected {len(findings)} open findings for {target}")
    return findings
