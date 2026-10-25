"""Record one live growth observation, assessment, defense and reassessment.

No background agent loop. The target's existing growth timer remains untouched.
"""
import argparse
import asyncio
from datetime import datetime
import json
import math
from pathlib import Path
import time
from zoneinfo import ZoneInfo

import httpx

from agents import scout
from core.lab_checks import assess, PATH
from orchestrator import run_defender_round
from run_attacker import _guard_target


def snapshot(client):
    response = client.get("/openapi.json")
    response.raise_for_status()
    paths = response.json()["paths"]
    return {"observed_at": datetime.now(ZoneInfo("Asia/Dubai")).isoformat(),
            "collections": sorted(match[1] for path in paths if (match := PATH.fullmatch(path))),
            "endpoint_method_pairs": sum(method.lower() in {"get", "post", "put", "patch", "delete", "head", "options"}
                                         for methods in paths.values() for method in methods)}


def metrics(before, defense, after):
    original = {f["id"]: f for f in before["findings"]}
    final = {f["id"]: f for f in after["findings"]}
    vulnerable = {fid for fid, f in original.items() if f["verdict"] is True}
    verified = {p["finding_id"] for p in defense["plans"] if p.get("applied") and p.get("verified")}
    repaired = {fid for fid in vulnerable & verified if final.get(fid, {}).get("verdict") is False}
    owner_checks = [f.get("evidence", {}).get("checks", {}).get(key) is True
                    for f in final.values() for key in ("alice_owner_ok", "bob_owner_ok")]
    per_template = {}
    for template in sorted({f.get("template", "legacy") for f in original.values()}):
        ids = {fid for fid, f in original.items() if f.get("template", "legacy") == template}
        eligible = ids & vulnerable
        per_template[template] = {"tested": len(ids), "initially_vulnerable": len(eligible),
                                  "verified_repairs_still_secure": len(ids & repaired),
                                  "remediation_rate": len(ids & repaired) / len(eligible) if eligible else None}
    return {
        "per_template": per_template,
        "assessed_collections_before": len(original), "assessed_collections_after": len(final),
        "before": before["summary"], "after": after["summary"],
        "initially_vulnerable": len(vulnerable), "verified_repairs_still_secure": len(repaired),
        "remediation_rate": len(repaired) / len(vulnerable) if vulnerable else None,
        "defender_plans": len(defense["plans"]), "defender_applied": defense["applied"],
        "defender_verified": defense["verified"],
        "defender_failed": sum(p["status"] == "failed" for p in defense["plans"]),
        "defender_rolled_back": sum(p.get("rolled_back") is True for p in defense["plans"]),
        "original_vulnerabilities_remaining": sum(final.get(fid, {}).get("verdict") is True for fid in vulnerable),
        "original_vulnerabilities_unresolved": sum(fid not in final or final[fid]["verdict"] is None for fid in vulnerable),
        "new_collections_during_agents": len(final.keys() - original.keys()),
        "new_vulnerabilities_during_agents": sum(final[fid]["verdict"] is True for fid in final.keys() - original.keys()),
        "regressions": sum(f["verdict"] is False and final.get(fid, {}).get("verdict") is True for fid, f in original.items()),
        "owner_checks_passed": sum(owner_checks), "owner_checks_total": len(owner_checks),
        "owner_access_preservation_rate": sum(owner_checks) / len(owner_checks) if owner_checks else None,
    }


def write_summary(folder, data):
    m = data["metrics"]
    percent = lambda value: "N/A (no eligible cases)" if value is None else f"{value:.1%}"
    rows = {
        "Collections at observation start / end": f"{len(data['growth_before']['collections'])} / {len(data['growth_after']['collections'])}",
        "Endpoint/method pairs at observation start / end": f"{data['growth_before']['endpoint_method_pairs']} / {data['growth_after']['endpoint_method_pairs']}",
        "New collections observed": data["new_collections_observed"],
        "Observed endpoint additions per minute": f"{data['endpoint_additions_per_minute']:.2f}",
        "Before: vulnerable / defended / inconclusive": " / ".join(str(m["before"][key]) for key in ("vulnerable", "defended", "inconclusive")),
        "After: vulnerable / defended / inconclusive": " / ".join(str(m["after"][key]) for key in ("vulnerable", "defended", "inconclusive")),
        "Verified repairs still secure": f"{m['verified_repairs_still_secure']} / {m['initially_vulnerable']}",
        "Remediation rate": percent(m["remediation_rate"]),
        "Defender applied / verified / failed / rolled back": f"{m['defender_applied']} / {m['defender_verified']} / {m['defender_failed']} / {m['defender_rolled_back']}",
        "Legitimate-operation preservation": f"{m['owner_checks_passed']} / {m['owner_checks_total']} ({percent(m['owner_access_preservation_rate'])})",
        "Original vulnerabilities remaining / unresolved": f"{m['original_vulnerabilities_remaining']} / {m['original_vulnerabilities_unresolved']}",
        "New collections / vulnerabilities during agent execution": f"{m['new_collections_during_agents']} / {m['new_vulnerabilities_during_agents']}",
        "Previously defended collections that regressed": m["regressions"],
    }
    lines = ["# Live growing API run", "", f"Started: {data['started_at']} (Asia/Dubai)", "",
             f"Target: `{data['target']}`", "", "## Procedure", "",
             "Observed a running API's growth, performed one deterministic two-user assessment, "
             "applied the supported operation-specific authorization policies, and independently reassessed. No repeating "
             "agent loop was started. Existing policies and scenario history were retained.", "",
             "## Results", "", "| Metric | Observed value |", "|---|---|"]
    lines.extend(f"| {name} | {value} |" for name, value in rows.items())
    lines.extend(["", "## Results by template", "", "| Type | Tested | Initially vulnerable | Verified repairs |", "|---|---|---|---|"])
    lines.extend(f"| {template} | {row['tested']} | {row['initially_vulnerable']} | {row['verified_repairs_still_secure']} |" for template, row in m["per_template"].items())
    lines.extend(["", "## Timings", "", "| Phase | Seconds |", "|---|---|"])
    lines.extend(f"| {name} | {seconds:.3f} |" for name, seconds in data["durations_seconds"].items())
    lines.extend(["", "## Interpretation and limits", "",
                  "Remediation rate counts initially vulnerable collections that the defender verified "
                  "and the independent reassessment still found secure, divided by initially vulnerable "
                  "collections. Missing/inconclusive results are not repairs. Newly introduced collections "
                  "are reported separately so ongoing growth cannot distort that denominator.", "",
                  "This validates supported B1–B7/V1 scenarios with fixed Alice/Bob/admin identities, "
                  "not general LLM reasoning, all API vulnerability classes, or code-patch generation. "
                  "Live precision/recall and introduction-to-detection latency are not claimed: this run "
                  "does not read private ground truth. Timings are phase durations, not per-finding MTTR.", "",
                  "## Evidence", "",
                  "- [Metrics and observation snapshots](metrics.json)",
                  "- [Initial assessment](assessment-before.json)",
                  "- [Defender actions and verification](defender.json)",
                  "- [Independent reassessment](assessment-after.json)", ""])
    (folder / "SUMMARY.md").write_text("\n".join(lines))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--target", default="http://localhost:8000")
    parser.add_argument("--observe-seconds", type=float, default=25)
    parser.add_argument("--apply", action="store_true", required=True, help="Explicitly authorize one defender pass")
    parser.add_argument("--policy-file", type=Path, required=True)
    parser.add_argument("--output-dir", type=Path)
    args = parser.parse_args()
    if not math.isfinite(args.observe_seconds) or not 0 < args.observe_seconds <= 60:
        parser.error("--observe-seconds must be greater than 0 and at most 60")
    _guard_target(args.target, False)
    started = datetime.now(ZoneInfo("Asia/Dubai"))
    folder = args.output_dir or Path("runs") / started.strftime("%Y-%m-%d_%H-%M-%S")
    folder.mkdir(parents=True, exist_ok=False)
    save = lambda name, value: (folder / name).write_text(json.dumps(value, indent=2))
    data = {"started_at": started.isoformat(), "target": args.target.rstrip("/"), "durations_seconds": {}}
    print(f"Recording one live run in {folder}; observing growth for {args.observe_seconds}s", flush=True)
    try:
        with httpx.Client(base_url=data["target"], timeout=10) as client:
            start = time.monotonic()
            data["growth_before"] = snapshot(client)
            time.sleep(args.observe_seconds)
            data["growth_after"] = snapshot(client)
            elapsed = time.monotonic() - start
            data["durations_seconds"]["growth_observation"] = elapsed
            data["new_collections_observed"] = len(set(data["growth_after"]["collections"]) - set(data["growth_before"]["collections"]))
            data["endpoint_additions_per_minute"] = (data["growth_after"]["endpoint_method_pairs"] - data["growth_before"]["endpoint_method_pairs"]) / elapsed * 60
            save("observations.json", data)
            start = time.monotonic()
            before = assess(client, data["target"])
            data["durations_seconds"]["assessment"] = time.monotonic() - start
            save("assessment-before.json", before)
            start = time.monotonic()
            defense = asyncio.run(run_defender_round(data["target"], args.policy_file, client))
            data["durations_seconds"]["defense_and_verification"] = time.monotonic() - start
            save("defender.json", defense)
            start = time.monotonic()
            after = assess(client, data["target"])
            data["durations_seconds"]["independent_reassessment"] = time.monotonic() - start
            save("assessment-after.json", after)
            data["metrics"] = metrics(before, defense, after)
            save("metrics.json", data)
            write_summary(folder, data)
            scout.run(data["target"], None)
    except Exception as exc:
        save("error.json", {"error": str(exc), "type": type(exc).__name__})
        raise
    print(json.dumps({"folder": str(folder), "metrics": data["metrics"]}, indent=2))


if __name__ == "__main__":
    main()
