"""Remediation metrics shared by single-pass live runs and the closed loop."""


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


def write_loop_report(folder, result: dict) -> None:
    """Persist a closed-loop run: metrics.json, per-round raw evidence, SUMMARY.md."""
    import json
    from datetime import datetime
    from pathlib import Path
    from zoneinfo import ZoneInfo

    folder = Path(folder)
    folder.mkdir(parents=True, exist_ok=True)
    dump = lambda name, value: (folder / name).write_text(json.dumps(value, indent=2, default=str))
    loop = {k: v for k, v in result.items() if k != "evidence"}
    dump("metrics.json", loop)
    for number, files in result.get("evidence", {}).items():
        for name, value in files.items():
            dump(f"round-{number}-{name}.json", value)

    t = loop["totals"] or {}
    pct = lambda v: "N/A (no eligible cases)" if v is None else f"{v:.1%}"
    started = datetime.fromtimestamp(loop["started_at"], ZoneInfo("Asia/Dubai")).isoformat(timespec="seconds")
    c = loop["config"]
    lines = ["# Closed attacker-defender loop", "",
             f"Started: {started} (Asia/Dubai) · Target: `{loop['target']}` · Status: **{loop['status']}**", "",
             f"Configuration: {c['rounds']} round(s), +{c['grow_per_round']} scenario(s) per round, "
             f"drift {c['drift']} patch(es) per round, LLM sample {c['llm_sample']}, seed {c['seed']}.", "",
             "Each round: the API grows (and optionally drifts) at a round boundary, Scout rediscovers the "
             "surface, the attacker assesses every collection, the defender applies and verifies supported "
             "authorization policies (rolling back on failure), and an independent reassessment confirms the result.", "",
             "## Totals", "", "| Metric | Value |", "|---|---|",
             f"| Rounds completed | {t.get('rounds_completed', 0)} |",
             f"| Collections after last round | {t.get('collections_final', 0)} |",
             f"| Vulnerabilities detected (all rounds, incl. regressions) | {t.get('vulnerabilities_detected', 0)} |",
             f"| Verified repairs still secure on reassessment | {t.get('verified_repairs', 0)} |",
             f"| Remediation rate | {pct(t.get('remediation_rate'))} |",
             f"| New exposure (vulnerable on first appearance) | {t.get('new_exposure', 0)} |",
             f"| Regressions detected / repaired | {t.get('regressions_detected', 0)} / {t.get('regressions_repaired', 0)} |",
             f"| Defender failures / rollbacks | {t.get('defender_failed', 0)} / {t.get('defender_rolled_back', 0)} |",
             f"| Legitimate-operation preservation | {t.get('legit_checks_passed', 0)} / {t.get('legit_checks_total', 0)} ({pct(t.get('legit_preservation_rate'))}) |",
             f"| Open / inconclusive after last round | {t.get('open_after_last_round')} / {t.get('inconclusive_after_last_round')} |",
             "", "## Per round", "",
             "| Round | Collections | New | New exposure | Regressions | Found | Verified fixed | Open after | Legit checks | Seconds |",
             "|---|---|---|---|---|---|---|---|---|---|"]
    for r in loop["rounds"]:
        m = r.get("metrics")
        if not m:
            lines.append(f"| {r['round']} | stopped before completion | | | | | | | | |")
            continue
        lines.append(f"| {r['round']} | {r['surface']['collections']} | {len(r['new_collections'])} | {len(r['new_exposure'])} | "
                     f"{len(r['regressions'])} | {m['initially_vulnerable']} | {m['verified_repairs_still_secure']} | "
                     f"{m['after']['vulnerable']} | {m['owner_checks_passed']}/{m['owner_checks_total']} | {sum(r['durations'].values()):.2f} |")
    lines += ["", "## Phase durations (seconds)", "", "| Round | " + " | ".join(("grow", "discover", "attack", "defend", "verify")) + " |",
              "|---|---|---|---|---|---|"]
    for r in loop["rounds"]:
        lines.append(f"| {r['round']} | " + " | ".join(f"{r['durations'].get(p, 0):.3f}" for p in ("grow", "discover", "attack", "defend", "verify")) + " |")
    lines += ["", "## Interpretation and limits", "",
              "Remediation rate counts findings the defender verified and the independent reassessment still found "
              "secure, divided by all vulnerabilities detected across rounds (a regression counts again when it "
              "reappears). New exposure is reported separately from regressions. Drift is a simulated configuration "
              "rollback of verified patches, used to show the loop catches and re-repairs regressions.", "",
              "Scope: supported B1–B7/V1 authorization scenarios with fixed Alice/Bob/admin identities and predefined "
              "policy repairs. This is not general vulnerability discovery or source-code patch generation, and live "
              "runs do not read private ground truth (no precision/recall claimed here; see `run_harness.py`).", ""]
    (folder / "SUMMARY.md").write_text("\n".join(lines))
