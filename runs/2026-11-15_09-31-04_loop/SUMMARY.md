# Closed attacker-defender loop

Started: 2026-11-15T09:31:04+04:00 (Asia/Dubai) · Target: `http://localhost:8000` · Status: **done**

Configuration: 5 round(s), +5 scenario(s) per round, drift 1 patch(es) per round, LLM sample 0, seed 444.

Each round: the API grows (and optionally drifts) at a round boundary, Scout rediscovers the surface, the attacker assesses every collection, the defender applies and verifies supported authorization policies (rolling back on failure), and an independent reassessment confirms the result.

## Totals

| Metric | Value |
|---|---|
| Rounds completed | 5 |
| Collections after last round | 25 |
| Vulnerabilities detected (all rounds, incl. regressions) | 19 |
| Verified repairs still secure on reassessment | 19 |
| Remediation rate | 100.0% |
| New exposure (vulnerable on first appearance) | 15 |
| Regressions detected / repaired | 4 / 4 |
| Defender failures / rollbacks | 0 / 0 |
| Legitimate-operation preservation | 150 / 150 (100.0%) |
| Open / inconclusive after last round | 0 / 0 |

## Per round

| Round | Collections | New | New exposure | Regressions | Found | Verified fixed | Open after | Legit checks | Seconds |
|---|---|---|---|---|---|---|---|---|---|
| 1 | 5 | 5 | 3 | 0 | 3 | 3 | 0 | 10/10 | 0.61 |
| 2 | 10 | 5 | 4 | 1 | 5 | 5 | 0 | 20/20 | 1.06 |
| 3 | 15 | 5 | 2 | 1 | 3 | 3 | 0 | 30/30 | 1.09 |
| 4 | 20 | 5 | 4 | 1 | 5 | 5 | 0 | 40/40 | 1.45 |
| 5 | 25 | 5 | 2 | 1 | 3 | 3 | 0 | 50/50 | 1.45 |

## Phase durations (seconds)

| Round | grow | discover | attack | defend | verify |
|---|---|---|---|---|---|
| 1 | 0.015 | 0.010 | 0.093 | 0.334 | 0.160 |
| 2 | 0.013 | 0.016 | 0.210 | 0.554 | 0.263 |
| 3 | 0.009 | 0.016 | 0.313 | 0.396 | 0.359 |
| 4 | 0.008 | 0.018 | 0.367 | 0.591 | 0.469 |
| 5 | 0.008 | 0.021 | 0.489 | 0.403 | 0.529 |

## Interpretation and limits

Remediation rate counts findings the defender verified and the independent reassessment still found secure, divided by all vulnerabilities detected across rounds (a regression counts again when it reappears). New exposure is reported separately from regressions. Drift is a simulated configuration rollback of verified patches, used to show the loop catches and re-repairs regressions.

Scope: supported B1–B7/V1 authorization scenarios with fixed Alice/Bob/admin identities and predefined policy repairs. This is not general vulnerability discovery or source-code patch generation, and live runs do not read private ground truth (no precision/recall claimed here; see `run_harness.py`).
