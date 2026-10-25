# Live growing API run

Started: 2026-10-21T13:19:51.961725+04:00 (Asia/Dubai)

Target: `http://localhost:18001`

## Procedure

Observed a running API's growth, performed one deterministic two-user assessment, applied the supported operation-specific authorization policies, and independently reassessed. No repeating agent loop was started. Existing policies and scenario history were retained.

## Results

| Metric | Observed value |
|---|---|
| Collections at observation start / end | 16 / 16 |
| Endpoint/method pairs at observation start / end | 64 / 64 |
| New collections observed | 0 |
| Observed endpoint additions per minute | 0.00 |
| Before: vulnerable / defended / inconclusive | 8 / 8 / 0 |
| After: vulnerable / defended / inconclusive | 0 / 16 / 0 |
| Verified repairs still secure | 8 / 8 |
| Remediation rate | 100.0% |
| Defender applied / verified / failed / rolled back | 8 / 8 / 0 / 0 |
| Legitimate-operation preservation | 32 / 32 (100.0%) |
| Original vulnerabilities remaining / unresolved | 0 / 0 |
| New collections / vulnerabilities during agent execution | 0 / 0 |
| Previously defended collections that regressed | 0 |

## Results by template

| Type | Tested | Initially vulnerable | Verified repairs |
|---|---|---|---|
| B1 | 2 | 1 | 1 |
| B2 | 2 | 1 | 1 |
| B3 | 2 | 1 | 1 |
| B4 | 2 | 1 | 1 |
| B5 | 2 | 1 | 1 |
| B6 | 2 | 1 | 1 |
| B7 | 2 | 1 | 1 |
| V1 | 2 | 1 | 1 |

## Timings

| Phase | Seconds |
|---|---|
| growth_observation | 1.053 |
| assessment | 0.725 |
| defense_and_verification | 0.825 |
| independent_reassessment | 0.483 |

## Interpretation and limits

Remediation rate counts initially vulnerable collections that the defender verified and the independent reassessment still found secure, divided by initially vulnerable collections. Missing/inconclusive results are not repairs. Newly introduced collections are reported separately so ongoing growth cannot distort that denominator.

This validates supported B1–B7/V1 scenarios with fixed Alice/Bob/admin identities, not general LLM reasoning, all API vulnerability classes, or code-patch generation. Live precision/recall and introduction-to-detection latency are not claimed: this run does not read private ground truth. Timings are phase durations, not per-finding MTTR.

## Evidence

- [Metrics and observation snapshots](metrics.json)
- [Initial assessment](assessment-before.json)
- [Defender actions and verification](defender.json)
- [Independent reassessment](assessment-after.json)
