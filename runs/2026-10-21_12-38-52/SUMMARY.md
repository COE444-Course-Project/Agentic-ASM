# Live growing API run

Started: 2026-10-21T12:38:52.315460+04:00 (Asia/Dubai)

Target: `http://localhost:8000`

## Procedure

Observed a running API's growth, performed one deterministic two-user assessment, applied the supported ownership policies, and independently reassessed. No repeating agent loop was started. Existing policies and scenario history were retained.

## Results

| Metric | Observed value |
|---|---|
| Collections at observation start / end | 138 / 141 |
| Endpoint/method pairs at observation start / end | 278 / 284 |
| New collections observed | 3 |
| Observed endpoint additions per minute | 14.29 |
| Before: vulnerable / defended / inconclusive | 56 / 85 / 0 |
| After: vulnerable / defended / inconclusive | 1 / 141 / 0 |
| Verified repairs still secure | 56 / 56 |
| Remediation rate | 100.0% |
| Defender applied / verified / failed / rolled back | 56 / 56 / 0 / 0 |
| Owner access preservation | 284 / 284 (100.0%) |
| Original vulnerabilities remaining / unresolved | 0 / 0 |
| New collections / vulnerabilities during agent execution | 1 / 1 |
| Previously defended collections that regressed | 0 |

## Timings

| Phase | Seconds |
|---|---|
| growth_observation | 25.190 |
| assessment | 3.734 |
| defense_and_verification | 6.516 |
| independent_reassessment | 3.459 |

## Findings

The surface grew from 138 to 141 collections during the 25.19-second observation.
The initial assessment found 56 vulnerable and 85 defended collections. The
defender verified all 56 repairs, with no failed patches or rollbacks. Independent
reassessment confirmed all 56 remained secure and all 284 legitimate-owner checks
passed. One new vulnerable collection (`collection_0142`) appeared during agent execution.
It was not part of the initial remediation set, so it is remaining new exposure,
not a failed repair. Growth remains enabled; this report is a time-bounded snapshot.

## Interpretation and limits

Remediation rate counts initially vulnerable collections that the defender verified and the independent reassessment still found secure, divided by initially vulnerable collections. Missing/inconclusive results are not repairs. Newly introduced collections are reported separately so ongoing growth cannot distort that denominator.

This validates a known object-ownership template with fixed Alice/Bob identities, not general LLM reasoning, all API vulnerability classes, or code-patch generation. Live precision/recall and introduction-to-detection latency are not claimed: this run does not read private ground truth. Timings are phase durations, not per-finding MTTR.

## Evidence

- [Metrics and observation snapshots](metrics.json)
- [Initial assessment](assessment-before.json)
- [Defender actions and verification](defender.json)
- [Independent reassessment](assessment-after.json)
