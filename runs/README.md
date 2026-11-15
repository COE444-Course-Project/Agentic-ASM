# Recorded live runs

Each directory contains a Markdown summary, metric definitions/results, and raw
HTTP assessment and defender evidence. Directory timestamps use Asia/Dubai time.
These are live runs against the Docker API, distinct from the isolated harness
reports under `reports/`. Existing scenarios and policies are retained between
runs; these are not necessarily fresh-baseline experiments.

| Run | Remediation rate | Remaining exposure at reassessment |
|---|---|---|
| [2026-10-21 12:38:52](2026-10-21_12-38-52/SUMMARY.md) | 56/56 (100%) | One newly introduced vulnerable collection |
| [2026-11-15 09:31:04 closed loop, 5 rounds](2026-11-15_09-31-04_loop/SUMMARY.md) | 19/19 (100%), incl. 4/4 drift regressions | None after the last round |

Record another run from the repository root:

```bash
.venv/bin/python run_live.py --target http://localhost:8000 \
  --observe-seconds 25 --apply --policy-file lab-policy/policy.json
```

This performs a single sequence and leaves the target's growth timer unchanged. For repeated rounds:

```bash
.venv/bin/python run_loop.py --rounds 5 --grow 5 --drift 1 --seed 444
```
See the main README for Docker startup, individual agent commands, and metrics.
