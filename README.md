# Agentic ASM — evolving API lab and attacker assessment

The primary experiment is now a **growing FastAPI attack surface**. VAmPI
remains the fixed external benchmark for regression testing. The LLM attacker remains VAmPI-specific; the growing lab has its own
deterministic ownership-assessment adapter. The defender supports preview mode and explicit, verified remediation of the
lab ownership vulnerability. There is no automatic attacker–defender loop.

## Run growth, assessment, defense, and metrics

These commands run the **live Docker lab**, using real HTTP requests. The lab
attacker is a deterministic two-user ownership assessment; it does not invoke
Ollama. The separate VAmPI pipeline still provides the LLM-driven benchmark.

1. Open Docker Desktop, then prepare the project:

   ```bash
   cd /Users/wbk/Documents/GitHub/Agentic-ASM
   python3 -m venv .venv  # only if the virtual environment does not exist
   .venv/bin/python -m pip install -r requirements.txt -r lab/requirements.txt
   mkdir -p lab-policy
   ```

2. Start or resume growth and the dashboard:

   ```bash
   LAB_GROWTH_SECONDS=10 LAB_MAX_COLLECTIONS=0 docker compose -f compose.lab.yml up -d --build
   docker compose up -d --build --no-deps agent
   ```

   Open http://localhost:8000/docs for API documentation and
   http://localhost:8765 for findings and logs. Existing collections and patches
   are retained. The lab adds one collection (two endpoint/method pairs) every
   ten seconds, with no configured collection limit. Refresh Swagger to see new
   routes. Do not remove “orphan” containers: the two Compose files intentionally
   manage different services under the same project.

3. Record one complete live experiment:

   ```bash
   .venv/bin/python run_live.py --target http://localhost:8000 \
     --observe-seconds 25 --apply --policy-file lab-policy/policy.json
   ```

   This observes growth for 25 seconds, performs one assessment, runs one
   defender pass, and independently reassesses. It saves a timestamped folder
   under `runs/` (Asia/Dubai time), including `SUMMARY.md`, `metrics.json`, and
   raw assessment/defender evidence. It also writes the usual dashboard state.
   It exits after this sequence; it does not start an unattended agent loop.
   Run only one assessment/defender writer at a time and stop any scout watcher
   before starting this command. Growth continues during and after the experiment.

4. Alternatively, run the stages individually:

   ```bash
   .venv/bin/python run_lab_assessment.py --target http://localhost:8000
   .venv/bin/python run_defender.py --target http://localhost:8000
   .venv/bin/python run_defender.py --target http://localhost:8000 \
     --apply --policy-file lab-policy/policy.json
   .venv/bin/python run_lab_assessment.py --target http://localhost:8000
   ```

   The second command previews proposals. The third applies supported policies
   and verifies them. These individual commands save shared state, but only
   `run_live.py` creates the consolidated run folder and Markdown summary.
   The dashboard's **Run round** button still invokes the VAmPI attacker;
   use the CLI commands above for the growing lab. Current findings update after
   defense; previous round totals remain historical snapshots.

5. To observe discovery alone, run the following and stop it with Ctrl+C before
   launching another assessment:

   ```bash
   .venv/bin/python run_scout.py --target http://localhost:8000 --interval 5
   ```

6. Pause growth without deleting data when a fixed before/after comparison is
   needed:

   ```bash
   LAB_GROWTH_SECONDS=0 LAB_MAX_COLLECTIONS=0 docker compose -f compose.lab.yml up -d
   ```

   Repeat step 2's growth command to resume. `docker compose -f compose.lab.yml
   down` stops the lab while retaining its scenario volume and host policy file.

### Metrics and their meaning

| Metric | Definition |
|---|---|
| Surface size | Collections and endpoint/method pairs in two OpenAPI snapshots; the latter includes login and health routes. |
| Observed growth rate | Difference in endpoint/method pairs divided by measured observation seconds, multiplied by 60. A short observation window can differ from the configured long-term rate. |
| Assessment outcomes | Number of vulnerable, defended, and inconclusive collections, before and after defense. A collection has two routes but one ownership finding. |
| Remediation rate | Initially vulnerable findings with a verified defender patch **and** a secure independent reassessment, divided by all initially vulnerable findings. No eligible findings produces N/A, not 100%. |
| Defender outcomes | Counts of applied policies, verified fixes, failures, and successful rollbacks. |
| Remaining / unresolved | Initially vulnerable findings still vulnerable, or missing/inconclusive, respectively. Unresolved findings never count as repaired. |
| Owner access preservation | Successful legitimate-owner checks after defense divided by two checks per reassessed collection. Missing evidence counts as a failed check. |
| New exposure during agents | Collections and vulnerabilities first present in reassessment; these are separate from the original remediation denominator. |
| Regressions | Initially defended findings that become vulnerable on reassessment. |
| Phase durations | Observation, assessment, defense including verification, and independent reassessment elapsed seconds. These are not per-finding MTTR. |

Live runs do not read evaluator ground truth, so they do not claim precision,
recall, or exact introduction-to-detection latency. The isolated `run_harness.py`
compares observed verdicts with known labels and reports classification counts.
Neither mode establishes general LLM effectiveness or coverage of every API flaw.

### How growth works, at a high level

Think of the API as a building that keeps opening new rooms. Each new collection
is one room with two doors: a list of the current user's records, and access to
one specific record. The application has a timer that creates another named
collection from the same template and registers its two real routes with FastAPI.
It refreshes OpenAPI so Scout and Swagger can discover them without restarting.

Each collection contains Alice's record and Bob's record. Some individual-record
routes check ownership; others intentionally omit that check. The attacker tests
whether Alice can read Bob's record and vice versa. The defender enables an
ownership rule for that collection, then verifies that cross-user access is
blocked while owners retain access. Newly added collections have independent
rules, so repairing existing collections does not preemptively repair future ones.

This simulates deployment of new API resources. It does not invent new code or
new vulnerability types: it grows instances of one controlled template. That is
useful for measuring discovery and remediation as a surface expands, but broader
research claims require more templates and the independent VAmPI benchmark.

## Recorded live result

The [21 October 2026 live run](runs/2026-10-21_12-38-52/SUMMARY.md) observed
138 → 141 collections, then assessed 141 collections. It found 56 vulnerable
collections and verified all 56 repairs: **100% remediation rate**, zero failed
patches, zero rollbacks, and **284/284 legitimate-owner checks passed** on
reassessment. One new vulnerable collection appeared during agent execution,
so the final snapshot contained 141 defended and one vulnerable collection.
This distinguishes successful repair of known findings from new exposure caused
by continued growth. Full raw evidence is stored alongside the summary.

## Implementation roadmap

1. **Growing lab (implemented):** introduce resource collections over time, publish them in
   OpenAPI, preserve progress across restarts, and keep evaluator-only ground
   truth outside the public API. Mix secure and vulnerable ownership checks.
2. **General attacker (future):** extract schemas and auth requirements, detect surface
   changes, and replace exact VAmPI path matching with reusable checks. Start
   with two-user object authorization. Record target/endpoint-specific findings.
3. **Defender (lab adapter implemented):** Watcher reads target-scoped findings,
   Analyst selects a supported recipe, and Responder applies an ownership policy.
   Closure requires fresh exploit replay and legitimate-user checks. VAmPI recipes
   remain proposals; source-code patch generation and broader adapters are future work.
4. **Closed loop:** alternate assessment, remediation, and verification with
   scenario changes at reproducible boundaries. Add permission changes, removals,
   and regressions as well as new endpoints.
5. **Evaluation (initial harness implemented):** validate timed growth, classify
   ownership failures against private ground truth, and evaluate one defender pass.
   Broader detection metrics, varied business logic and scale testing remain future
   work. Keep VAmPI as the unchanged benchmark; add crAPI later for transfer testing.

Current limitations: the lab assessment is a deterministic fixture-based adapter,
not a general LLM attacker. Remediation enforces a predefined policy rather than
generating a source patch. The harness validates one template, not arbitrary APIs. Timed growth adds instances of one resource
template; it does not generate arbitrary business logic or new vulnerability classes.


The executable attack pipeline still implements M4 against VAmPI. The new
lab, defender and evaluation harness establish the next stages without claiming a completed
attacker–defender loop.

## Growing FastAPI lab

Start the lab independently of the benchmark (Docker Desktop must be running):

```bash
docker compose -f compose.lab.yml up -d --build
```

Open http://localhost:8000/docs or fetch http://localhost:8000/openapi.json.
Initially there are two collections, each with a list route and an item route.
Every 60 seconds another collection appears with two real, callable routes.
Reload Swagger UI to see new routes. Growth stops at 100 collections by default
to bound memory use; explicitly set `LAB_MAX_COLLECTIONS=0` for indefinite growth.

```bash
# Faster demo: one collection every ten seconds, no collection limit
LAB_GROWTH_SECONDS=10 LAB_MAX_COLLECTIONS=0 docker compose -f compose.lab.yml up -d

# Inspect startup and growth events
docker compose -f compose.lab.yml logs -f growing-api
```

| Setting | Default | Meaning |
|---|---|---|
| `LAB_SEED` | `444` | Repeatable secure/vulnerable ordering |
| `LAB_INITIAL_COLLECTIONS` | `2` | Minimum initial number of collections |
| `LAB_GROWTH_SECONDS` | `60` | Seconds between additions; `0` freezes growth |
| `LAB_MAX_COLLECTIONS` | `100` | Maximum collections; `0` means unlimited |

Each collection has records owned by `alice` (item 1) and `bob` (item 2).
Login at `POST /auth/login` with either username and password `lab-password`.
Use the returned `access_token` as a bearer token. Listings show only the
current user's records. Some detail routes deliberately omit the ownership
check; other routes enforce it. Every pair of collections includes both variants.
Authentication uses fixed lab tokens, not production credentials.

The seed fixes labels and route order, not wall-clock timings. Restarts resume
saved collections and restart the growth timer; they do not backfill downtime.
The private evaluator manifest (`/data/scenario.json` in the container) records
introduction times and vulnerability labels. It is not served by the API and
is not mounted into the attacker. Keep it out of agent prompts. Run one Uvicorn
worker only: multiple workers would disagree about live routes and saved state.

```bash
# Evaluator-only inspection
docker compose -f compose.lab.yml exec growing-api cat /data/scenario.json

# Stop while retaining the scenario
docker compose -f compose.lab.yml down

# Start over: this deletes the lab scenario volume (not benchmark or agent state)
docker compose -f compose.lab.yml down -v
```

For native development:

```bash
.venv/bin/python -m pip install -r lab/requirements.txt
.venv/bin/python -m uvicorn lab.app:create_app --factory --port 8000 --workers 1
```

Native state lives in `lab-state/scenario.json`. Changing the seed requires a
new state file (`LAB_STATE_FILE`) or a fresh Docker volume. Invalid saved state
fails startup rather than silently resetting the experiment.

### Watch growth in the existing dashboard

With the dashboard already running, use a native discovery-only watcher:

```bash
.venv/bin/python run_scout.py --target http://localhost:8000 --interval 5
```

Or rebuild the agent image and run the watcher inside Docker:

```bash
docker compose build agent
docker compose run --rm --no-deps agent python3 run_scout.py \
  --target http://growing-api:8000 --interval 5
```

The two Compose files share the default project network when invoked from this
repository with the same project name (do not use different `-p` names).
Open http://localhost:8765 to see the Attack Surface table and scout events
update. This only refreshes discovery; it creates no attack round or findings.
Stop the watcher before running benchmark attacks because the dashboard has
one current surface snapshot. The **Run round** button still runs VAmPI-specific
modules: do not interpret its results on the growing lab as vulnerability coverage.

## Standalone assessment and defender (no loop)

The supported lab action is a real per-collection ownership policy. The API reads
`lab-policy/policy.json` on each item request, so changes take effect without a
restart. Docker mounts the directory read-only into the API; the native defender
writes the host file atomically. This is separate from the evaluator manifest:
patching does not change the original vulnerability labels.

Rebuild the lab to include policy support, then run these **separate commands**:

```bash
mkdir -p lab-policy
docker compose -f compose.lab.yml up -d --build

# One discovery/assessment pass using Alice and Bob; no Ollama needed
.venv/bin/python run_lab_assessment.py --target http://localhost:8000

# Preview remediation proposals from those saved findings
.venv/bin/python run_defender.py --target http://localhost:8000

# Explicitly apply the supported policies and verify them
.venv/bin/python run_defender.py --target http://localhost:8000 \
  --apply --policy-file lab-policy/policy.json
```

Use the exact same target URL for assessment and defender. Run one assessment or
state writer at a time. `ASM_STATE_DIR` can select a separate output directory;
set it consistently for both commands. The native defender uses the host-mounted
policy file, not the Docker container's `/policy` path. Policy files belong to one
lab instance; do not share them across experiments or reuse them when resetting a
scenario. For a fresh experiment, use both a fresh scenario volume and a fresh
policy directory (or move the old policy file aside). `down -v` alone does not
remove the host policy file.

```text
run_defender.py -> orchestrator.run_defender_round(target)
                   -> Watcher: target-scoped open findings
                   -> Analyst: supported remediation recipe
                   -> Responder: reproduce, apply, verify or roll back
                   -> state/defender_plans.json + findings + event log
```

The assessment uses OpenAPI to enumerate this lab's collection routes and probes
both users' own and other-user records. It saves one finding per collection.
It does not read the private manifest. This is a known-fixture test adapter, not
an autonomous general-purpose attacker. The dashboard's Run round button still
runs the VAmPI pipeline; use the CLI above for lab assessment.

The defender reproduces the issue before applying a policy. It then checks both
cross-user accesses return 403, both owners retain their data, and anonymous
access stays blocked. Only then is the finding marked patched and its current
verdict updated. Verification failure restores the previous policy and leaves
the finding open. Unsupported modules are not applied. The draft VAmPI recipes
remain available in preview mode. A positive reassessment reopens a previously
patched finding. Newly grown collections get their own policy entries only when
explicitly assessed and remediated; there is no background remediation loop.

Policy writes use an advisory lock and atomic replacement. Docker Desktop can
briefly hide a bind-mounted file during replacement: policy reads retry transient
failures, and the defender allows a bounded propagation window before rollback.
Once a running API has observed a policy, its disappearance fails closed with
503 rather than reverting to vulnerable defaults. These retries do not schedule
additional assessment rounds or introduce an agent loop. A malformed policy
returns 503 on item reads instead of silently disabling authorization. If the
wrong policy file is supplied, verification fails; a policy write alone is never
counted as remediation. Plans and evidence are saved in `state/defender_plans.json`
and exposed in `/api/state`; the dashboard displays findings and defender logs.

## Evaluation harness

```bash
.venv/bin/python -m pip install -r requirements.txt -r lab/requirements.txt
.venv/bin/python run_harness.py --output reports/lab-validation.json
.venv/bin/python -m unittest discover -s tests -v
```

The harness creates a disposable lab and isolated agent state. It does not alter
running Docker services, existing scenarios, or dashboard history. It uses actual
FastAPI routing and lifespan timers through ASGI TestClient, rather than network
sockets, and performs **one assessment followed by one defender pass**, never an
alternating loop. JSON output records checks, evidence, classification counts,
discovery delays, defender duration, and remediation rate. Failures exit nonzero.

Default experiment: start with two collections, grow to six at 50 ms intervals,
then assess all six. The evaluator alone compares results with private labels.
It checks secure negative controls, both ownership directions, new routes after
OpenAPI caching, retained routes, labels absent from public schema, unchanged
ground truth after repair, and policy/route persistence after app reconstruction.
Tests additionally cover rollback, incorrect policy paths, malformed policy,
regressions, and newly introduced unpatched collections.

```bash
# Larger controlled run; the timeout must exceed the requested growth duration
.venv/bin/python run_harness.py --collections 20 --growth-seconds 0.1 \
  --timeout 15 --seed 445 --output reports/lab-validation-20.json
```

Interpretation: this validates that **controlled surface growth and real policy
remediation work for one ownership template**. It does not demonstrate arbitrary
vulnerability discovery, unlimited-scale stability, LLM reasoning quality, or
source-code repair. Fixed tokens and predictable record IDs are lab fixtures.
The next research step is additional resource schemas and vulnerability classes,
followed by comparison with VAmPI using equivalent clean-baseline measurements.

## Architecture

```
run_attacker.py  (CLI)  ─┐
gui/server.py    (GUI)  ─┴─► orchestrator.run_attacker_round(target, model)
                                 │
                                 ├─► agents/scout.py      recon only, no exploits
                                 │      writes → core/state_store.py (attack_surface.json)
                                 │
                                 ├─► agents/planner.py     orders agents/operator.py's
                                 │      MODULES catalog against the discovered surface
                                 │
                                 └─► agents/operator.py    runs each module (deterministic
                                        HTTP check, or a LangGraph ReAct agent using the
                                        `http_request` MCP tool in tools/http_server.py),
                                        writes each Finding → state_store as it completes

core/state_store.py is the shared, file-backed state (events/findings/
attack_surface/rounds under state/) that all of the above read and write.
It is also the integration point for what's next:
```

- **Extending the Defender (M6):** add adapters beyond lab ownership policy.
  `mark_verified_patch()` records verification evidence and closes findings.
  Planner receives prior findings but does not use them yet. Re-verification
  scheduling and alternating rounds remain future work, outside the current scope.
- **A stronger planning model:** `agents/planner.py`'s `plan()` is
  deliberately a plain heuristic today — swap its body for an LLM call
  over the same attack surface + module catalog + prior findings.
- **A new attack module:** add one entry to `agents/operator.py`'s
  `MODULES` list (`requires` = OpenAPI paths it needs, `kind` =
  `"deterministic"` or `"llm"`); Planner and Operator pick it up
  automatically.
- **A new target beyond VAmPI:** Scout already works off any
  OpenAPI-documented API; only `agents/operator.py`'s `MODULES` are
  VAmPI-specific.

## VAmPI benchmark setup

### Software everyone needs installed

| Tool | Why | Get it |
|---|---|---|
| **Git** | clone this repo + VAmPI | usually preinstalled; else `git-scm.com` |
| **Docker Desktop** (or Docker Engine + Compose v2 on Linux) | runs both VAmPI instances, and optionally this agent | `docker.com/products/docker-desktop` |
| **Ollama** | runs the local LLM the attacker agent uses — installed **natively**, not in Docker (Docker Desktop on macOS has no GPU passthrough, so a containerized Ollama is much slower) | macOS: `brew install ollama`; else `ollama.com/download` |
| **Python 3.11+** | only if you'll run the agent natively instead of via Docker (see Option A below) | `python.org`, or `brew install python` on macOS |

After installing Ollama, everyone pulls the model once:
```bash
ollama pull qwen2.5
```

### Clone (this repo + VAmPI, as siblings)

```bash
mkdir agentic-asm-workspace && cd agentic-asm-workspace
git clone <this repo's URL> agentic-asm
git clone https://github.com/erev0s/VAmPI.git
```
The two must sit side by side like this — `docker-compose.yml` and the
native instructions both assume `../VAmPI` relative to `agentic-asm/`.

### Option A — native (recommended while actively developing the agent)

```bash
cd agentic-asm
python3 -m venv .venv
.venv/bin/python3 -m pip install -r requirements.txt

cd ../VAmPI && docker compose up -d && cd ../agentic-asm
curl localhost:5001/createdb && curl localhost:5002/createdb   # once, after first boot

.venv/bin/python3 run_attacker.py --target http://localhost:5002
.venv/bin/python3 gui/server.py            # → http://localhost:8765
```

### Option B — one command, fully containerized (fast way to just see it work)

Nobody needs Python or `pip install` for this path — only Docker + a
native Ollama with `qwen2.5` pulled.

```bash
cd agentic-asm
docker compose up -d --build               # VAmPI (5001/5002) + GUI (8765)
curl localhost:5001/createdb && curl localhost:5002/createdb   # once, after first boot
open http://localhost:8765                  # click "Run round"

# or run the CLI instead of/alongside the GUI, same shared state/:
docker compose run --rm agent python3 run_attacker.py --target http://vampi-vulnerable:5000 --rounds 3

docker compose down                         # stop everything
```

Either option writes to the same `state/` directory the GUI reads. Run only one
assessment writer at a time: file locks are process-local. CLI runs reset the
target database once at startup; dashboard runs do not. Before repeating a
dashboard run, call `/createdb` again because a module changes a user's password.
The dashboard's Reset state button clears saved results, not the target database.

```bash
# fast sanity check either way, no LLM/Ollama needed:
.venv/bin/python3 run_attacker.py --target http://localhost:5002 --skip-llm
```

`smoke_agent.py` (unchanged) is the original MCP-wiring sanity check from
earlier in the project and isn't part of this pipeline.

## Sharing via GitHub

1. Create a **private** repo on GitHub (web UI: New repository → Private;
   or `gh repo create agentic-asm --private --source=. --push` if you have
   the `gh` CLI installed and authenticated).
2. From this folder:
   ```bash
   git remote add origin <the repo's URL>
   git branch -M main
   git push -u origin main
   ```
3. Add teammates: repo page → **Settings → Collaborators and teams → Add
   people**, and send each of them this README's Team Setup section (or
   just the repo link — it's the first thing they'll see).
4. Optional but recommended for a 4-person team: **Settings → Branches →
   Add rule** on `main` requiring a pull request before merging, so
   everyone reviews each other's agent/module changes.
5. `state/` and `reports/` are gitignored (they're per-run output, not
   source) — nobody needs to `git add` them, and merge conflicts there
   are one thing you'll never hit.

## VAmPI benchmark baseline

Eight modules across the OWASP API Security Top 10 — 3 deterministic
("insecure by design", vulnerable regardless of VAmPI's `vulnerable` flag)
and 5 LLM-driven exploit chains (mass assignment, login user/password
enumeration, SQL injection, and two BOLA attacks) that correctly flip
between VAmPI's "vulnerable" (port 5002) and "secure" (port 5001)
instances when execution succeeds. See `agents/operator.py`'s `MODULES` for the
full list. Results are recorded in `state/`, not generated Markdown reports.
Treat this as a fixed regression suite: compare each instance from a clean seeded
database, record model/version and verdicts, and keep inconclusive results distinct
from defended ones. VAmPI's secure setting does not fix every tested weakness.
