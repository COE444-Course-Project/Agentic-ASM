# Agentic ASM — evolving API lab and attacker assessment

The primary experiment is now a **growing FastAPI attack surface**. VAmPI
remains the fixed external benchmark for regression testing. The growing lab's
own deterministic ownership-assessment adapter checks every collection, every
round, with no LLM involved -- that stays the fast, exhaustive baseline. An
optional, sampled LLM-driven cross-check is also available for the lab (see
"LLM-sampled checks" below); VAmPI's reasoning-based modules remain the only
*exhaustive* LLM attacker. The defender supports preview mode and explicit, verified remediation of the
lab ownership vulnerability, and a **bounded closed attacker–defender loop**
(`run_loop.py`, or **Start loop** in the dashboard) repeats grow → discover →
attack → defend → verify for as many rounds as you ask.

## Closed attacker–defender loop

```bash
docker compose -f compose.lab.yml up -d --build        # the growing lab
.venv/bin/python run_loop.py --rounds 5 --grow 5 --drift 1 --seed 444
```

Each round:

1. **Grow** — the lab adds `--grow` new scenarios at the round boundary (lab timer
   growth is paused for the run and restored afterwards, so every change is
   reproducible). With `--drift N`, from round 2 on N verified patches are
   reverted to simulate a configuration regression.
2. **Discover** — Scout rereads the OpenAPI schema.
3. **Attack** — the deterministic two-user assessment probes every collection
   (plus `--llm-sample` LLM missions via Ollama, if requested).
4. **Defend** — Watcher → Analyst → Responder: reproduce, apply the
   operation-specific policy, replay the exploit, check legitimate users,
   roll back on failure.
5. **Verify** — an independent reassessment confirms what held.

Per round the loop records new collections, **new exposure** (vulnerable on
first appearance), **regressions** (secure last round, vulnerable now),
found / verified-fixed / still-open counts, legitimate-operation checks and
phase durations. Results go to `runs/<timestamp>_loop/` (`SUMMARY.md`,
`metrics.json`, raw per-round assessment and defender evidence) and live into
`state/loop.json`, which the dashboard animates. Bounds: 1–20 rounds, 0–50
scenarios per round, 0–20 drift. The dashboard's **Stop** ends the loop
cooperatively between collections. If `--policy-file` does not exist the loop
starts it empty: never *delete* the policy file under a running lab — a lab that
has seen a policy fails closed (503) when it disappears; empty it instead.

Recorded: [15 November 2026 loop](runs/2026-11-15_09-31-04_loop/SUMMARY.md) —
5 rounds, 0 → 25 collections, 19/19 vulnerabilities (15 new exposure + 4 drift
regressions) fixed with verified repairs, 150/150 legitimate checks, 0
rollbacks, about 1.1 s per round.

The dashboard (`gui/server.py`) exposes the same loop at `POST /api/loop`
(`rounds`, `grow_per_round`, `drift`, `llm_sample`, `phase_delay`, `seed`) and
a single verified defender pass at `POST /api/defend`; both refuse non-lab
targets. In Docker the agent container mounts `lab-policy/` read-write for this.

### Live dashboard

`.venv/bin/python gui/server.py` (or the `agent` Compose service) serves
http://localhost:8765. Pick the target from the chip in the top bar, then use
the run console's tabs: **Closed loop** (rounds, new scenarios per round, drift,
phase pacing), **Assess once**, or **Defend once**. The loop ring lights
Grow → Discover → Attack → Defend → Verify as the server reports each phase
(pacing holds each phase on screen so an audience can follow; it is excluded
from measured durations). Each collection is a lamp: Waiting, Probing,
Breached (red, hatched, "!"), Fixed by defender (green, shield), Secure (green
outline) or Unclear (amber, dashed, "?"), with "new" and "reverted" notches.
The round scoreboard stamps Found / Fixed / New exposure / Regressions and the
totals; click any lamp for its before/after HTTP evidence. **Lab controls**
holds the growth settings and **Guide** explains every term. Design records:
`PRODUCT.md`, `JOURNEY.md`, `DESIGN.md`.

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
   LAB_GROWTH_SECONDS=3 LAB_MAX_COLLECTIONS=15 docker compose -f compose.lab.yml up -d --build
   docker compose up -d --build --no-deps agent
   ```

   Open http://localhost:8000/docs for API documentation and
   http://localhost:8765 for findings and logs. Existing collections and patches
   are retained. These values are tuned for a short, bounded demo: the lab adds
   one collection (a randomly selected scenario type) every 3 seconds and stops
   automatically at 15 -- enough to see a good mix of templates within about a
   minute, without growing (and consuming memory) forever in the background.
   `LAB_MAX_COLLECTIONS=0` removes the cap for a genuinely unbounded, long-running
   experiment, but expect proportionally more memory/CPU use the longer it runs
   -- see "Memory requirements" further below. Use the dashboard's growth
   **Lab controls** drawer (or its **Reset to 0** button) to change the pace or start
   over live, without a restart. Refresh Swagger to see new routes. Do not
   remove "orphan" containers: the two Compose files intentionally manage
   different services under the same project.

3. Record one complete live experiment:

   ```bash
   .venv/bin/python run_live.py --target http://localhost:8000 \
     --observe-seconds 25 --apply --policy-file lab-policy/policy.json
   ```

   This observes growth for 25 seconds, performs one assessment, runs one
   defender pass, and independently reassesses. It saves a timestamped folder
   under `runs/` (Asia/Dubai time), including `SUMMARY.md`, `metrics.json`, and
   raw assessment/defender evidence. It also writes the usual dashboard state.
   It exits after this single sequence; use `run_loop.py` for repeated rounds.
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
   The dashboard's **Run assessment** (Assess once tab) button supports both VAmPI and the custom API.
   Choose **Auto-detect API**, **VAmPI attacker**, or **Custom API assessment**.
   Custom API rounds refresh discovery and run deterministic checks on every
   collection, with no Ollama involved, by default. Setting the dashboard's
   **LLM-sampled checks** field above `0` additionally runs that many
   independent, model-driven cross-checks against randomly chosen collections
   -- see "LLM-sampled checks on the custom API lab" below. Defender
   application is the dashboard's **Defend once** tab or the CLI. Current findings update after
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

7. Reset the lab's collections from the dashboard instead of deleting the
   scenario volume. The dashboard's **Reset to 0** button (in the **Lab
   controls** drawer) calls the lab's `POST /admin/reset`: it clears every
   collection and its routes, then reseeds to `LAB_INITIAL_COLLECTIONS`, live,
   with no Docker command or restart. Growth settings (interval, cap,
   templates, odds) are kept as currently configured. Because collections are
   renumbered from 1, a stale policy entry for an old `collection_0001` would
   silently re-apply to the *new* `collection_0001`, so the dashboard button
   also empties `lab-policy/policy.json` (`"clear_policy": true`). The plain
   API call below leaves the policy alone; empty the file yourself (never
   delete it under a running lab) if you also want a clean remediation slate:

   ```bash
   curl -X POST http://localhost:8765/api/lab-reset \
     -H 'Content-Type: application/json' -d '{"target": "http://localhost:8000"}'
   ```

### Metrics and their meaning

| Metric | Definition |
|---|---|
| Surface size | Collections and endpoint/method pairs in two OpenAPI snapshots; the latter includes login and health routes. |
| Observed growth rate | Difference in endpoint/method pairs divided by measured observation seconds, multiplied by 60. A short observation window can differ from the configured long-term rate. |
| Assessment outcomes | Number of vulnerable, defended, and inconclusive collections, before and after defense. A collection has supporting routes and one selected operation-family finding. `defended` is every currently-secure collection; its `patched` subset is only those secure because of a verified defender patch still in effect, not merely because `vulnerability_probability` never made them vulnerable in the first place -- the dashboard's assessment chips and `run_live.py`'s metrics both break this out. |
| Remediation rate | Initially vulnerable findings with a verified defender patch **and** a secure independent reassessment, divided by all initially vulnerable findings. No eligible findings produces N/A, not 100%. |
| Defender outcomes | Counts of applied policies, verified fixes, failures, and successful rollbacks. |
| Remaining / unresolved | Initially vulnerable findings still vulnerable, or missing/inconclusive, respectively. Unresolved findings never count as repaired. |
| Legitimate-operation preservation | Two positive operation checks per reassessed collection; owner operations for B1–B7, administrator actions for V1. Missing evidence counts as a failed check. Legacy JSON keys retain the `owner_` prefix. |
| Per-template results | Tested scenarios, initially vulnerable cases, verified repairs, and remediation rate grouped by B1–B7/V1 or legacy. |
| New exposure during agents | Collections and vulnerabilities first present in reassessment; these are separate from the original remediation denominator. |
| Regressions | Initially defended findings that become vulnerable on reassessment. |
| Phase durations | Observation, assessment, defense including verification, and independent reassessment elapsed seconds. These are not per-finding MTTR. |

Live runs do not read evaluator ground truth, so they do not claim precision,
recall, or exact introduction-to-detection latency. The isolated `run_harness.py`
compares observed verdicts with known labels and reports classification counts.
Neither mode establishes general LLM effectiveness or coverage of every API flaw.

### How growth works, at a high level

Think of the API as a building that keeps opening different kinds of rooms.
At each tick, the generator randomly chooses **one** scenario type and independently
chooses whether that scenario is vulnerable. It registers real routes and refreshes
OpenAPI without restarting. A document-export scenario does not also receive batch,
sharing, invoice, and administrator vulnerabilities.

The seed makes the choices reproducible. The default vulnerability probability is
50%; a short run can contain an uneven mix or miss some types entirely. Existing
saved scenarios keep their assignments on restart. The attacker discovers operation
shapes from public OpenAPI and tests actual effects; it never reads private labels.
The defender enables the matching operation-specific policy, verifies blocked attacks
and legitimate use, and rolls back failed changes. Future scenarios get independent
policies. This grows a catalog of controlled templates, not arbitrary generated code.

## Random vulnerability templates

All routes below are under `/api/collection_NNNN`. Every new collection has only
one selected type, plus protected supporting routes (`/items`, owner reads, cleanup
operations as needed). Supporting endpoints do not acquire the other weaknesses.

| ID | Operation | Deliberate flaw | Verified defense |
|---|---|---|---|
| B1 | `GET /documents/{id}` | Reads another user's document | Enforce ownership |
| B2 | `POST /exports` | Exports another user's document from a JSON reference | Authorize the referenced document; direct reads remain protected |
| B3 | `GET /projects/{project_id}/files/{file_id}` | File belongs to a different project | Check project membership and file/project relationship |
| B4 | `POST /documents/batch` | Only the first ID in a mixed batch is checked | Authorize every ID; reject unauthorized batches atomically |
| B5 | `PATCH /documents/{id}` | Changes another user's content | Enforce update ownership; direct reads remain protected |
| B6 | `POST /documents/{id}/share` | Creates a working link to another user's document | Require ownership before sharing |
| B7 | `GET /organisations/{org_id}/invoices/{id}` | Billing role alone allows cross-tenant access | Check organisation membership and invoice scope |
| V1 | `POST /admin/users/{id}/disable` | Ordinary user disables an account within that scenario | Enforce administrator role |

Alice and Bob own different records/projects/organisations and have the billing role.
`admin` is the administrator positive control; all three log in with `lab-password`.
Disabling an account blocks that user's authenticated access within the scenario,
not across unrelated scenarios. Probes restore modified contents, revoke generated
share links, and re-enable accounts, verifying cleanup before counting success.
Mutation fixtures are in-memory and reset on API restart; assignments and repair
policies persist. Run assessments serially to avoid concurrent fixture mutation.

```bash
# All eight random types, 50% probability of a vulnerable scenario, bounded for a quick demo
LAB_GROWTH_SECONDS=3 LAB_MAX_COLLECTIONS=15 LAB_VULNERABILITY_PROBABILITY=0.5 \
  docker compose -f compose.lab.yml up -d --build

# Optional focused experiment (affects only future scenarios)
LAB_TEMPLATES=B2,B4 LAB_VULNERABILITY_PROBABILITY=0.75 \
  LAB_GROWTH_SECONDS=3 LAB_MAX_COLLECTIONS=15 docker compose -f compose.lab.yml up -d
```

`LAB_TEMPLATES` defaults to `B1,B2,B3,B4,B5,B6,B7,V1`. Probability `0` creates
secure negative controls; `1` creates vulnerable cases. Changing these settings
only affects future additions, not existing records. Use a new seed and fresh
scenario/policy storage for a different reproducible experiment.

Backward compatibility: older collections without a template remain the original
`/items/{item_id}` ownership scenario and retain existing fixes. New repairs are
stored as `{"collection_NNNN": {"B2": true}}`, for example. A B1 policy cannot
silently fix B2. Findings include target, collection, and type. The CLI/dashboard
adapters are deterministic known-fixture checks by default; an optional, sampled
LLM cross-check is also available (see the next section) -- neither is open-ended
autonomous exploit discovery against an unknown schema.

## LLM-sampled checks on the custom API lab

The deterministic adapter above stays the fast, exhaustive default: it checks
every collection, every round, in milliseconds, with no LLM involved. On top of
that, an **optional, sampled** LLM-driven cross-check is available -- the first
piece of the roadmap's "general attacker" step (below), scoped down to
something that actually finishes against an unbounded, still-growing lab.

Set the dashboard's **LLM-sampled checks** field above `0` (and pick an
**Ollama model**) before clicking **Run assessment** (Assess once tab) against the custom API. After
the deterministic pass, that many randomly chosen collections also get an
independent mission: the same two lab users and the same documented operation
(`core/template_catalog.py`'s public B1-V1 contracts), but the request is
decided and sent by the model through the MCP `http_request` tool -- the exact
same ReAct-agent machinery `agents/operator.py` uses for VAmPI -- not by a
direct Python call. Its verdict is graded from the actual HTTP response in the
tool-call transcript, never the model's own prose claim, same discipline as
every other module in this project.

Results appear in **Findings** as `LLM-driven check: <template> (<collection>)`,
tagged `kind: llm`, saved under a distinct id (`lab-llm`) so they never
overwrite the deterministic finding for that same collection -- the two sit
side by side for comparison. A sample of 5-20 is usually enough to confirm the
deterministic baseline and the model agree; running it against every collection
in a lab with hundreds or thousands of them would take hours to re-prove the
same 8 vulnerability shapes repeatedly, which is why this is sampled rather
than exhaustive, and why there's a dashboard cap (50) on the sample size. See
`agents/lab_operator.py` for the per-template attack specs, and the dashboard's
**Guide** drawer ("LLM-sampled checks") for the same explanation
in place.

```bash
curl -X POST http://localhost:8765/api/run -H 'Content-Type: application/json' \
  -d '{"target": "http://localhost:8000", "mode": "custom", "model": "qwen2.5", "llm_sample": 10}'
```

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
2. **General attacker (sampled LLM cross-check implemented, exhaustive version future):**
   extract schemas and auth requirements, detect surface changes, and replace
   exact VAmPI path matching with reusable checks. `agents/lab_operator.py`
   is a first step -- a schema-driven prompt/grader pair reused across all 8
   lab templates instead of one bespoke module each (see "LLM-sampled checks
   on the custom API lab" above) -- but it runs on a random sample, not every
   collection, and still needs a human-picked sample size rather than
   deciding its own scope. Two-user object authorization only; no broader
   reusable-check catalog yet.
3. **Defender (lab adapter implemented):** Watcher reads target-scoped findings,
   Analyst selects a supported recipe, and Responder applies an ownership policy.
   Closure requires fresh exploit replay and legitimate-user checks. VAmPI recipes
   remain proposals; source-code patch generation and broader adapters are future work.
4. **Closed loop (implemented):** alternate assessment, remediation, and verification with
   scenario changes and simulated drift at reproducible round boundaries (`run_loop.py`). Add permission changes, removals,
   and regressions as well as new endpoints.
5. **Evaluation (initial harness implemented):** validate timed growth, classify
   ownership failures against private ground truth, and evaluate one defender pass.
   Broader detection metrics, varied business logic and scale testing remain future
   work. Keep VAmPI as the unchanged benchmark; add crAPI later for transfer testing.

Current limitations: the lab's default assessment is a deterministic
fixture-based adapter; the optional LLM-sampled cross-check (above) only
exercises a random sample per round against the same 8 known templates, not
open-ended discovery of unknown vulnerability shapes -- neither is a general
LLM attacker. Remediation enforces a predefined policy rather than
generating a source patch. The harness validates eight supported types, not arbitrary APIs. Timed growth selects
from the catalog; it does not generate arbitrary business logic.


The executable attack pipeline still implements M4 against VAmPI. The new
lab, defender, closed loop and evaluation harness run against the growing custom API.

## Growing FastAPI lab

Start the lab independently of the benchmark (Docker Desktop must be running):

```bash
docker compose -f compose.lab.yml up -d --build
```

Open http://localhost:8000/docs or fetch http://localhost:8000/openapi.json.
Initially there are two randomly assigned collections. Every 60 seconds another
scenario appears with its operation routes and protected supporting routes.
Reload Swagger UI to see new routes. Growth stops at 100 collections by default
to bound memory use; explicitly set `LAB_MAX_COLLECTIONS=0` for indefinite growth.

```bash
# Short, bounded demo: one collection every 3 seconds, stopping at 15
LAB_GROWTH_SECONDS=3 LAB_MAX_COLLECTIONS=15 docker compose -f compose.lab.yml up -d

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
current user's records. Each new scenario has one randomly chosen type and an
independent secure/vulnerable assignment. Authentication uses fixed lab tokens,
not production credentials.

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
one current surface snapshot. The **Run assessment** (Assess once tab) button detects the target type from its public OpenAPI schema.
Choose **Custom API assessment** to run discovery and supported deterministic checks
on the growing lab. A mismatched explicit type produces an error before assessment.

## Standalone assessment and defender (single passes)

The supported lab actions are real per-collection, per-operation authorization policies. The API reads
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

The assessment uses OpenAPI to enumerate collection routes and select the matching
operation adapter. It checks both users and uses an administrator positive control
for V1. Mutating probes verify effects and clean up their changes. It saves one finding per collection.
It does not read the private manifest. This is a known-fixture test adapter, not
an autonomous general-purpose attacker. The dashboard's **Assess once** tab runs the
same assessment.

The defender reproduces the issue before applying the matching policy. It checks
unauthorized operations are blocked, legitimate operations still work, anonymous
invocation is rejected, and mutable fixtures are restored. Only then is the finding marked patched and its current
verdict updated. Verification failure restores the previous policy and leaves
the finding open. Unsupported modules are not applied. The draft VAmPI recipes
remain available in preview mode. A positive reassessment reopens a previously
patched finding. Newly grown collections get their own policy entries only when
explicitly assessed and remediated, by these commands or by the closed loop.

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
sockets, and performs **one assessment followed by one defender pass**; the
closed loop is covered by `tests/test_loop.py`. JSON output records checks, evidence, classification counts,
discovery delays, defender duration, and remediation rate. Failures exit nonzero.

Default experiment: start with two collections, grow to 32 at 50 ms intervals,
then assess all 32. Random sampling does not guarantee every type; the separate
template test suite explicitly covers all eight in vulnerable and secure modes. The evaluator alone compares results with private labels.
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
remediation work for the supported authorization templates**. It does not demonstrate arbitrary
vulnerability discovery, unlimited-scale stability, LLM reasoning quality, or
source-code repair. Fixed tokens and predictable record IDs are lab fixtures.
The next research step is additional resource schemas and vulnerability classes,
followed by comparison with VAmPI using equivalent clean-baseline measurements.

## Architecture

```
run_attacker.py  (CLI)  ─┐
gui/server.py    (GUI)  ─┼─ VAmPI target ──► orchestrator.run_attacker_round(target, model)
                         │                       │
                         │                       ├─► agents/scout.py      recon only, no exploits
                         │                       │      writes → core/state_store.py (attack_surface.json)
                         │                       │
                         │                       ├─► agents/planner.py     orders agents/operator.py's
                         │                       │      MODULES catalog against the discovered surface
                         │                       │
                         │                       └─► agents/operator.py    runs each module (deterministic
                         │                              HTTP check, or a LangGraph ReAct agent using the
                         │                              `http_request` MCP tool in tools/http_server.py),
                         │                              writes each Finding → state_store as it completes
                         │
                         └─ custom API lab ──► core/lab_checks.assess(client, target)   (every collection,
                                                   deterministic, no LLM)
                                                      │
                                                      └─ optional, llm_sample > 0 ──► agents/lab_operator.py
                                                             run_llm_sample(): same ReAct-agent machinery as
                                                             operator.py, reused generically across all 8
                                                             templates via core/template_catalog.py, run on a
                                                             random sample of collections only

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
- **A new attack module:** for VAmPI, add one entry to `agents/operator.py`'s
  `MODULES` list (`requires` = OpenAPI paths it needs, `kind` =
  `"deterministic"` or `"llm"`); Planner and Operator pick it up
  automatically. For the custom lab, add one entry to
  `agents/lab_operator.py`'s `_SPECS` (`path`, `body`, `needle`) and one row
  to `core/template_catalog.py`'s `TEMPLATES` -- the prompt and grader are
  already generic across every template, so a new one needs no bespoke
  prompt-writing or checking logic, just its attack spec.
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

**Memory requirements.** `qwen2.5`'s default size is ~4.6GB resident, and Docker
Desktop's VM commonly reserves another ~3.8GB -- together that's over 8GB
before macOS, a browser, or anything else is counted. Measured directly on an
8GB machine: a full VAmPI LLM assessment took **~218s** with the custom API
lab stopped (the floor -- loading the model and running 5 sequential
multi-turn missions is inherently a few minutes, not seconds, once memory
pressure forces swapping to disk) and **~315s** with the lab running and
large (~2,000 collections) -- about 45% slower, from the lab's in-memory
route table and the dashboard's larger state payload competing with Ollama
for the same limited RAM. Deterministic-only checks (`--skip-llm`, or any
custom API assessment with `llm_sample: 0`) stay sub-2-second regardless,
since no model is involved. If assessments feel unexpectedly slow: pause or
reset the lab first (the dashboard warns you before an LLM-driven run if the
lab is large and still growing), consider a smaller/quantized model, close
other heavy applications, or reboot if the machine has been up for days --
long uptimes accumulate swap/memory fragmentation that a reboot reclaims.
16GB+ of RAM avoids this class of slowdown entirely.

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
open http://localhost:8765                  # Assess once → Run assessment, or Closed loop → Start loop

# or run the CLI instead of/alongside the GUI, same shared state/:
docker compose run --rm agent python3 run_attacker.py --target http://vampi-vulnerable:5000 --rounds 3

docker compose down                         # stop everything
```

Either option writes to the same `state/` directory the GUI reads. Run only one
assessment writer at a time: file locks are process-local. Both CLI and dashboard VAmPI runs reset the target's demo database via
`/createdb` before **every round**, then verify both seeded logins and a victim
book before starting attacks. This restores passwords changed by prior attacks.
Only use this mode against disposable VAmPI fixtures: reset removes demo data.
CLI `--no-reset` skips restoration but still validates prerequisites.
If Docker is stopped, reset fails, or fixtures are missing, the run stops with a
preflight error instead of generating misleading security results.
Custom API assessments do not reset their database or applied defender policies.

VAmPI uses sequential Ollama/MCP attack modules and can take several minutes;
custom API assessments use fast deterministic HTTP probes. HTTP server errors,
rate limits, malformed tool results, and internal/database failures are
inconclusive, never proof of defense. Inconclusive LLM checks may still occur
if the model fails to execute the requested attack; inspect their evidence.
Historical results are retained: rounds produced before this fix are not
reclassified and must not be used as security evidence.
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
