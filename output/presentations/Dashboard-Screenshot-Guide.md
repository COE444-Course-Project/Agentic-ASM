# Dashboard screenshots for the Week 10 slides

The revised deck uses slide 3 for the attacker, slide 4 for the defender, slide 5 for the custom API, and slide 6 for the scenario descriptions. The dashboard at port 8765 was not running when checked, so the deck contains no new dashboard screenshots. These steps produce real screenshots to add to the relevant slides.

## Preparation

Run the commands from the project folder. Keep this terminal open throughout so the variables and server process IDs remain available. The commands create separate dashboard state and a fresh custom lab under a temporary directory, preserving the project's existing results and lab policies.

```bash
cd /Users/wbk/Documents/GitHub/Agentic-ASM
DEMO_DIR="$(mktemp -d /tmp/asm-slide-demo.XXXXXX)"
mkdir -p "$DEMO_DIR/attacker" "$DEMO_DIR/lab-state" "$DEMO_DIR/policy"
printf 'Screenshot evidence directory: %s\n' "$DEMO_DIR"
```

Prerequisites: the project's `.venv` with `requirements.txt` and `lab/requirements.txt` installed. The VAmPI screenshot also needs Docker Desktop, the sibling VAmPI checkout, and Ollama running with `qwen2.5` available. The custom API and defender screenshots do not need Ollama or Docker.

## Attacker screenshot — slide 3

Start the VAmPI targets and a dashboard that uses separate demo state:

```bash
docker compose up -d --build vampi-secure vampi-vulnerable
ASM_STATE_DIR="$DEMO_DIR/attacker" TARGET=http://localhost:5002 MODEL=qwen2.5 \
  .venv/bin/python gui/server.py --port 8765 > "$DEMO_DIR/attacker-dashboard.log" 2>&1 &
ATTACKER_DASH_PID=$!
```

If the targets are still starting, wait until their API responds. Initialize the disposable VAmPI vulnerable benchmark database before the round. This resets that benchmark's test users and records:

```bash
curl --fail http://localhost:5002/createdb
```

Open [the attacker dashboard](http://localhost:8765).

1. Set **Target URL** to `http://localhost:5002` and **Ollama model** to `qwen2.5`.
2. Click **Run round** once and wait until the round finishes.
3. Capture the round summary, **Findings**, and **Live log** together. Show at least one finding with its evidence, plus the Scout/Planner/Operator activity if visible.
4. If an LLM mission is inconclusive, keep that outcome visible and diagnose the log. Do not label it as defended.

Suggested caption: **“VAmPI assessment with endpoint discovery, exploit findings and an execution log.”**

For a secure-mode comparison, initialize `http://localhost:5001/createdb`, change the dashboard target to port 5001, and run a separate round. Some deterministic weaknesses remain in both VAmPI modes, so do not expect every finding to become defended. Capture the vulnerable run first, because the Findings panel combines results from the stored targets.

## Defender screenshots — slide 4

Start a fresh native custom API with 16 initial collections and growth paused. The 50% setting mixes secure and vulnerable cases; use the actual results, not the historical slide totals, for the screenshot caption.

```bash
LAB_STATE_FILE="$DEMO_DIR/scenario.json" \
LAB_POLICY_FILE="$DEMO_DIR/policy/policy.json" \
LAB_SEED=444 LAB_INITIAL_COLLECTIONS=16 LAB_GROWTH_SECONDS=0 \
LAB_MAX_COLLECTIONS=20 LAB_VULNERABILITY_PROBABILITY=0.5 \
  .venv/bin/python -m uvicorn lab.app:create_app --factory \
  --host 127.0.0.1 --port 8001 --workers 1 > "$DEMO_DIR/custom-api.log" 2>&1 &
LAB_PID=$!

ASM_STATE_DIR="$DEMO_DIR/lab-state" TARGET=http://localhost:8001 \
  .venv/bin/python gui/server.py --port 8766 > "$DEMO_DIR/lab-dashboard.log" 2>&1 &
LAB_DASH_PID=$!
```

After the API finishes starting, run the assessment:

```bash
ASM_STATE_DIR="$DEMO_DIR/lab-state" \
  .venv/bin/python run_lab_assessment.py --target http://localhost:8001 \
  > "$DEMO_DIR/assessment-before.json"
```

Open [the custom lab dashboard](http://localhost:8766). Capture a **VULNERABLE** finding with its document/action description and evidence. Then apply the supported defender policies:

```bash
ASM_STATE_DIR="$DEMO_DIR/lab-state" \
  .venv/bin/python run_defender.py --target http://localhost:8001 \
  --apply --policy-file "$DEMO_DIR/policy/policy.json" \
  > "$DEMO_DIR/defender.json"
```

The dashboard polls automatically. Capture the same finding showing **defended** and **patched**, with Responder messages in the log. Current finding status updates after defense, but old round-summary counts describe the earlier assessment. Use the current Findings panel as the before/after evidence.

For additional independent verification, run another assessment after taking the patched screenshot:

```bash
ASM_STATE_DIR="$DEMO_DIR/lab-state" \
  .venv/bin/python run_lab_assessment.py --target http://localhost:8001 \
  > "$DEMO_DIR/assessment-after.json"
```

Suggested caption: **“The defender blocks the previously confirmed unauthorized action and verifies legitimate access.”** Use this caption only when the actual verification succeeds. Pair the before and after captures of the same finding, rather than unrelated rows.

**Do not click Run round for the custom API.** That button always invokes the VAmPI attacker. The lab assessment and defender run through the terminal commands above, and their state feeds this dashboard. There is no dedicated defender screen or repair button.

## Custom API growth screenshots — slide 5

Reuse the fresh lab, now allowing four additional collections. Stop only the lab process started above, then restart it with the same scenario and policy files:

```bash
kill "$LAB_PID"
wait "$LAB_PID" 2>/dev/null || true

LAB_STATE_FILE="$DEMO_DIR/scenario.json" \
LAB_POLICY_FILE="$DEMO_DIR/policy/policy.json" \
LAB_SEED=444 LAB_INITIAL_COLLECTIONS=16 LAB_GROWTH_SECONDS=10 \
LAB_MAX_COLLECTIONS=20 LAB_VULNERABILITY_PROBABILITY=0.5 \
  .venv/bin/python -m uvicorn lab.app:create_app --factory \
  --host 127.0.0.1 --port 8001 --workers 1 > "$DEMO_DIR/custom-api-growth.log" 2>&1 &
LAB_PID=$!
```

After startup, begin the discovery watcher:

```bash
ASM_STATE_DIR="$DEMO_DIR/lab-state" \
  .venv/bin/python run_scout.py --target http://localhost:8001 --interval 5
```

1. Capture the **Attack Surface** panel and the discovery log near the beginning.
2. After approximately 40 seconds, capture the larger endpoint list and a later discovery count. Scroll inside the panel to show newly added collection paths.
3. Optionally open [the custom API documentation](http://localhost:8001/docs) and refresh it to show the generated operation routes.
4. Press **Ctrl+C** to stop the watcher before running any further assessment or defender command.

Suggested caption: **“The custom API adds collections over time, and Scout discovers their new routes.”** Discovery alone does not assess vulnerabilities. Existing Findings during this screenshot still refer to the previous assessment.

## Adding the images to the presentation

Use a wide browser window and capture only the useful application area. Keep the target URL, finding verdicts and relevant log messages legible. On macOS, Shift–Command–4 lets you capture a region.

- **Slide 3:** Attacker overview or a focused finding with its execution log.
- **Slide 4:** Before/after captures of the same finding.
- **Slide 5:** Before/after endpoint discovery, or one clear dashboard capture plus Swagger routes.

The slides currently contain implementation and evidence bullets. Place a screenshot below the implementation bullets and move the lower explanatory bullets to speaker notes if needed. For a readable full dashboard, duplicate the relevant slide for a dedicated evidence slide rather than squeezing the entire interface next to dense text. New runs may differ from the recorded October 21 metrics already in the deck. Label them as separate demonstration runs and use their actual counts.

When finished, stop only the demo processes started in this terminal. The temporary evidence files remain available:

```bash
kill "$ATTACKER_DASH_PID" "$LAB_DASH_PID" "$LAB_PID"
```
