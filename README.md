# agentic-asm - attacker agent (M4)

Implements the proposal's "team of specialists" architecture for the
**attacker** side only, against **VAmPI** only, per the current milestone
(M4: "Attacker agent discovers and reports findings"). Built so the
**defender agent + attacker↔defender loop** (M6/M7) can be added later
without restructuring this code.

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

- **Adding the Defender (M6):** write `agents/watcher.py` /
  `agents/analyst.py` / `agents/responder.py`, add
  `orchestrator.run_defender_round()` next to `run_attacker_round()` (a
  placeholder comment marks where), and have Responder call
  `state_store.upsert_finding(..., )` with `status="patched"`. Planner
  already reads `findings` when it plans — teach it to skip or re-verify
  patched ones and the loop (M7, "Round 1 baseline → Round N shrinking
  exposure") falls out of calling `run_attacker_round` /
  `run_defender_round` alternately.
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

## Team setup

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

Either option writes to the same `state/` directory the GUI reads, so you
can mix native and Docker-run commands freely.

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

## What it currently finds on VAmPI

Eight modules across the OWASP API Security Top 10 — 3 deterministic
("insecure by design", vulnerable regardless of VAmPI's `vulnerable` flag)
and 5 LLM-driven exploit chains (mass assignment, login user/password
enumeration, SQL injection, and two BOLA attacks) that correctly flip
between VAmPI's "vulnerable" (port 5002) and "secure" (port 5001)
instances. See `agents/operator.py`'s `MODULES` for the full list and
`reports/` for past run output.
