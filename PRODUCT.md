# Product

<!-- impeccable:product-schema 1 -->

## Platform

web

## Users
Primary: the instructor and classmates watching the COE444 final presentation on a classroom projector. They are not API-security specialists. Their job is to understand, in real time, that one agent attacks a changing API and another repairs and re-verifies it, round after round. The four team members drive the page during the demo and run experiments with it, but the screen is designed for the audience first.

## Product Purpose
Agentic ASM is a continuous attack-surface assessment system. It answers the research question: can attacker and defender agents repeatedly discover, confirm, remediate and re-test vulnerabilities as an API changes? The dashboard makes that loop visible and records the evidence. Success means a viewer can tell what round and phase is running, what was found, what was fixed, and that legitimate use still works.

## Positioning
Not a one-time scanner. Each round the API grows (and can drift), the attacker re-discovers and probes every collection with real HTTP requests, the defender applies a policy, replays the exploit, checks legitimate access and rolls back on failure, and an independent reassessment confirms. Verdicts come from actual responses, never from a model's claim.

## Operating Context
- Targets: a growing FastAPI lab (8 authorization templates B1–B7, V1) and the fixed VAmPI benchmark (secure and vulnerable instances).
- Runs: single assessment, single defender pass, or the bounded closed loop. Optional LLM-sampled cross-checks via local Ollama (qwen2.5).
- Served by `gui/server.py` (Flask) at http://localhost:8765, polling `/api/state`.

## Capabilities and Constraints
- Single self-contained `gui/static/index.html`; no build step; server substitutes `__DEFAULT_TARGET__`, `__DEFAULT_MODEL__`, `__KNOWN_TARGETS_JSON__`.
- The defender and loop support only the custom lab; VAmPI remediation stays proposal-only.
- "Patched" (verified defender fix in effect) differs from "secure" (never vulnerable). "Inconclusive" never means safe.
- Scope boundaries: predefined policy repairs, not source patches; known templates, not general exploit discovery.

## Brand Commitments
Name "Agentic ASM" only. Primary colour is a light purple alongside white (user-binding). No existing mark must be kept.

## Evidence on Hand
Live run folders under `runs/` (SUMMARY.md, metrics.json, raw evidence); harness reports under `reports/`. No customers, testimonials or benchmarks beyond these recorded runs exist; do not invent any.

## Product Principles
1. Show the loop, not just the results: phase and round are always legible.
2. Evidence over assertion: every verdict links to the real response.
3. Honest states: patched, secure, exploitable and inconclusive are never blurred.
4. Self-explanatory for a newcomer watching from the back of the room.

## Accessibility & Inclusion
No product-specific requirement was set beyond WCAG AA (user expressed no preference). Projector legibility follows from the audience.
