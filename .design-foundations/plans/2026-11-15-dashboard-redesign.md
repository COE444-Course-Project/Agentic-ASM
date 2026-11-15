# Plan: Agentic ASM dashboard redesign

**Track:** Standard (Phase 1) / Full gate on Phase 2 because it locks DESIGN.md · **Entry stage:** Discover (no JOURNEY.md / DESIGN.md existed)

## Context

**Problem:** Redesign the single-page dashboard (`gui/static/index.html`) so a live audience at the COE444 final demo can *watch* the closed attacker→defender loop: which round and phase is running, the attacker probing collections, the defender patching, the verifier confirming — while keeping every existing control reachable.

**Constraints:**
- One self-contained HTML file served by Flask (`gui/server.py` string-substitutes `__DEFAULT_TARGET__`, `__DEFAULT_MODEL__`, `__KNOWN_TARGETS_JSON__`); no build step; data from polling `/api/state`.
- **Light theme, white surfaces, light-purple primary** (user override: not the slides' teal).
- Projector-legible; evidence text ≥14px; `prefers-reduced-motion` honored.
- Truthful: "patched" (verified defender fix) vs "always secure" stay distinct; inconclusive is never shown as safe.
- Must keep: target picker + custom URL, mode, model, LLM sample, Assess / Defend / Loop / Stop / Reset state, lab growth controls (max, probability, interval, paused, templates, grow, apply, refresh, reset), findings (exploitable / corrected before-after / inconclusive), attack surface, live log, guide drawer.

**Success criteria:** current round + phase readable in ≤2s; collection tiles animate attack → exploitable → patched → verified; per-round scoreboard (remediation rate, new exposure, regressions, legit checks); text pairs pass WCAG AA; works at 375px.

## Phases

### Phase 1: Demo journey + page spec
**Stage:** Discover
**Model:** sonnet
**Doctrine:** journey, content-design, usability
**Gate:** Standard

**Goal:** Define the presenter's job, the demo story, IA and the single-page spec with every region and state.

**Scope:** IN: JTBD, demo-time journey (setup → loop → explain results), IA ordering, page spec regions (top bar, run console, loop stage, tile grid, scoreboard, findings, surface, log, lab drawer, guide), empty/running/error/stopped states, microcopy. OUT: visual styling.

**Edge cases:** VAmPI target selected (loop/defend unavailable → explain, don't hide); no loop ever run (empty stage invites first run); loop stopped mid-round; error from backend; 0 vulnerabilities in a round (rate N/A, not 100%).

**Produces:** JOURNEY.md (Job, Journey, IA, Page specs)
**Depends on:** confirmed brief (this plan's Context, approved in conversation 2026-11-15) | **Unlocks:** Phase 2

**Done when:**
- [ ] DW-1.1: JOURNEY.md `## Page specs` has a complete entry for the dashboard with every region and its empty/running/done/error state
- [ ] DW-1.2: JOURNEY.md contains a control-to-region mapping table with zero unmapped controls from the Constraints list
- [ ] DW-1.3: microcopy for phases, tile states and scoreboard metrics reviewed jargon-free (each term understandable by a non-security classmate)

### Phase 2: Visual DNA, motion system and mock
**Stage:** Design
**Model:** fable
**Doctrine:** design-dna, foundations, color, fonts, motion, interaction, data-viz, responsive, ai-tells
**Gate:** Full

**Goal:** Lock a light-purple-on-white identity and motion grammar, then render a mock of the page spec.

**Scope:** IN: DESIGN.md token block (purple ramp, semantic attacker/defender/verify colors, type scale, spacing, radii), motion tokens (durations, easings, stagger), tile state machine visuals, phase pipeline animation, scoreboard chart spec, responsive rules; self-contained mock HTML. OUT: wiring to live API (build).

**Constraints:** DESIGN.md is locked and user-confirmed before the mock is rendered (DW-2.1 gates DW-2.4). Primary is a light purple used on white; attacker red and defender green must remain distinguishable for colour-blind viewers (pair with icon/shape); reduced-motion fallback is a static state change.
**Edge cases:** purple accent text on white failing AA → use darker purple for text, light purple for fills; 50+ tiles must still fit.

**Produces:** DESIGN.md (locked, token block) + `.design-foundations/mocks/dashboard.html`
**Depends on:** Phase 1 | **Unlocks:** build

**Done when:**
- [ ] DW-2.1: DESIGN.md locked (token block present + user-confirmed)
- [ ] DW-2.2: all text/background pairs pass WCAG AA (≥4.5:1 body, ≥3:1 large); interactive elements ≥3:1 non-text
- [ ] DW-2.3: semantic aliases resolved (`--background`, `--surface`, `--text`, `--accent-solid`, `--error/success/warning/info-*`); no hard-coded hex in the mock outside the token block
- [ ] DW-2.4: mock renders self-contained at 1440px and 375px with tiles in all five states and the phase pipeline animating
- [ ] DW-2.5: design-review-agent returns no Critical findings; Major resolved or accepted

## Verification plan
- DW-1.1–1.3: read JOURNEY.md against the Constraints control list.
- DW-2.2: contrast-check every token pair (dirty case: purple-500 text on white expected to fail → must be swapped for a darker step).
- DW-2.4: screenshot mock at both widths; reduced-motion emulation shows no animation.
- Dirty case Phase 1: VAmPI target state is specified (loop disabled with reason).
- Verification level: rendered-pixel review.

## Execution log
**Status:** complete · **Started:** 2026-11-15 10:40 · **Completed:** 2026-11-15 14:20 · Branch: feature/closed-loop-dashboard

### Phase 1: Demo journey + page spec (Gate: Standard)
- [x] BUILD: JOURNEY.md written by the orchestrator (deviation: not dispatched to design-build-agent)
- [x] REVIEW: three attempts. Attempt 3 passed DW-1.1, DW-1.2 and DW-1.3, but flagged one edge case: JOURNEY.md did not describe the VAmPI stage/scoreboard copy. Per the gate-failure protocol (3 attempts max) it was not re-reviewed. The copy was added to JOURNEY.md and verified in the live UI instead. Escalated to the user in the final report.
- [x] Committed with Phase 2
Summary: JOURNEY.md holds the job, journey, IA, per-region page specs (empty/running/done/stopped-error), the control-to-region map (0 unmapped) and the plain-language glossary.

### Phase 2: Visual DNA, motion system and mock (Gate: Full)
- [x] BUILD: DESIGN.md locked by the orchestrator (purple pinned by the user, Annunciator Panel chosen on the impeccable decision page). Mock rendered by design-build-agent (opus; fable rate-limited).
- [x] REVIEW: mock review PASS. Two Majors fixed in DESIGN.md: --lamp-idle at 3.59:1 for waiting outlines, and the counting rule.
- [x] User sign-off on the mock: Approve.
- [x] Live build: gui/static/index.html wired to /api/state. Finish review: fix → ship (7/7 fixes resolved). Gates: taste inspect --app 0 FAIL / 0 WARN (palette-purple allowed as brand), impeccable detect [].
Summary: the dashboard ships the Annunciator Panel world in light purple on white, with a live loop ring, a lamp wall, a stamped scoreboard and before/after evidence.
- [x] Post-documenter fix: --lamp-edge darkened to #8269d8 (2.64:1 → 3.66:1 on lavender).
