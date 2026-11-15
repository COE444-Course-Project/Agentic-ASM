# Design Review: Mock - Dashboard redesign

## Rendered Evidence (Step 0)
- Screenshots: `.design-foundations/mocks/dashboard-1440.png` (2880x1800 @2x), `.design-foundations/mocks/dashboard-375.png` (750x6000 @2x, full page)
- Source: `.design-foundations/mocks/dashboard.html` (835 lines, tokens inlined verbatim from DESIGN.md)
- Surface: Dashboard (`/`) in its "paused after round 2 of 4" sample state, styled fidelity, desktop + phone.

## Assessment B — Deterministic Detector
- Command: `node scripts/detect.mjs .design-foundations/mocks/dashboard.html > .design-foundations/build/detect.json` (from design-for-ai 4.2.0 plugin root)
- Exit: 0 (ran, status "ran", 16 rules)
- Findings: 0
- Opened only after Assessment A findings were frozen: YES

## Triage
- Baseline (always-on): visual (design-dna, checklists, ai-tells CHECKER) + usability (Nielsen 10)
- Dispatched: data-viz (scoreboard totals, per-round number table, lamp wall encodes state counts); content-design (real microcopy: phase sentences, lamp states, scoreboard labels, notes)
- Not applicable: journey (single page state reviewed; flow states are in JOURNEY.md but only one rendered), behavioral/deceptive-patterns (no conversion surface)
- Deferred: none

## Cross-Pillar Findings (ONE ranked report)
| Severity | Pillar | Problem (in the rendered pixels) | Principle | Fix |
|----------|--------|----------------------------------|-----------|-----|
| Major | content-design / data-viz | Totals disagree on screen. Scoreboard says "Fix rate 100% · 9 of 9 found are fixed"; the lamp wall shows 8 green "Fixed by defender" lamps (01,03,05,07,08,10,13,15); the Findings tab (375 shot) says "Fixed by defender 8". The 9 counts B2·03 twice (fixed R1, regressed, fixed again R2). For a surface whose JTBD is "audience trusts the results", two different fixed counts on one screen is the one thing a sharp classmate will ask about. | Nielsen #4 consistency; data integrity / one number per fact (Few, *Information Dashboard Design*) | Either count findings-events and say so ("9 fixes across 8 collections"), or count distinct collections everywhere (8 of 8). Make the scoreboard sub-label state the unit. |
| Major | visual / usability | `--border` (#e6e0f5) is the Waiting lamp edge: 1.28:1 on white, and the white lamp on `--fascia` panel is ~1.15:1. Waiting lamps (the entire wall in the Set-up / empty-to-start state) would have no perceivable boundary; the legend "Waiting" swatch in both screenshots is already near-invisible. Lamps are buttons. | WCAG 2.2 SC 1.4.11 non-text contrast (3:1 for UI component boundaries) | Use `--lamp-edge` (#9a85e6, 3.06:1) 1px for Waiting, or keep `--border` but add a text-muted dash mark. This is a DESIGN.md token-table issue; fix it there. |
| Minor | visual | Legend swatches for "Waiting" and "Secure" both read as an empty white box at 22x16px; Secure differs only by a 1px green edge. On the lamps themselves the text label disambiguates, so this is legend-only. | Gestalt similarity; WCAG 1.4.1 use of colour (mitigated by labels) | Give the Secure swatch a small check or solid green 2px edge; give Waiting a dash. |
| Minor | visual | At 1440 the live-station label "Verify" sits flush against the pulsing ring (no gap), while other labels have clear air. | Proximity / optical spacing (Gestalt) | Offset the Verify label by ~8px or anchor labels outside the ring radius. |
| Minor | usability | Disabled Stop uses opacity .45 on an outline pill (about 2:1). Exempt under WCAG 1.4.3 for inactive controls, but on a projector it may read as missing. | WCAG 1.4.3 exception for disabled; Nielsen #1 visibility of system status | Acceptable; optionally keep the label at text-muted rather than fading the whole button. |
| Minor | content-design | Status "Sample run paused after round 2 of 4" describes a Paused state not in the JOURNEY.md state table (Empty/Running/Done/Error). Fine as mock framing, but there is no Resume affordance next to "Start loop". | Nielsen #2 match between system and real world | Confirm whether paused exists; if so label primary "Resume" or "Start new loop". |
| Note | detector | 0 hits across 16 AI-tell rules. Consistent with A: no purple gradients, no glassmorphism, no card-shadow stacks, single family (Figtree) with a tabular-figure system. | ai-tells.md | — |

### Distinctiveness (ai-tells CHECKER)
Nameable direction: "control-room annunciator lamp wall" / "lavender fascia instrument panel". Non-generic choices present: lamp windows with "new"/"reverted" notches, hatch + "!" / shield / dashed "?" redundant state encodings, metro-style loop circle with a live station ring, no shadows except drawers. The purple-on-white SaaS palette and pill buttons are on-pattern, but the lamp wall and loop line carry identity. PASS on distinctiveness.

### Contrast verified (computed from tokens as applied in CSS)
text/fascia 14.78 · text-muted/white 7.00 · text-muted/fascia 6.05 · accent-text/fascia 6.22 (Reset results, Lab controls, Replay demo links) · white/accent-solid 7.20 (Start loop) · success-ink/success-fill 7.36 · error-ink/error-fill 7.44 · warning-text/warning-fill 4.83 (Unclear lamp, 14 "Unclear") · error-text/white 6.01 (regression "1") · success-text/white 5.91 · lamp-edge/white 3.06 (inputs, notches). All text pairs >= 4.5:1. Only failing pair is the non-text Waiting edge above.

### Responsive (375)
Console fields stack single-column, primary pill fills row, stage centres, lamp wall reflows to 3 columns, scoreboard row meta wraps under the round name, no horizontal scroll observed, touch targets bumped to 44px. No defects.

## Requirement Fulfillment
### DW-MOCK.1
PREMISE:  the mock renders a viewable surface for the Dashboard page.
EVIDENCE: Both screenshots show a fully rendered Dashboard following the JOURNEY.md IA order: top bar (mark, name, target chip with `localhost:18001`, Guide), run console (3 tabs, rounds/scenarios/drift/pacing fields, Start loop, Stop, Reset results, Lab controls, status), loop stage (5 stations, Round 2 / 4, "Verify", phase sentence verbatim from JOURNEY microcopy), lamp wall (16 lamps, legend) at 2/3 + scoreboard at 1/3, detail tabs (Findings 9, Attack surface 16, Live log). 375 shot shows the Findings tab content rendered.
VERDICT:  PASS

### DW-MOCK.2
PREMISE:  text/interactive contrast and applied tokens hold on the rendered pixels (styled).
EVIDENCE: `:root` tokens match DESIGN.md verbatim; only derived values are mixes of locked tokens. Every rendered text pair computes >= 4.5:1 (lowest: warning-text on warning-fill 4.83). Interactive boundaries: inputs/notches use lamp-edge 3.06:1, primary button fill vs white high. Lamp state table (fill/edge/mark) is applied as specified for Fixed, Secure, Unclear, reverted/new notches. Type scale (56 round, 28 phase, 14/500 labels, mono endpoints) observed. The Waiting-lamp edge (`--border`, 1.28:1) is a DESIGN.md-specified token, not visible as a lamp in this rendered state (only in the legend); logged as Major for DESIGN.md, not a mock deviation.
VERDICT:  PASS

**All requirements met:** YES

## Notes (non-blocking)
- Only one run state (paused, mid-loop) is rendered; Empty, Running, Done, Error, Breached and Probing lamp states were not visible in pixels. The CSS for them exists and Breached uses hatch + "!" (not colour alone), but these are unverified on pixels.
- Fonts load from Google Fonts; screenshots show Figtree rendering correctly.
- `prefers-reduced-motion` handled in CSS (animations neutralised, live ring shown static).

## Issues
No blockers. Two Majors to fix before build: reconcile the 9-vs-8 fixed count, and raise the Waiting lamp edge to >= 3:1 in DESIGN.md.

**Verdict: PASS**
