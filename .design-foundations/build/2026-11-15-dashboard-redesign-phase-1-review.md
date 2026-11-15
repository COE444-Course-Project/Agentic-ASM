# Design Review: Phase 1 - Dashboard redesign (spec-only)

## Rendered Evidence (Step 0)
- Screenshot: none. The artifact is a spec (`JOURNEY.md`), not a rendered surface. Structure-level critique only; pixel-level contrast, spacing and hierarchy are unverified.
- Surface: `/Users/ahmed/University/Computer Security/CS Project/agentic-asm/JOURNEY.md`, reviewed as it is on disk today. Line numbers refer to that file.
- Coverage note: the previous review at this output path cites text that is not in the current file (for example "Exploitable", "remediation rate", "thirteen blank state cells"), and its DW-1.2 FAIL is contradicted by current lines 54–55 (mode tabs and Start loop rows exist). That review was overwritten. All findings below were re-derived from the current file.

## Assessment B — Deterministic Detector
- Command: `node /Users/ahmed/.claude/plugins/cache/rtd/design-for-ai/4.2.0/scripts/detect.mjs > <scratchpad>/detect-phase1-na.json` (no HTML or mock path supplied).
- Exit: 3 (N/A, no rendered artifact). This is the no-artifact carve-out, not a skipped detector. The output was written to the scratchpad so the existing `detect.json` in the build folder is untouched.
- Findings: N/A — no rendered artifact. The JSON status is `"na"` with zero findings.
- Opened only after Assessment A findings were frozen: YES. The JSON was printed by the same shell command that ran it, after the A findings had been drafted; it held no findings, so nothing could anchor on it.

## Triage
- Baseline (always-on): visual + usability. No pixels exist, so only structural and spec-level visual checks applied. Distinctiveness criterion: N/A (no visual surface).
- Dispatched: `usability` (run console, mode tabs, stop and reset, drawers, error recovery); `content-design` (phase sentences, tile states, scoreboard terms, error copy); `journey` (page-spec states, VAmPI and empty-state routes).
- Not applicable: `behavioral` and `deceptive-patterns` (no persuasion surface).
- Signal present, not dispatched: `data-viz` (scoreboard totals and lamp counts encode numbers). Noted, not scored.
- Deferred: none.

## Cross-Pillar Findings (ONE ranked report)
| Severity | Pillar | Problem | Principle | Fix |
|----------|--------|---------|-----------|-----|
| Critical | journey / usability | VAmPI edge case is only partly handled. The Loop stage empty copy (line 29) says "Start one to watch the attacker and defender take turns," but on VAmPI the Start control is disabled (line 38). The Lab drawer is limited to "Custom API lab only" (IA, line 20) with no explanation on VAmPI, so it is hidden rather than explained. | Edge-case rule "explain, don't hide"; Nielsen #1 visibility of system status | Add a VAmPI variant of the Loop stage and Scoreboard empty copy with the same sentence as line 38. Show the Lab drawer in a disabled state that carries the same explanation. |
| Major | content-design | The loop-finished summary (line 29) says "0 still open after the last round" but never mentions Unclear results. The spec says Unclear is "Never counted as safe" (line 68), so a run with Unclear checks can read as fully resolved on the summary line. | Nielsen #1 visibility of system status; the spec's own Unclear rule (line 68) | Add the Unclear count to the summary, e.g. "0 still open, 2 unclear (not checked cleanly)." |
| Minor | content-design | Found, Breached and Breached now name the same concept. Scoreboard "Found" (line 76) is defined as breaches confirmed; the tile is "Breached" (line 65); the Findings group is "Breached now" (line 50). A classmate may read these as three things. | Nielsen #4 consistency; Podmajersky (one vocabulary) | State "Found = Breached" once in the glossary, or use one word everywhere. |
| Minor | content-design | Three names for resets: "Reset results" (Run console, line 28), "Reset to 0" (Lab drawer, line 49, which deletes collections), and "Reset state" (mapping, line 47). Scope differs between them. | Nielsen #4 consistency; name by what is deleted | Name each by its effect, e.g. "Clear results" and "Delete all collections." |
| Minor | content-design | The Loop failed state (line 29) shows "Loop failed" plus raw server error text, with no recovery step. The Run console (line 28) does give recovery, so the user is not dead-ended, but the stage-level message is not self-sufficient. | Yifrah cause + fix formula (content-design Rules) | Add one recovery line to the Loop failed copy, or point to the Run console recovery. |
| Minor | usability | The Top bar status dot turns red on error (line 27) with no text label. The spec's "never colour alone" rule (line 30) applies only to lamps. | WCAG 1.4.1 Use of Color (usability accessibility) | Pair the red dot with text, e.g. "Error" beside the dot. |
| Minor | usability | No live-status rule. Phase changes, Stop and errors update the run status line (line 28) with no stated announcement to assistive technology. | WCAG 4.1.3 Status Messages | State that the run status line is a polite live region. |
| Minor | journey | Stopped mid-round: lamps "keep their last real result" (line 30). A lamp that appeared on Discover and was never attacked has no last real result. The spec does not say what it shows. | journey.md §F (states must be complete) | Specify "Waiting" for lamps never tested when the run stopped. |

## Requirement Fulfillment

### DW-1.1
PREMISE:  "JOURNEY.md `## Page specs` has a complete entry for the dashboard with every region and its empty/running/done/error state"
EVIDENCE: The Dashboard table (lines 25–36) has ten regions and four state columns (Empty, Running, Done, Stopped / error), and every cell is filled. Examples: Run console line 28, "Stopped: 'Loop stopped.' Error: 'Error: <message from the server>' in red"; Loop stage line 29, "No loop yet. Start one to watch…" (empty) and "Loop failed" with error text (error); Scoreboard line 31, "On an error the rows keep the finished rounds and the loop stage shows the error text"; Lab drawer line 35, "Could not reach <url>… recovery: start the lab container, then press Refresh." The Top bar has no separate Stopped copy (line 27), which is a note, not a gap against the four named states.
VERDICT:  PASS

### DW-1.2
PREMISE:  "JOURNEY.md contains a control-to-region mapping table with zero unmapped controls from this list: target picker + custom URL, mode, model, LLM sample, Assess / Defend / Loop / Stop / Reset state, lab growth controls (max, probability, interval, paused, templates, grow, apply, refresh, reset), findings (exploitable / corrected before-after / inconclusive), attack surface, live log, guide drawer."
EVIDENCE: Mapping table, lines 41–58. Target + custom URL → line 43. Mode → line 54 ("(new) Run mode tabs"). Model and LLM-sampled checks → line 44. Assess → line 45. Defend → line 56. Loop → line 55 (Start loop) and line 57 (rounds/growth/drift/pacing). Stop → line 46. Reset state → line 47. Lab max, probability, interval, paused, templates → line 48. Grow, apply, refresh, reset → line 49. Findings → line 50 (before/after and unclear; spec wording "breached / fixed by defender / unclear" is the plain-language form of the requirement's "exploitable / corrected / inconclusive"). Attack surface → line 51. Live log → line 52. Guide → line 53. Line 58 states "Unmapped controls: 0," and each listed control has a row.
VERDICT:  PASS (note: "mode" is only mapped through a row marked "(new)", so the spec does not show that an existing mode control was carried over. This does not break the zero-unmapped claim.)

### DW-1.3
PREMISE:  "Microcopy for phases, tile states and scoreboard metrics reviewed jargon-free (each term understandable by a non-security classmate)"
EVIDENCE: Phases (line 61): "Grow 'The API adds new scenarios.'", "Discover 'Scout reads the API's endpoint list.'", "Attack 'The attacker tries every collection as another user.'", "Defend 'The defender switches on a fix, replays the attack, and checks real users still work.'", "Verify 'A fresh attacker run checks the fixes held.'" Tile states (lines 63–68) each have a plain-language sentence, including "Probing: the attacker is sending its requests to this collection right now" (line 64) and "Unclear: the check could not run cleanly, so we do not know. Never counted as safe." (line 68). Scoreboard metrics (lines 74–81) each have a definition: Collection, Endpoint, Found, Fixed, New exposure, Regressions, Fix rate (n/a rule), Real users OK. Outside the three listed sets, the spec still uses terms a classmate may not know: "LLM", "Ollama", "qwen2.5" (line 72), "Closed loop" (line 54/57), "Assess once", "METHOD" (attack surface), "HTTP evidence" (Journey step 5). These are outside DW-1.3's stated scope and are not scored.
VERDICT:  PASS

## Edge cases — verify handling
- VAmPI target selected (loop/defend unavailable → explain, don't hide): FAIL. Line 38 explains the disabled tabs ("The defender and loop work on the Custom API lab. VAmPI runs the LLM attacker only."), which is correct. But the Loop stage empty copy (line 29) and the Scoreboard empty copy (line 31) still invite a Start the disabled control does not allow, and the Lab drawer is hidden with no explanation (line 20 IA). The edge case is therefore left partly unhandled.
- No loop ever run (empty stage invites first run): PASS. Line 29 "No loop yet. Start one to watch the attacker and defender take turns."; line 31 "Start a loop to fill this scoreboard round by round."
- Loop stopped mid-round: PASS. Line 29 "Stopped by the presenter: 'Loop stopped' with the same counts so far."; line 31 "Unfinished round row says 'Stopped before it finished'"; line 30 "nothing stays in Probing once the run ends." Note: a lamp with no real result yet is not covered (see Minor row).
- Error from backend: PASS. Line 28 shows the error in red with the cause and recovery; line 29 "Loop failed" with error text; line 31 keeps finished rounds; line 35 names the cause and gives recovery. Note: the stage-level error has no recovery line.
- 0 vulnerabilities in a round (rate N/A, not 100%): PASS. Line 80 "When nothing has been found it shows 'n/a', never 100%." The rate is cumulative, and no per-round rate is shown, so no per-round 100% can appear. Note: the copy for a zero-found round is not specified, and the fix rate definition applies across all rounds, not per round.

**All requirements met:** YES (DW-1.1, DW-1.2, DW-1.3 PASS). One edge case FAILS (VAmPI).

## Notes (non-blocking)
- Spec-only artifact: no pixels. Colour, spacing, contrast and hierarchy are unverified. Visual findings are structural only.
- Visual distinctiveness criterion not applied (no visual surface yet).
- The `data-viz` signal (scoreboard totals, lamp counts) was not in the dispatched doctrine list. Recommend a data-viz pass on the scoreboard before the visual phase.
- The Guide drawer copy (line 36) is not written, so the "same words everywhere… in the Guide" rule (line 73) cannot be verified.
- Lamp shape plus text label, not colour alone (line 30), is a sound accessibility decision and is recorded as a pass.
- Naming drift: "Lab controls" (line 30) vs "Lab drawer" (line 35) vs "Lab controls drawer" (IA line 20). Minor, but a classmate may read them as three panels.

## Issues (if FAIL)
1. VAmPI edge case partly unhandled: loop-stage (line 29) and scoreboard (line 31) empty copy invite a disabled Start; Lab drawer hidden without explanation (IA line 20). Critical / journey + usability / Edge-case rule "explain, don't hide"; Nielsen #1 / Add a VAmPI variant of the empty copy and a disabled, explained Lab drawer.

**Verdict: FAIL — blocker: VAmPI edge case (lines 29, 31, IA line 20 vs line 38).**
