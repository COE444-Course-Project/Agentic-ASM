# JOURNEY — Agentic ASM live dashboard

## Job
When I present our project to the class, I want the screen to show the attacker and defender taking turns against a growing API, so the audience understands the loop and trusts the results without me narrating every line.

## Journey (demo time)
1. **Set up (30 s).** Presenter picks the Custom API lab target, resets the lab if needed. Audience sees an empty lamp wall with an invitation to start.
2. **Start the loop.** Presenter sets rounds / growth / drift and presses Start loop.
3. **Watch a round (about 5 s each with phase pacing).** Loop line lights Grow → Discover → Attack → Defend → Verify. New lamps appear (grow), attacker sweeps lamps (probing pulse), breaches light red, defender patches them green, verifier confirms.
4. **Read the outcome.** Scoreboard stamps each round: Found, Fixed, New exposure, Regressions, Real users OK. Totals show the Fix rate.
5. **Dig into evidence (on request).** Click a lamp or open Findings to see the before/after HTTP evidence; open the log.
6. **Single actions (team use).** Assess once, Defend once, VAmPI assessment with LLM, lab growth controls.

## IA (top to bottom)
1. Top bar: mark + name, target picker chip, Guide.
2. Run console: mode tabs (Closed loop · Assess once · Defend once), their fields, primary action, Stop, status.
3. Loop stage: loop line (5 stations + travelling dot), round N of M, phase name + plain sentence.
4. Lamp wall (left, 2/3) + Round scoreboard (right, 1/3).
5. Detail tabs: Findings · Attack surface · Live log.
6. Lab controls drawer (Custom API lab only) and Guide drawer.

## Page specs

### Page: Dashboard (`/`)
| Region | Content | Empty | Running | Done | Stopped / error |
|---|---|---|---|---|---|
| Top bar | Mark, "Agentic ASM", target chip (label + URL), Guide button | Static: shows the default target | Status dot pulses | Static | Dot turns red on error |
| Run console | Tabs: Closed loop (rounds 1–20, new scenarios per round 0–50, drift 0–20, phase pacing), Assess once (type, model, LLM-sampled checks), Defend once. Start/Run button, Stop, Reset results (asks for confirmation) | Defaults filled, status "Ready." | Primary disabled, Stop enabled, status "Running round 2 of 4 · Attack" | Primary re-enabled, status "Loop finished." | Stopped: "Loop stopped." Error: "Error: <message from the server>" in red, with the cause; recovery: correct the field or target the message names and press the button again, or open Live log for detail |
| Loop stage | Circle line with stations Grow, Discover, Attack, Defend, Verify; live station lit; dot travels; big "Round 2 / 4"; one plain sentence for the phase | "No loop yet. Start one to watch the attacker and defender take turns." | Live station lit and named | "Loop finished: 13 found, 13 fixed and verified, 0 still open after the last round" (plus "N unclear, not counted as safe" when any check could not run) and the saved report path | Stopped by the presenter: "Loop stopped" with the same counts so far. Error: "Loop failed" with the error text |
| Lamp wall | One lamp per collection: template code, number, state (shape mark + text label, never colour alone) | "The lab has no collections yet. Grow it from Lab controls, or start a loop." | New lamps enter on Discover; all lamps show Probing for a moment on Attack/Verify, then flip to their real result one by one | Final results | Each lamp keeps its last real result; nothing stays in Probing once the run ends |
| Scoreboard | Totals (Fix rate, Real users OK), one stamped row per round. With no loop for this target the totals show "Breached now" and "Fixed by defender" counts instead | "Start a loop to fill this scoreboard round by round."  | Current round row "In progress · <phase>", later rounds "Waiting" | All rows filled | Unfinished round row says "Stopped before it finished"; unrun rounds say "Not run". On an error the rows keep the finished rounds and the loop stage shows the error text |
| Findings tab | Breached now / Fixed by defender (before vs after evidence) / Unclear / LLM-sampled cross-checks; secure count | "No findings yet. Run an assessment or start a loop." | Updates as each collection is checked | Static | Static (keeps last results) |
| Attack surface tab | Endpoint table METHOD + path + note | "Run an assessment to discover endpoints." | Refreshes when Discover finishes | Static | Static |
| Live log tab | time, agent, message | "Nothing logged yet." | Autoscrolls when already at the bottom | Static | Warnings in amber |
| Lab drawer | collections count, seed, max, probability, interval, paused, templates, Grow to limit, Apply, Refresh, Reset to 0 (asks for confirmation) | "Not loaded yet." then loads | Grow and Reset disabled during a run | "Grew to 15 collections (+15)." | Error line names the cause (e.g. "Could not reach <url>"); recovery: start the lab container, then press Refresh |
| Guide drawer | What you are watching, the loop, reading the lamps, reading the scoreboard, targets, 8 templates, LLM sampling, lab controls, timing | Static | Static | Static | Static |

VAmPI target selected: the Closed loop and Defend once tabs show "The defender and loop work on the Custom API lab. VAmPI runs the LLM attacker only." with their button disabled; the Lab controls button is hidden because VAmPI has no growth controls. The Loop stage reads "This target runs single assessments. Choose the Custom API lab to run the loop." The Scoreboard shows "Breached now" / "Fixed by defender" counts with the note "Round results appear when you run the loop on the Custom API lab." The lamp wall is titled "Attack checks" and shows one lamp per VAmPI check.

## Control-to-region mapping
| Existing control | Region |
|---|---|
| Target select + custom URL | Top bar target chip (popover) |
| Assessment type, Ollama model, LLM-sampled checks | Run console › Assess once |
| Run assessment | Run console › Assess once › Run assessment |
| Stop | Run console (all tabs) |
| Reset state | Run console overflow ("Reset results") |
| Max collections, vulnerability probability, auto-grow interval, paused, templates | Lab drawer |
| Grow to limit, Apply settings, Refresh, Reset to 0 | Lab drawer |
| Findings (breached, fixed by defender with before/after, unclear) | Findings tab |
| Attack surface | Surface tab |
| Live log | Log tab |
| Guide | Top bar › Guide drawer |
| (new) Run mode tabs: Closed loop / Assess once / Defend once | Run console tab row |
| (new) Start loop | Run console › Closed loop › Start loop |
| (new) Defend once | Run console › Defend once › Defend once |
| (new) Closed loop rounds / growth / drift / pacing | Run console › Closed loop |
Unmapped controls: 0.

## Microcopy
Phases: **Grow** "The API adds new scenarios." · **Discover** "Scout reads the API's endpoint list." · **Attack** "The attacker tries every collection as another user." · **Defend** "The defender switches on a fix, replays the attack, and checks real users still work." · **Verify** "A fresh attacker run checks the fixes held."
Lamp and finding states (identical words on lamps, Findings groups, the Guide and the log summaries):
- **Waiting**: the attacker has not tried this collection yet.
- **Probing**: the attacker is sending its requests to this collection right now.
- **Breached**: the attack worked: one test user read or changed the other user's data (Findings group "Breached now").
- **Fixed by defender**: the defender switched on a fix, the same attack was blocked, and real users still work.
- **Secure**: the attack never worked; no fix was needed.
- **Unclear**: the check could not run cleanly, so we do not know. Never counted as safe.

Other words used on the page:
- **Drift**: at the start of a round, some fixes are switched off on purpose to imitate a bad deploy, so the loop can show it notices and fixes them again.
- **LLM-sampled checks**: extra attacks where a local AI model (an LLM, here qwen2.5 via Ollama) decides the request itself; results are graded from the real responses.
Scoreboard terms (the same words everywhere on the page and in the Guide):
- **Collection**: one small group of API endpoints the lab added, owned by two test users (Alice and Bob).
- **Endpoint**: one web address the API answers, like `GET /documents/1`.
- **Found**: breaches the attacker confirmed this round.
- **Fixed**: of those, how many have a verified fix that still held on the fresh attacker run.
- **New exposure**: collections that were vulnerable the first time they appeared.
- **Regressions**: collections that were secure last round and breached now (for example after drift).
- **Fix rate**: verified repairs divided by everything found, across all rounds. A regression fixed again counts as another repair, and the subline says so. When nothing has been found it shows "n/a", never 100%.
- **Real users OK**: legitimate-use checks that still pass after the fixes (two per collection).
