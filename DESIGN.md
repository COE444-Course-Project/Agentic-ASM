---
name: Agentic ASM
description: A control-room annunciator for an attacker and a defender agent taking turns against a growing API.
colors:
  background: "#ffffff"
  surface: "#ffffff"
  fascia: "#f1ecfd"
  fascia-strong: "#e4dbfa"
  border: "#e6e0f5"
  lamp-edge: "#8269d8"
  lamp-idle: "#8a83a3"
  text: "#1e1830"
  text-muted: "#5c5573"
  accent-solid: "#5b3fc0"
  accent-hover: "#4a31a6"
  accent-text: "#5b3fc0"
  accent-mark: "#8b6fe0"
  error-text: "#b8302a"
  error-fill: "#fde8e6"
  error-ink: "#8f211c"
  success-text: "#1f7247"
  success-fill: "#e2f4ea"
  success-ink: "#17583a"
  warning-text: "#94600a"
  warning-fill: "#fdf3dc"
  info-text: "#5b3fc0"
  info-fill: "#efe9fd"
typography:
  display:
    fontFamily: "Figtree, system-ui, -apple-system, Segoe UI, sans-serif"
    fontSize: "3.5rem"
    fontWeight: 700
    lineHeight: 1
    letterSpacing: "-0.01em"
    fontFeature: "tnum"
  stat:
    fontFamily: "Figtree, system-ui, -apple-system, Segoe UI, sans-serif"
    fontSize: "2.5rem"
    fontWeight: 700
    lineHeight: 1.1
    fontFeature: "tnum"
  headline:
    fontFamily: "Figtree, system-ui, -apple-system, Segoe UI, sans-serif"
    fontSize: "1.75rem"
    fontWeight: 700
    lineHeight: 1.2
  number:
    fontFamily: "Figtree, system-ui, -apple-system, Segoe UI, sans-serif"
    fontSize: "1.375rem"
    fontWeight: 700
    lineHeight: 1.2
    fontFeature: "tnum"
  title:
    fontFamily: "Figtree, system-ui, -apple-system, Segoe UI, sans-serif"
    fontSize: "1.125rem"
    fontWeight: 700
    lineHeight: 1.3
  body:
    fontFamily: "Figtree, system-ui, -apple-system, Segoe UI, sans-serif"
    fontSize: "1rem"
    fontWeight: 400
    lineHeight: 1.5
    fontFeature: "tnum"
  label:
    fontFamily: "Figtree, system-ui, -apple-system, Segoe UI, sans-serif"
    fontSize: "0.875rem"
    fontWeight: 500
  caption:
    fontFamily: "Figtree, system-ui, -apple-system, Segoe UI, sans-serif"
    fontSize: "0.75rem"
    fontWeight: 500
    lineHeight: 1.3
  mono:
    fontFamily: "ui-monospace, SF Mono, Menlo, Consolas, monospace"
    fontSize: "0.875rem"
    lineHeight: 1.55
rounded:
  lamp: "6px"
  panel: "14px"
  control: "999px"
spacing:
  space-1: "4px"
  space-2: "8px"
  space-3: "12px"
  space-4: "16px"
  space-5: "24px"
  space-6: "32px"
  space-7: "48px"
components:
  button-primary:
    backgroundColor: "{colors.accent-solid}"
    textColor: "{colors.surface}"
    typography: "{typography.body}"
    rounded: "{rounded.control}"
    padding: "0 24px"
    height: "40px"
  button-primary-hover:
    backgroundColor: "{colors.accent-hover}"
    textColor: "{colors.surface}"
  button-secondary:
    backgroundColor: "{colors.surface}"
    textColor: "{colors.accent-text}"
    rounded: "{rounded.control}"
    padding: "0 24px"
    height: "40px"
  button-secondary-hover:
    backgroundColor: "{colors.fascia}"
    textColor: "{colors.accent-text}"
  button-text:
    textColor: "{colors.accent-text}"
    rounded: "{rounded.control}"
    padding: "0 12px"
    height: "40px"
  button-text-hover:
    backgroundColor: "{colors.fascia-strong}"
  chip-target:
    backgroundColor: "{colors.fascia}"
    textColor: "{colors.text}"
    rounded: "{rounded.control}"
    padding: "0 16px"
    height: "40px"
  chip-target-hover:
    backgroundColor: "{colors.fascia-strong}"
  input-field:
    backgroundColor: "{colors.surface}"
    textColor: "{colors.text}"
    rounded: "{rounded.lamp}"
    padding: "0 12px"
    height: "40px"
  panel:
    backgroundColor: "{colors.fascia}"
    rounded: "{rounded.panel}"
    padding: "24px"
  lamp-waiting:
    backgroundColor: "{colors.surface}"
    textColor: "{colors.text}"
    rounded: "{rounded.lamp}"
    padding: "8px 8px 8px 12px"
    height: "84px"
  lamp-probing:
    backgroundColor: "{colors.info-fill}"
  lamp-breached:
    backgroundColor: "{colors.error-fill}"
    textColor: "{colors.error-ink}"
  lamp-fixed:
    backgroundColor: "{colors.success-fill}"
    textColor: "{colors.success-ink}"
  lamp-secure:
    backgroundColor: "{colors.surface}"
    textColor: "{colors.success-ink}"
  lamp-unclear:
    backgroundColor: "{colors.warning-fill}"
    textColor: "{colors.warning-text}"
  scoreboard-row:
    backgroundColor: "{colors.surface}"
    rounded: "{rounded.lamp}"
    padding: "12px"
  evidence-before:
    backgroundColor: "{colors.error-fill}"
    textColor: "{colors.error-ink}"
    rounded: "{rounded.lamp}"
    padding: "16px"
  evidence-after:
    backgroundColor: "{colors.success-fill}"
    textColor: "{colors.success-ink}"
    rounded: "{rounded.lamp}"
    padding: "16px"
  kind-tag:
    backgroundColor: "{colors.info-fill}"
    textColor: "{colors.info-text}"
    typography: "{typography.caption}"
    rounded: "{rounded.control}"
    padding: "1px 8px"
---

# DESIGN — Agentic ASM dashboard

Status: **locked** 2026-11-15 (light purple on white confirmed by the user; Annunciator Panel direction chosen on the decision page).
Pins: primary hue light purple · ground white · direction Annunciator Panel (seed 4676d823).

Recorded from the shipped `gui/static/index.html` (finish review: ship). The frontmatter and the `:root` block below mirror the built stylesheet exactly; where this file and the build ever disagree, the build is the truth and this file is stale.

## Overview

**Creative North Star: "The Annunciator Panel"**

### Direction
A control-room annunciator. Collections are white enamel lamp windows set into a lavender fascia; the loop is one circle line with five stations. Colour lives on lamps and data, the purple fascia frames them, everything else is ink on white.

The page is read from the back of a classroom, so density is moderate and every state is spelled out: a lamp carries its template code, collection number, a drawn mark and its state in words, never colour alone. The surface is flat. Lavender panels sit on a white ground without borders or shadows; the only lifted object is the right-hand drawer. Motion exists only to report a change of state (a lamp flipping, the train moving to the live station, a round row stamping in) and disappears under reduced motion.

**Key Characteristics:**
- White ground, lavender fascia panels (14px corners), white enamel lamps (6px corners), pill controls.
- One workhorse sans (self-hosted Figtree, variable 400–700) with tabular figures everywhere; monospace only for real code.
- Six lamp states, each with fill, edge, drawn SVG mark and printed state word.
- One filled purple button per pane; everything else outline or text.
- Flat at rest; the drawer is the only shadowed element.

## Colors

Ink on white, framed in lavender, with saturated colour reserved for lamp states and the data they report.

### Tokens
```css
:root {
  /* ground and fascia */
  --background: #ffffff;
  --surface: #ffffff;
  --fascia: #f1ecfd;        /* light purple panels */
  --fascia-strong: #e4dbfa; /* selected / pressed fascia, non-text */
  --border: #e6e0f5;
  --lamp-edge: #8269d8;     /* non-text, 4.23:1 white, 3.66:1 fascia, 3.19:1 fascia-strong */
  --lamp-idle: #8a83a3;     /* waiting-lamp outline, 3.59:1 white */
  /* ink */
  --text: #1e1830;          /* 17.1:1 white */
  --text-muted: #5c5573;    /* 7.0:1 white, 6.1:1 fascia */
  /* purple */
  --accent-solid: #5b3fc0;  /* buttons; white text 7.2:1 */
  --accent-hover: #4a31a6;
  --accent-text: #5b3fc0;   /* links, 7.2:1 white */
  --accent-mark: #8b6fe0;   /* non-text marks only, 3.85:1 white */
  /* functional */
  --error-text: #b8302a;  --error-fill: #fde8e6;  --error-ink: #8f211c;
  --success-text: #1f7247; --success-fill: #e2f4ea; --success-ink: #17583a;
  --warning-text: #94600a; --warning-fill: #fdf3dc;
  --info-text: #5b3fc0;    --info-fill: #efe9fd;
  /* type */
  --font: "Figtree", system-ui, -apple-system, "Segoe UI", sans-serif;
  --text-xs: 0.75rem; --text-sm: 0.875rem; --text-base: 1rem; --text-lg: 1.125rem;
  --text-xl: 1.375rem; --text-2xl: 1.75rem; --text-3xl: 2.5rem; --text-4xl: 3.5rem;
  /* space and shape */
  --space-1: 4px; --space-2: 8px; --space-3: 12px; --space-4: 16px; --space-5: 24px; --space-6: 32px; --space-7: 48px;
  --radius-lamp: 6px; --radius-panel: 14px; --radius-control: 999px;
  /* motion */
  --dur-fast: 160ms; --dur-state: 320ms; --dur-travel: 900ms; --stagger: 40ms;
  --ease-out: cubic-bezier(.2,.7,.2,1); --ease-in-out: cubic-bezier(.6,0,.3,1);
  /* derived (no new colours: mixes of locked tokens only) */
  --mono: ui-monospace, "SF Mono", Menlo, Consolas, monospace;
  --scrim: color-mix(in srgb, var(--text) 35%, transparent);
  --white: var(--surface);
}
```
Contrast: every text pair is ≥4.5:1 on white and on `--fascia` (lowest shipped text pair: warning text on warning fill, 4.83:1). Status text never sits on `--fascia-strong`. `--accent-mark`, `--lamp-edge` and `--lamp-idle` are non-text only.

### Primary
- **Annunciator Violet** (`accent-solid`): the one filled button per pane, the focus ring, the live station, the train dot, the selected-tab underline, checkbox accent. `accent-hover` is its pressed/hover shade; `accent-text` is the same violet for links and outline-button labels.
- **Soft Violet Mark** (`accent-mark`): non-text marks only: completed stations, the probing lamp edge and sweep bar, the in-progress scoreboard row edge, the brand mark's track.

### Neutral
- **Enamel White** (`background`, `surface`, aliased `--white`): page ground, lamp windows, scoreboard rows, inputs, drawer, popover.
- **Lavender Fascia** (`fascia`): every panel (run console, loop stage, lamp wall, scoreboard), the target chip, secondary-button hover, "plain" evidence boxes.
- **Pressed Lavender** (`fascia-strong`): chip and text-button hover, the scoreboard totals rule, console tab rule, text selection.
- **Hairline Lilac** (`border`): table rules, finding separators, drawer section rules, popover outline.
- **Lamp Edge Lilac** (`lamp-edge`): loop track and station outlines, input strokes, "new" notch, waiting scoreboard rows (dashed), log scrollbar.
- **Idle Grey-Violet** (`lamp-idle`): the waiting-lamp outline and the idle status dot.
- **Deep Ink** (`text`) and **Muted Ink** (`text-muted`): body and secondary text.

### Functional
- **Breach Red** (`error-text` edge, `error-fill` ground, `error-ink` words): breached lamps, the "reverted" notch, the attack station tint, before-evidence boxes, regression counts, error status.
- **Repair Green** (`success-text` edge, `success-fill` ground, `success-ink` words): fixed and secure lamps, the defend station tint, after-evidence boxes, the running status dot.
- **Caution Amber** (`warning-text`, `warning-fill`): unclear lamps and evidence, VAmPI notes, stopped rounds, warning log lines.
- **Info Violet** (`info-text`, `info-fill`): probing lamps, the LLM kind tag, the flash on a finding opened from a lamp.

### Named Rules
**The Derived-Only Rule.** No colour exists outside the token block. New needs are met with `color-mix()` of existing tokens (the scrim at 35% ink, the drawer shadow at 16% ink), never a new hex.

**The Lamp-Owns-Colour Rule.** Red, green and amber appear only where they report a verdict (lamps, station tints, evidence, counts, status). Chrome stays violet, lavender and ink.

## Typography

**Display / Body Font:** Figtree (self-hosted variable woff2, weights 400–700, latin and latin-ext subsets, `font-display: swap`, latin preloaded), falling back to system-ui, -apple-system, Segoe UI, sans-serif.
**Label/Mono Font:** ui-monospace, SF Mono, Menlo, Consolas, monospace, for endpoints, evidence, URLs and log timestamps only.

**Character:** One friendly geometric workhorse doing every job, with tabular figures set on `body` so every number in the page aligns and never jitters as it updates.

### Hierarchy
- **Display** (700, 56px, line-height 1, -0.01em): the round number on the loop stage ("Round 2 of 4", the "of 4" in muted 500). Drops to 40px under 760px.
- **Stat** (700, 40px, 1.1): the two scoreboard totals (fix rate, real users OK). 28px under 760px.
- **Headline** (700, 28px, 1.2): the live phase name.
- **Number** (700, 22px, 1.2): lamp collection numbers and scoreboard row figures; also the brand wordmark.
- **Title** (700, 18px, 1.3): panel headings, findings group headings; the phase sentence uses 18px at 400 (max 44ch).
- **Body** (400, 16px, 1.5): running text, buttons (500).
- **Label** (500, 14px, sentence case): field labels, column heads, legend, notes (max 56ch), console status.
- **Caption** (500, 12px): lamp state words, notches, LLM tag.
- **Mono** (14px, 1.55 in evidence): real code only.

### Named Rules
**The Tabular Rule.** Every figure is tabular (`font-variant-numeric: tabular-nums` on body). Never switch numbers to proportional.

**The Sentence-Case Rule.** Labels, tabs and buttons are sentence case at 500. No uppercase tracking, no small caps.

## Layout

A centred 1440px column with 24px side padding (16px under 760px). Top bar (brand mark, target chip, Guide), then the run console panel, then the main grid: loop stage and lamp wall stacked in the left two-thirds, the round scoreboard in the right third (`2fr / 1fr`, 16px gap). Findings, attack surface and live log sit below in underline tabs with 48px above and below.

- The loop stage is a 280px SVG circle beside the round and phase text (32px gap); under 760px it stacks and the SVG scales to max 300px.
- The lamp wall is an auto-fill grid of lamps at min 100px (94px under 760px), 8px gaps.
- Spacing steps are the seven tokens (4–48px); panels pad 24px (16px under 760px).
- Breakpoints: 1100px (main grid collapses to one column), 760px (top bar wraps, fields go two-up, primary button goes full width, controls grow to 44px), 420px (fields one-up).

## Elevation & Depth

Flat. Depth comes from tonal layering: white ground, lavender panel, white lamp or row set into the panel. Panels have no border and no shadow; the target popover is white with a 1px hairline and no shadow.

### Shadow Vocabulary
- **Drawer lift** (`box-shadow: -12px 0 32px color-mix(in srgb, var(--text) 16%, transparent)`): only on an open right-side drawer, over the 35% ink scrim.

### Named Rules
**The One-Lift Rule.** The drawer is the only shadowed element. Nothing else casts a shadow, at rest or on hover.

## Shapes

Three radii, each with a job: 6px for anything that is an instrument (lamps, inputs, scoreboard rows, evidence boxes, popover items), 14px for the fascia panels and the popover, a full pill (999px) for controls (buttons, target chip, notches, the LLM tag). Lamp edges are 2px (1px for secure), dashed for unclear; waiting rounds use a 1px dashed lilac edge, stopped rounds 1px dashed amber.

The brand mark and the loop stage share one silhouette: a circle line carrying five stations, one filled as live.

## Components

### Buttons
- **Shape:** pill (999px), min height 40px (44px under 760px), 24px side padding, 500 weight.
- **Primary:** violet fill, white label, 2px violet border; one per pane (Start loop, Run assessment, Defend once, Grow to limit). Hover deepens to `accent-hover`.
- **Secondary:** white with a 2px violet border and violet label; hover fills lavender.
- **Text:** no border, 12px padding; hover fills pressed lavender.
- **Disabled:** 45% opacity, not-allowed cursor.
- **Focus (all interactive):** 2px violet outline, 2px offset.
- **Links:** violet 500, underlined with 3px offset (Show evidence).

### Target chip and popover
Lavender pill holding a status dot (green running, pulsing at 1.6s; idle grey-violet; red on error), the target name at 500 and the URL in muted mono, ellipsised. Opens a 360px white popover (14px, 1px hairline) of targets; selected and hovered items fill lavender.

### Inputs / Fields
- **Style:** white, 1px `lamp-edge` stroke, 6px corners, 40px tall, label above at 14/500.
- **Focus:** the global violet ring.
- Checkboxes are 18px with the violet accent colour.

### Tabs
Underline tabs: muted 500 at rest, ink 700 with a 2px violet underline when selected, 44px tall, over a 1px rule (pressed lavender inside the console). Count chips sit inline in muted 500.

### Lamp states (never colour alone)
| State | Fill | Edge | Mark | Word |
|---|---|---|---|---|
| Waiting | white | 2px `--lamp-idle` | none | Waiting |
| Probing | `--info-fill` | 2px `--accent-mark` | sweep bar along the bottom edge | Probing |
| Breached | `--error-fill` | 2px `--error-text` | diagonal hatch (16%) + warning-triangle "!" SVG | Breached |
| Fixed by defender | `--success-fill` | 2px `--success-text` | shield-check SVG | Fixed by defender |
| Secure (never vulnerable) | white | 1px `--success-text` | none | Secure |
| Unclear | `--warning-fill` | 2px dashed `--warning-text` | dashed-circle "?" SVG | Unclear |

Lamp anatomy: template code top-left (14/700), mark top-right (18px SVG), collection number centred (22/700, zero-padded), state word at the foot (12/500, tinted ink for its state). Min height 84px. New lamps carry a "new" pill notch over the top-right edge (lilac edge, muted text); drifted (regressed) lamps carry a "reverted" notch over the top-left (red edge, red ink). The legend under the wall repeats each state as a 22×16 swatch with the same mark.

### Loop line
SVG circle (r 80) in a 4px lilac track with five 10px stations: grow, discover, attack, defend, verify. Completed stations fill soft violet, the live station fills violet with an expanding ring and a 700-weight label, the train is a 7px violet dot with a white 3px stroke. Station tints report the lamp wall: the attack station turns red while any lamp is breached; the defend station turns green when a lamp is fixed (during defend and verify, or when idle).

### Round scoreboard
Lavender panel: two stat totals over a pressed-lavender rule, a four-column head (Found, Fixed, New exposure, Regressions), then one white 6px row per round with figures at 22/700 (regressions in red when non-zero). Waiting rounds are transparent with a dashed lilac edge, the in-progress round has a soft-violet edge, a stopped round a dashed amber edge.

### Counting rule
The scoreboard's fix rate counts **repairs** (a regression re-fixed counts again) and always says so beneath the figure, one line per fact: "N of M repairs verified", then "K were regressions" when any were, then "J fixed before this loop" when idle. The lamp wall counts collections ("12 collections"). Never show the two as the same unit; unclear collections are noted as "not counted as safe".

### Evidence panels
6px boxes with a 1px edge and 16px padding, a 14/700 heading and pre-wrapped mono evidence. Before: error fill, red edge, "Before: the attack worked". After: success fill, green edge, "After: blocked, real users still work". Shown side by side for fixed findings (stacked under 760px). Unclear uses amber; plain (LLM cross-checks) uses lavender with a lilac edge. LLM findings carry a pill "LLM" tag in info violet.

### Drawers
Right-side sheet, min(520px, 100vw), white, slides in over 320ms on the ease-out curve with the 35% ink scrim; sections separated by hairlines. Guide and Lab controls.

### Motion
Motion only reports state.
- Lamp change: 320ms colour and border transition plus a 1.06 → 1 scale settle; new lamps enter from 0.9 scale and 0 opacity. Changes stagger in collection order at 40ms, capped so a full wall finishes within about 1.2s.
- Train dot travels the circle between stations in 900ms (cubic in-out).
- Live station ring expands to 2.1× and fades on a 1.6s loop; the running status dot pulses at 1.6s.
- Probing sweep bar runs on a 700ms loop.
- Scoreboard row stamps in once (scale 1.15 → 1, 220ms).
- Hovers: 160ms.
- `prefers-reduced-motion`: animations and transitions collapse to instant, the train jumps, lamps switch without stagger, rows do not stamp, and the live ring holds as a static halo (60% opacity, 1.6× scale) so the live station stays marked.

## Do's and Don'ts

### Do:
- **Do** give every lamp state its fill, edge, drawn SVG mark and printed word together.
- **Do** keep one filled violet button per pane; secondary actions are outline, tertiary are text.
- **Do** set every figure tabular and every label in sentence case at 500.
- **Do** derive any new tint with `color-mix()` from the token block.
- **Do** label the fix-rate unit as repairs and the lamp-wall unit as collections.
- **Do** keep 40px minimum control height (44px under 760px) and the 2px violet focus ring.

### Don't:
- **Don't** shadow anything except an open drawer.
- **Don't** put borders on fascia panels.
- **Don't** use red, green or amber for chrome; they belong to verdicts.
- **Don't** render an unclear result as safe or blend patched (fixed by defender) with secure.
- **Don't** use monospace for anything that is not real code, URLs or timestamps.
- **Don't** use glyph or emoji icons; marks are inline SVG drawn in `currentColor`.
