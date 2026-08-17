# Design System: Security Vitals

## 1. Overview: The Bench

**Creative north star: a precision instrument bench.**

The console is the bench you set a security control on and press. It is not a
spatial OS, not frosted glass, not a SOC wallpaper. Dark lacquer, one green
filament, hairline rules, and type that can be read from the other side of a
meeting-room table.

This direction replaces the 0.8.x aurora-glass console. The previous surface
borrowed every AI-slop tell at once: a teal/violet light field, nested frost
cards, pill buttons, emoji chrome, and a different colour on every chip. A
world-class security tool does not glow. It *measures*.

**Key characteristics**

- Warm-dark lacquer, never pure black and never navy-purple night.
- HPE green as the single brand accent — primary action and `blocked`.
- A geometric sans + a real mono. No Inter, no Segoe-as-the-only-voice.
- Small radii (4–6px). Hairline strokes. Almost no shadow.
- Colour is a verdict, not decoration. Most of the window is neutral.
- Motion is the emission lane and the signal wire — honest, not ambient.

## 2. Anti-patterns (do not reintroduce)

- Aurora / coloured light-fields behind the glass.
- Drop shadows, outer glows, specular "wet" top edges on every pane.
- Pill-shaped buttons (`radius = height / 2`).
- Emoji in chrome (`🎤`, `⬇`, `☰`, `⟳`, `✓` as a status).
- ALL-CAPS section banners in the accent colour.
- A different chromatic fill on every chip, badge, and rail.
- Nested cards (a tile inside a frosted dialog inside a glowing stage).
- Inter, Roboto, Open Sans, Arial as the UI face.
- Pure `#000` grounds or pure `#888` greys — neutrals are tinted.

## 3. Colour

Tinted neutrals. One accent. Four state inks, used only on the state they name.

| Token | Hex | Role |
|---|---|---|
| `GUI_BG` | `#0c1210` | Window floor — green-black lacquer |
| `GUI_SURFACE` | `#151c19` | Raised pane, header, card body |
| `GUI_PANEL` | `#1a2320` | Command strip, inset chrome |
| `GUI_GRID` | `#2a3530` | Hairline / rule |
| `GUI_INK` | `#e6eee8` | Primary text |
| `GUI_DIM` | `#8a9a91` | Secondary text |
| `GUI_FAINT` | `#6b7a72` | Meta, idle status |
| `GUI_ACCENT` | `#01A982` | Brand, primary CTA, **blocked** |
| `GUI_INFO` | `#7eb8c9` | **allowed** — steel, not electric cyan |
| `GUI_WARN` | `#d4923a` | **ratio** / live-suspect caution |
| `GUI_CRIT` | `#d45a4c` | **error** |
| `GUI_GOLD` | `#c9a84a` | **invalid** / not configured |

`blocked` is green on purpose: enforcement working is the success state of
this product, not a generic "go". Do not recolour it red.

## 4. Type

| Role | Windows | Linux | Fallback |
|---|---|---|---|
| UI | Bahnschrift | Source Sans 3 | Noto Sans Display → DejaVu Sans → Segoe UI |
| Mono | Cascadia Mono | JetBrains Mono | DejaVu Sans Mono → Consolas |

Scale (px): 8 meta · 9 chrome · 10 body · 11 row title · 15 wordmark ·
16 dialog title · 20 signal count / presenter label · 22 presenter verdict.

Wordmark is tracked slightly (`letter`-feel via size, not a second face).
Section labels are sentence case, mono, faint — never a green shout.

## 5. Space and radius

- Radius: controls 4px, panes 6px, dialogs 8px. Never 16–20.
- Card gap 5px, card pad 10px, window gutter 18px.
- Header is a flush instrument strip, not a floating island.
- Elevation is a one-step tint (`GUI_BG` → `GUI_SURFACE` → `GUI_PANEL`) plus
  a hairline. No drop shadow.

## 6. Components

**Primary button.** Fill `GUI_ACCENT`, ink `#04140f`, radius 4. Hover lifts
the fill; no halo.

**Ghost button.** Hairline on `GUI_PANEL`, ink `GUI_INK`. Hover lifts the
fill one step. Keyboard focus is a second inner hairline, not a colour ring
that fights the accent.

**Trigger row.** One surface, left severity rail (2px), title, emission lane,
status. Expand in place for talking point, Fire, and the three detail wells.
Hover brightens the hairline — it does not throw a coloured glow.

**Emission lane.** Host → gate → internet. One dot per on-wire signal. Hold
at the gate until the run returns. `error` scatters; it never draws a block.

**Signal wire.** Header trace that spikes only when a signal leaves this host.
Idle is a flat hairline. That honesty is the product.

**Dialog.** Same lacquer, one raised pane, no backdrop photograph.

**Presenter picker.** A setlist, not a wall of cards. Each row is the profile
name, one-line story, and the committed signal count as the hero number.
Click the row to open the stage. No per-row Present button.

**Presenter stage.** Wall-readable instrument: tracked eyebrow (profile),
20px trigger title, expect / talk / look as a three-line brief, the emission
lane named host · gate · internet, the verdict at 22px, then a bead
scoreboard of what this host observed. Back / Fire / Next hold the pace.

## 7. Motion

One shared clock (`_Anim`). Ease is smoothstep. No bounce, no elastic.
Ambient motion is the heartbeat of the signal wire and is paused when the
window is not focused. A decorative animation that is not reporting a fact
does not ship.

## 8. Writing

- Buttons: `Run all enabled`, `Presenter`, `Save report`, `Signal manifest`.
- Status: `not run`, `disabled (live)`, `not configured`, `running…`.
- Attestation: `Console: not marked` / `confirmed` / `not seen`.
- Tagline: `Inline stack console  ·  local result only`.
