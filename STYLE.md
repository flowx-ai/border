# STYLE.md

Visual design brief for the `flowx-border` website.

Read with `LANDING_PAGE.md`. That file governs structure and copy. This one governs
look. Where they conflict, `LANDING_PAGE.md` wins on content and this file wins on
appearance.

---

## 1. Source of truth

These tokens were extracted from the live FlowX site (`/agent-builder`, August 2026).
They are the parent system. Do not invent a new palette.

**Dark, as shipped**

```
--bg          #0a0b0d      base, cool near-black
--bg-panel    #0c0e11
--bg-raised   #0e1013      raised surfaces are LIGHTER than base
--text        #f4f5f3      warm off-white
--lede        #cdd2dc      cool light grey
--spec-ink    #aeb4ba      cool mid grey, used for specs and diagrams
--hero-dim    #8f8f88      warm mid grey
--hero-eyebrow #a3a39a
--amber       #fcb813      single accent
--amber-hi    #ffc739
--amber-ink   #131007      text placed on amber
--danger      #e5484d
--line        rgba(255,255,255,.08)
--line-soft   rgba(255,255,255,.05)
--shadow-card none
```

Typography: **Sora Variable** (display), **Geist Variable** (body), **Geist Mono
Variable** (mono). Keep all three. They carry the FlowX relationship without a logo.

Two structural properties matter more than the colours and must survive the
inversion: **card shadows are none**, and **borders are hairlines at 5 to 8 percent**.
The system is flat and drawn with lines, not with elevation. Do not add shadows to
cards in the light theme.

---

## 2. Light theme, by role swap

Do not "lighten the dark theme". Swap the roles of the two anchor colours. The dark
theme is cool background with warm text. The light theme is warm paper with cool ink.
That is a principled inversion and it preserves the family resemblance.

```
--paper         #F4F5F3    was --text
--paper-raised  #FFFFFF    raised is lighter, same as dark
--paper-sunk    #EDEEEB    wells and code block backgrounds
--ink           #0A0B0D    was --bg
--ink-lede      #39404A    cool, for standfirst and lede text
--ink-spec      #545C64    cool, for specs, tables, captions
--ink-dim       #6B6B63    warm, for secondary text
--ink-eyebrow   #6B6B63    eyebrows and mono labels
--amber         #FCB813    unchanged, FILL ONLY
--amber-ink     #131007    text on amber fill
--amber-deep    #8A5B00    the only permitted amber for TEXT
--danger        #C4302B    darkened for AA on paper
--line          rgba(10,11,13,.12)
--line-soft     rgba(10,11,13,.07)
--boundary      #FCB813    2px, see section 3
--shadow-card   none
--shadow-pop    0 18px 40px rgba(10,11,13,.10)
```

**The amber rule, non-negotiable.** `#FCB813` on paper is roughly 1.7:1. It may never
be used for text, links, icons on paper, or thin strokes carrying meaning. It is
permitted as: a solid fill with `--amber-ink` text on top, a 2px boundary rule, and a
small marker or dot. For any amber-coloured text, use `--amber-deep`.

Contrast floor is WCAG AA. `--ink-dim` and lighter are for text at 16px and above.

---

## 3. The design concept

The library's governing idea is: **check hard where things cross the boundary, do not
re-inspect inside.** The visual system should enact that, not merely illustrate it.

Four rules follow. They are the whole concept and they are what makes this site not
look like every other developer site.

### 3.1 Boundaries are marked, interiors are not

Every section boundary is a **2px amber rule** running edge to edge. Inside a section
there are **no rules, no card borders, no boxes, no dividers**. Separation inside a
section comes from whitespace and typographic hierarchy alone.

This is the rule that will be hardest to keep, because the default instinct for a
feature list is a bordered card grid. Resist it. The interior is meant to feel open.
A page should read as: hard edge, open space, hard edge, open space.

Hairline `--line` is still permitted for table row rules and code block edges, which
are structural rather than sectional.

### 3.2 Density spikes at the boundary

At a boundary, information density and detail go up: mono eyebrow label, section
number, metadata. Immediately inside, density drops sharply: large display type,
generous leading, few words.

Concretely, every section boundary carries a mono label in `--ink-eyebrow` at 11px,
uppercase, 0.14em tracking, sitting directly on the amber rule. Then whitespace. Then
the section heading in Sora at a large size.

### 3.3 Two heavy moments per page, no more

The library has exactly two crossing points. The page should too. On the home page
those are the install command and the code sample. Everything else is quiet. Resist
giving every section its own visual crescendo.

### 3.4 Mono is measured, sans is asserted

This is the most important typographic rule on the site, and it directly serves the
positioning.

**Anything that is evidence is set in Geist Mono.** Latency figures, accuracy numbers,
model revisions, hashes, detector ids, version strings, dates, file names, policy
keys, the install command, all code.

**Anything that is a claim is set in Sora or Geist.** Headlines, explanations, prose.

The reader should be able to tell at a glance which parts of the page are measured and
which are asserted. On a site whose entire argument is "we produce evidence rather
than promises", this is the design doing the arguing.

---

## 4. The signature element: the stamp

One recurring mark, used sparingly. It represents the signed evidence record.

- A rounded rectangle, 2px `--boundary` border, `--paper-raised` fill, no shadow.
- Contents in Geist Mono at 10 to 11px, `--ink-spec`: detector id, a timestamp, a
  truncated hash, and a verdict word.
- Slight rotation, between 1 and 2 degrees, never more. It should look placed, not
  scattered.
- Appears **once at large size** on the home page beside the code sample, and small in
  the corner of use-case pages. Nowhere else.

**Hard constraints on this element.** No national or institutional imagery. No
circular seals, no stars, no eagles, no flags, no passport pages, no maps, no ink-blot
or distressed texture. It is a clean typographic mark, not a rubber stamp illustration.
If a draft starts to look like a passport, it is wrong and must be redrawn.

---

## 4a. Page heroes, and why they must be identical

Every page opens the same way: a mono eyebrow, an h1, a lede, an optional row of
actions or statistics, and a figure on the right. One component owns this,
`components/PageHero.jsx`, and no page builds its own. Three pages did build their
own and ended up with three different top margins, which is the reason this section
exists.

**The rule that is easy to get wrong.** The hero grid aligns to `start`, not to
`center`. Centring makes the top of the heading depend on how much copy the page
happens to have: a short lede leaves the text column shorter than the figure, the
column gets centred against it, and the heading drops. Measured on this site, that
put `/use-cases` 22px below `/docs` for no reason a reader could perceive. The text
pins to the top and the figure centres itself against it.

| | |
|---|---|
| Component | `PageHero`, one per page, never hand-rolled |
| Top spacing | `clamp(56px, 8vh, 96px)`, from `.page-hero` |
| Grid | `align-items: start`; the figure takes `align-self: center` |
| Full height | Home page only. An interior page has already been chosen. |
| Figure | A `CrossingFigure` variant, never a bespoke drawing |

**The figures are one drawing, not eight.** Ink bars are the checks, the amber run
between them is the verified interior, a small square is a payload crossing. A
variant changes the labels and what happens to the payload: redaction alters it,
regulated advice turns a lane away at the outbound gate, audit evidence issues a
stamp that stays after the payload has gone. A new page picks a variant or adds one
to the same grammar. It does not commission an illustration.

**Interior headings are not section headings.** An h2 inside an article uses
`.article-h2`, which is roughly a third the size of a landing-page section h2.
Without it a step in an argument renders at the same weight as the page title and
the hierarchy goes flat.

---

## 4b. Every new page, before it ships

Discoverability is not a launch task, it is a per-page task, and it is the one that
gets skipped. A page added without these is a page an answer engine never finds and
a link that renders as a bare URL in a Slack channel. All of it is enforced by
`npm run check` in the landing repository, so this list is the explanation rather
than the mechanism.

**1. Register it in `lib/routes.js`.** One entry, with a `summary` of at least 40
characters written as an answer rather than a tease. That file is the source for
the sitemap, for `llms.txt`, and for the coverage check. A page that is not in it
fails the build.

**2. Give it an `opengraph-image.jsx`.** Per page, never one shared default: a
single image means every link to the site looks identical wherever it is shared,
which is the moment most of these links are seen. Thin file, calls `ogImage()` from
`lib/og.jsx`. Dynamic segments get one file that covers all their children.

**3. Write the metadata as an answer.** A `title` that survives the `| border`
suffix inside about 60 characters, and a `description` inside about 155. Both are
rendered in full by search engines at those lengths and clipped past them. The page
should also open with a two or three sentence direct answer to its own title
question before any framing, which is what an answer engine extracts.

**4. Add the structured data it warrants.** `TechArticle` on documentation,
benchmark and blog pages. `BreadcrumbList` on anything nested. Both come from
`components/StructuredData.jsx` rather than a hand-written blob, so the url cannot
be copied from the page above and left wrong.

**5. Use `PageHero`.** See section 4a.

**6. Never type a number into `llms.txt`, or into a route summary.** That file is
generated on every build from the same modules the pages read, so a deploy
refreshes it. It is only as honest as that rule: it claimed thirteen detectors
while the site said twenty-four, because the count had been written into its intro
text by hand. A machine reading it will not check the figure against the pages, so
a stale number there is worse than a stale number anywhere else on the site.

The same applies to the `title` and `summary` in `lib/routes.js`. The detectors
page was titled "The 13 detectors" there, which put a number that changes into data
the sitemap and `llms.txt` both read. Titles in the manifest carry no counts.

**Noindex is a deliberate state, not a default.** Set `index: false` in the manifest
and the page leaves the sitemap and `llms.txt` and gains a `Disallow` in
`robots.txt`. The two legal drafts are the only pages in that state, and they are
there because an unreviewed term indexed by a search engine is an unreviewed term
somebody quotes back at you.

---

## 5. Component notes

**Nav.** Paper background, one hairline `--line` at the bottom, no blur, no shadow.
Links in `--ink-dim`, active in `--ink`. Right side holds the GitHub star count in
mono and the install command as a copy-able mono chip with an amber left border.

**Install command.** `--paper-sunk` background, mono, a 2px `--boundary` left edge, a
copy button that shows a mono "copied" state. This is one of the two heavy moments on
the home page. Give it room.

**Code blocks.** A primary design surface, not an afterthought. `--paper-sunk`
background, hairline border, no shadow, no traffic-light window chrome, no filename
tab unless the filename matters. Syntax theme: `--ink` for identifiers, `--ink-spec`
for keywords, `--amber-deep` for strings, `--ink-dim` for comments. Restrained.
Get the copy interaction and the mono metrics right before styling anything else.

**Detector table.** Hairline row rules only, no zebra striping, no outer border. All
numeric columns in mono, right-aligned, tabular figures on. Latency values link to
`/benchmarks` and carry a dotted `--ink-dim` underline rather than a colour change.

**Boundary diagram.** Static SVG. `--ink` strokes for boxes, `--boundary` amber only
at the two check points, `--line` dashed for the trusted area. No animation, no
gradient. It is the one place a reader should linger.

**Buttons.** Primary is `--ink` fill with `--paper` text. Amber fill with
`--amber-ink` is reserved for a single action per page at most, and on this site there
may be none, since the install command is the action. Ghost buttons use `--line`
borders.

---

## 6. Anti-patterns

Reject any draft that lands on these.

- **The three AI-default looks:** warm cream plus high-contrast serif plus terracotta;
  near-black plus one acid accent; broadsheet layout with hairline rules and dense
  columns. If the design plan drifts into one, revise and state what changed.
- Bordered card grids for feature lists. See 3.1.
- Amber as text, link colour, or icon colour on paper. See section 2.
- Card shadows. The parent system has none.
- Gradients, glassmorphism, blur, glow, animated backgrounds, scroll hijacking,
  parallax.
- Illustrations of robots, shields, locks, brains, or circuit boards.
- Passport, border-post, flag, star, or map imagery of any kind. See section 4.
- Stock photography of any kind.
- More than one accent hue. Amber is the only accent. `--danger` is semantic, used
  for failure states in examples, never decoratively.

---

## 7. Motion and quality floor

Motion: page-load fades only, under 200ms, and full respect for
`prefers-reduced-motion`. The copy button state change is the only interaction
animation on the site.

Non-negotiable: responsive to 360px, visible keyboard focus rings using `--ink` at 2px
with a 2px offset, WCAG AA contrast throughout, semantic landmarks, one `<h1>` per
page, tabular figures enabled wherever numbers are compared.

---

## 8. One open decision

The FlowX marketing site uses em-dashes freely. `CLAUDE.md` and `LANDING_PAGE.md`
forbid them on this project. Confirm which applies before the copy is written, because
a CI grep is specified and it will fail on inherited marketing strings if any FlowX
copy is reused verbatim.

---

## 9. Paste-ready prompt

```
Read STYLE.md and LANDING_PAGE.md fully before writing any code.

Build the design system for the flowx-border site as a Next.js App Router project on
Tailwind, matching the existing FlowX website repo conventions.

Before writing components, produce a short design plan: the token set as CSS custom
properties, the three typefaces with their assigned roles, the layout concept, and
how the four boundary rules in section 3 will be expressed in actual components.
Check it against the anti-patterns in section 6, then show it to me and wait.

Once approved, build in this order:
1. globals.css with the full light token set from section 2, plus tabular figures
   and the font loading for Sora, Geist and Geist Mono.
2. The code block and install-command components. These are the primary design
   surface. Get the mono metrics, the syntax theme and the copy interaction right
   before anything else.
3. The section boundary component: 2px amber rule, mono eyebrow sitting on it,
   generous space below. Every section on every page uses this and nothing else for
   separation.
4. The stamp component, following section 4 exactly, including the hard constraints.
5. The detector table, then the boundary diagram as static SVG.
6. The home page, assembling the above in the section order from LANDING_PAGE.md 6.1.

Constraints you must not violate:
- Amber is never text on paper. Use --amber-deep for any amber-coloured text.
- No card shadows anywhere. No bordered card grids for feature lists.
- Every number, hash, version, latency and identifier is set in mono. Every claim is
  set in sans.
- No passport, flag, seal, star or map imagery in any form.
- WCAG AA contrast on every text and background pair. Verify, do not assume.

After each numbered step, stop and show me what you built before continuing.
```
