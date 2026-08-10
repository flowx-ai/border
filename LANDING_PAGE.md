# LANDING_PAGE.md

Build instructions for the public website of `flowx-border`.

Read this together with `CLAUDE.md`. The writing style and compliance language rules
in that file apply to every word on this site, without exception.

---

## 1. What is being marketed

`flowx-border` is an open-source Python library (Apache-2.0) that checks the text
going into and coming out of an LLM and returns a structured decision plus an
audit-grade evidence record. It ships its own open-weight detection models,
published by FlowX.AI on Hugging Face.

It is not a gateway, not a proxy, not a SaaS product. There is nothing to buy.

**Primary visitor:** a platform or ML engineer at a bank, insurer or public-sector
body in Europe, who has been told by their risk team to demonstrate that AI inputs
and outputs are being checked, and who cannot send data to a US-hosted vendor.

**Their job on this site:** decide in under two minutes whether to run `pip install`.

**Secondary visitor:** a compliance or risk officer, non-technical, sent a link by
that engineer, who needs to understand what evidence the tool produces.

**The site's single job:** get the install command executed. Everything else on the
page is in service of that or it does not belong.

---

## 2. What NOT to copy from guardrailsai.com

The reference site was given as a structural example only. Two hard rules.

**Do not reproduce any of their copy, headlines, section wording, or page structure
verbatim.** Their content is copyrighted. Use their sitemap as a checklist of page
types that exist, nothing more. Every sentence on our site is written fresh.

**Do not copy their current information architecture.** As of August 2026 that
company has pivoted: their homepage sells an AI reliability platform led by a
simulation and synthetic-data product, and their open-source guardrails library is a
footer link. Their nav and use-case pages market a SaaS eval tool. We are shipping an
OSS library. Copying their IA would produce a site that sells the wrong thing.

The better structural references for tone and layout are open-source project sites:
Microsoft Presidio, Pydantic, LiteLLM, Ollama, Mistral. Docs-forward, install command
high on the page, GitHub link prominent, no "Book a demo" as the primary action.

---

## 3. Domain and stack

- **Stack:** Next.js App Router on Vercel, matching the existing FlowX website
  rebuild. Reuse its component conventions and Tailwind config where they fit.
- **Domain:** ship at `flowx.ai/border` unless instructed otherwise. A path on the
  main domain inherits its authority, which matters for a project whose whole
  strategy is discoverability. Reserve `border.flowx.ai` as a redirect.
- **No CMS for v1.** MDX files in the repo for blog and use-case content.
- Docs live at `flowx.ai/border/docs`, generated from the repo's `docs/` directory so
  there is exactly one source of truth. Do not hand-write docs content in the website
  repo.

---

## 4. Sitemap

```
/border                          home
/border/use-cases                index
  /pii-redaction
  /regulated-advice
  /agent-boundaries
  /multilingual
  /audit-evidence
/border/models                   the open-weight models, links to Hugging Face
/border/benchmarks               reproducible numbers
/border/docs                     generated from repo docs/
/border/blog                     MDX index and posts
/border/resources                papers, talks, migration guide, changelog
/border/legal/terms-of-use
/border/legal/privacy-policy
```

**Nav (desktop):** Use cases, Models, Benchmarks, Docs, Blog. Right side: GitHub link
with live star count, and a copy-to-clipboard `pip install flowx-border`.

There is no "Talk to us" and no "Get started" button. The install command is the
call to action. A contact route exists only in the footer.

**Footer columns:** Project (Docs, Models, Benchmarks, Changelog, GitHub) /
Resources (Blog, Papers, Migration guide, Discussions) / Legal (Terms of use,
Privacy policy, License) / FlowX (About FlowX.AI, Agent Builder, Observatory,
Careers).

**FlowX attribution:** every page footer carries "An open-source project by FlowX.AI"
linking to flowx.ai. On the home page it also appears once above the fold, small. Do
not put a FlowX logo lockup in the header nav, because that reads as a vendor
brochure and suppresses the community signal the project depends on.

---

## 5. Vocabulary

The project uses a boundary-inspection model. Use these five terms consistently
across the whole site, and define them once on the home page.

| Term | Meaning |
|---|---|
| **Border** | The library. Where checks happen. |
| **Code** | The policy file, `border-code.yaml`. The shared rulebook. |
| **Crossing** | A single scan event, inbound or outbound. |
| **Stamp** | The signed evidence record attached to a crossing. |
| **Area** | The trust domain. Services that accept each other's stamps. |

The governing idea, which the home page should state plainly: check hard where text
crosses the boundary, do not re-inspect inside.

**Do not name the political framework this idea is borrowed from.** Do not use flag
imagery, EU stars, passport graphics, maps of Europe, or any migration-adjacent
visual language. The principle travels, the reference does not. This is a hard rule.

---

## 6. Page specifications

### 6.1 Home

Sections in order. Do not add sections.

1. **Hero.** One-line statement of what it does. Below it, the install command in a
   copy-able block, and a link to the 30-second quickstart. No video, no animated
   gradient, no logo carousel. Include the GitHub star count and the current version.
2. **The two functions.** A short real code sample showing `scan_input` and
   `scan_output`, the returned `Decision`, and a stamp. This is the most persuasive
   element on the page and should sit high. Real, runnable code, not pseudocode.
3. **The boundary model.** The governing idea in three sentences plus one diagram:
   untrusted input, a check, a trusted area containing two agents that exchange
   messages without re-inspection, a check on the way out. Static SVG, no animation.
4. **The eight detectors.** A table: detector, side (input or output), tier, type,
   p95 latency on CPU. Every latency number links to `/benchmarks`. If a number is
   not in the benchmark output, it does not appear here.
5. **What makes it different.** Three items, no more: runs on CPU and air-gapped
   with no vendor callback; detection in Romanian, Polish, Hungarian, Turkish and
   Azerbaijani, not English with translations bolted on; emits a signed evidence
   record rather than a boolean.
6. **The models.** Four cards linking to Hugging Face, each showing parameter count,
   licence and download count. This section is why the site exists commercially, so
   it needs to be good, but it comes after the technical proof, not before it.
7. **What it is not.** Mandatory, and it stays. Not a gateway. Not a proxy. Does not
   make anyone compliant with any regulation. Does not replace a security review.
   Write it as plain prose, not as a warning box.
8. **Install.** Repeat the command and link to docs.

No testimonials. No customer logos. No "trusted by" strip. We have no users yet and
faking social proof on an OSS project is the fastest way to lose the audience.

### 6.2 Use cases

Index page: five cards, one line each, no hero.

Each use-case page follows one template:

1. The situation, in two or three sentences, written as a specific scenario rather
   than a market category.
2. What breaks without a check.
3. Which detectors apply, and the `border-code.yaml` fragment that configures them.
   Real YAML, copy-able.
4. What the stamp contains for this case, and who would read it.
5. Honest limitations. What this does not catch. Every page has this section.
6. Link to the relevant docs page.

The five:

- **`/pii-redaction`** Customer-facing assistant leaking personal data, in and out.
  Lead with the multilingual angle, because that is the differentiator.
- **`/regulated-advice`** Distinguishing an explanation from a recommendation in a
  banking assistant. This is the page with no competing equivalent anywhere, so it
  should be the most detailed. Show the hard case: explaining what an ETF is versus
  telling someone which to buy.
- **`/agent-boundaries`** Prompt injection through retrieved documents and tool
  output in a multi-agent system. Introduces stamps and mutual recognition.
- **`/multilingual`** Why English-first detectors fail on CEE languages, with real
  examples. Include the per-language evaluation table.
- **`/audit-evidence`** For the risk officer, not the engineer. What a stamp is,
  what it contains, what it does not contain (never raw user text), and how to verify
  one. Written in plain language with minimal code.

### 6.3 Models

One card per published model: name, task, parameter count, base model, licence,
languages covered, evaluation summary, Hugging Face link, and the exact
`border-code.yaml` line that enables it.

State the training data provenance for each model honestly. If a dataset cannot be
disclosed, say that rather than omitting the section.

### 6.4 Benchmarks

The credibility page. Every latency and accuracy number on the entire site
originates here.

- Latency table: p50 and p95 per detector and per tier, CPU, with the machine spec
  stated.
- Accuracy per detector, per language, against the fixture corpus.
- The exact command to reproduce, and a link to the harness in the repo.
- Known weaknesses. State where the detectors underperform. A benchmark page with no
  bad numbers on it is not believed by anyone competent.

### 6.5 Docs

Generated from the repo. Do not author content here. The site provides layout,
navigation and search only.

### 6.6 Blog

MDX in-repo. Launch set of three posts, all technical, no announcements:

- Why the open-source layer of this category went unmaintained, with the acquisition
  and archive timeline.
- Building a regulated-advice detector: the dataset, the hard negatives, what it
  gets wrong.
- Evaluating PII detection across six languages, with the numbers.

Author bylines are real people. No "the FlowX team".

### 6.7 Resources

A plain index, not a marketing page: the eXponential6 papers relevant to this work,
the LLM Guard migration guide, the changelog, conference talks, and the Discussions
link.

### 6.8 Terms of use

Scope this correctly, because it is commonly got wrong.

- The Apache-2.0 licence governs the software. The terms of use govern **the website
  only**. Say this explicitly in the first paragraph so nobody thinks the terms add
  conditions to the licence.
- Cover: acceptable use of the site, intellectual property in the site content,
  third-party links, no warranty for site content, limitation of liability,
  governing law (Romania), and contact.
- Explicitly disclaim that use of the site creates any support obligation or
  professional relationship.
- Do not draft anything about the model weights here. Model licensing lives on the
  Hugging Face model cards and is referenced, not restated.
- Mark the file `LEGAL REVIEW REQUIRED` at the top of the source and do not ship it
  without sign-off.

### 6.9 Privacy policy

- If the site collects nothing beyond privacy-preserving analytics, say so plainly
  and early. For this audience that is a feature, not boilerplate.
- Use a cookieless analytics provider (Plausible or Vercel Analytics) so there is no
  consent banner. A consent banner on a privacy-positioning site is an own goal.
- Cover: what is collected, legal basis under GDPR, retention, processors and where
  they are hosted, data subject rights, and the controller identity (FlowX.AI, with a
  Romanian address and a contact address).
- State clearly that the library itself sends no telemetry, makes no network calls at
  scan time, and that nothing a user scans reaches FlowX. This is a genuine
  differentiator and belongs here and on the home page.
- Same `LEGAL REVIEW REQUIRED` marker.

---

## 7. Copy rules

All rules from `CLAUDE.md` apply. Additionally, for the website:

- **No em-dashes anywhere.** A CI grep should fail the build on one.
- Sentence case for all headings.
- No superlatives, no "seamless", "powerful", "revolutionary", "enterprise-grade",
  "next-generation", "unlock", "leverage" as a verb.
- Every number is traceable to `/benchmarks`. No number appears without a source.
- Never claim compliance with any regulation. Permitted framing is that the library
  produces evidence about which controls ran and what they found. The obligations
  sit with the deployer, not with a dependency.
- Do not name competitors on the site. The acquisition timeline can appear in a blog
  post as dated fact with sources. It does not belong in marketing copy.
- Write for someone who will run the code today. Prefer a code sample to a paragraph
  wherever the code is clearer.

---

## 8. Design direction

Before writing any component, produce a short design plan: four to six named hex
values, two or three typefaces with their roles, a layout concept, and one signature
element. Review it against this brief, then build to it.

Constraints:

- Inherit the FlowX palette and typography where they fit, so this reads as a FlowX
  project rather than an unrelated one. Diverge only where the OSS context genuinely
  needs it, and say why.
- **Avoid the three defaults that AI-generated sites cluster around:** warm cream
  background with a high-contrast serif and a terracotta accent; near-black with a
  single acid accent; broadsheet layout with hairline rules and dense columns. If the
  design plan lands on one of these, revise it and state what changed.
- The signature element should be the boundary diagram, used once on the home page
  and echoed as a small motif elsewhere. Spend the boldness there and keep everything
  around it quiet.
- Code blocks are a primary design surface on this site, not an afterthought. Get the
  monospace face, the syntax theme, and the copy-button interaction right before
  polishing anything else.
- Motion: page-load only, minimal, and respect `prefers-reduced-motion`. No scroll
  hijacking, no parallax, no animated gradients.

Quality floor, not negotiable: responsive to 360px, visible keyboard focus states,
WCAG AA contrast, semantic landmarks, real `<h1>` per page.

---

## 9. SEO and AEO

- Static generation for every page. No client-side-only content.
- One `<h1>` per page matching the primary query intent.
- Structured data: `SoftwareSourceCode` on home, `TechArticle` on docs and blog,
  `BreadcrumbList` on nested pages, `Organization` pointing at FlowX.AI.
- The queries to target are problem-shaped, not brand-shaped: alternatives to an
  archived scanning library, checking LLM output for personal data, detecting
  financial advice in model output, running detection without sending data to a
  vendor, LLM checks in Romanian.
- Answer-engine formatting: each page opens with a two-to-three sentence direct
  answer to its own title question before any marketing framing. Use plain tables
  rather than styled divs for comparison data so they extract cleanly.
- `llms.txt` at the site root summarising the project and linking to key pages.
- Real OpenGraph images per page, generated at build time, not one shared default.

---

## 10. Definition of done

- Lighthouse: performance and accessibility both 95+ on mobile.
- No em-dash anywhere in the repo, enforced in CI.
- Every number on the site resolves to a row in the benchmark output.
- Home page communicates what this is and produces a copied install command within
  two minutes for a first-time technical visitor.
- Both legal pages carry the review marker and have not shipped without sign-off.
- No consent banner, because nothing requiring consent is collected.
- Zero copy, headline or layout lifted from any competitor site.
