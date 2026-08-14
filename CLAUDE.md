# CLAUDE.md

Standing context for this repository. Read this before every task.

## What this project is

An embeddable Python library that inspects the text going into and coming out of an
LLM, and returns a structured decision plus an audit-grade evidence record.

It ships its own open-weight detection models. It is not a gateway, not a proxy,
not an agent framework, and it does not wrap the LLM call.

Name: `flowx-border`, decided 2026-08-10, previously the working name `flowx-guard`.
Distribution name `flowx-border`, import name `flowx_border`. Even though the name is
settled, keep it out of the source: it belongs in `pyproject.toml` and the top-level
package directory, nowhere else.

## Where this lives, and who will read it

The library's remote is `git@github.com:flowx-ai/border.git`. The landing page gets its
own repository, not a directory in this one.

**The repository is private today and will be made public before release.** That is a fact
about every file in it, not a detail about hosting. Two consequences worth holding onto
while writing anything here:

- Nothing goes in that would embarrass anyone or leak anything when the switch flips. No
  credentials, obviously, but also no internal-only asides, no customer names, no
  disparagement of another project.
- Every claim in a comment, a docstring or a commit message is a public claim. The rules in
  the writing-style and compliance-language sections below are not house preference, they
  are what those claims will be read against. A number with no benchmark behind it becomes
  a public number with no benchmark behind it.

Commit messages are part of that surface. They are the most detailed record of why the code
is shaped the way it is, and they will be readable by anyone.

## Current state, read this before looking for files

Phase 0 landed on 2026-08-10. What exists: `pyproject.toml`, the CI workflow,
`types.py`, `detectors/base.py`, the three stub public functions, and the tests for
those. What does not exist yet: the policy loader, the engine, every detector, the
model runtime, the adapters, the benchmarks, and the README. The rest of the "Repo
layout" section below is still the target, not the present.

**Phase 7 is next, and it is the README.** Phases 0 to 6 are done and tagged. Every number
in it must come from `benchmarks/collect.py`, which writes `docs/reference/performance.json`,
and `tests/test_performance.py` fails if a score there loses its sample size.

**Nothing is published to Hugging Face until the end of the project.** Decided
2026-08-11 by the owner. The artifacts exist and are verified, and they stay on the training
VM until a single deliberate release at the end, alongside making this repository public.

The consequence to plan around: the library cannot fetch what is not published, so every
detector after the T0 pair would be unloadable and phases 4 and 5 would be untestable. The
answer is the local override in `models/registry.py`, `FLOWX_BORDER_MODEL_DIR`, which points
at a directory of artifact folders and is how development and tests run against unreleased
weights. A record produced from a local override says so: its revision reads `local:<sha>`
rather than a commit, because an evidence record that claimed a pinned published revision for
a file somebody had on their laptop would be a forgery. See the tests in
`tests/test_local_models.py`.

`BUILD_PLAN.md` is the sequencing document: seven phases, each with a paste-ready
prompt and a definition of done. Before starting work, find the lowest phase whose
definition of done does not yet hold, and do that one. Rules from that file that
matter across sessions:

- One phase per session. Do not run two phases in one session.
- Check the definition of done yourself rather than trusting a summary.
- Commit at the end of each phase, tagged `phase-N`, so a bad phase is one revert.

**Queued, after the Guardrails Hub migration:** work out whether new detectors should be
added to complete the set, as opposed to ported into it. Queued by the owner on
2026-08-11, deliberately after the port rather than folded into it. The raw material is
already assembled and is listed at the end of
`docs/porting-guardrails-validators.md`: the `gap = yes` rows of the declined table, the
`UNSUPPORTED` table in `adapters/llm_guard_compat.py`, and the three detectors that ship
unavailable for want of published weights. The output is a proposal with a tier and a
budget per candidate, not a set of new detectors.

Two deliberate deviations from the specified core types were made in phase 0 and are
open for reversal on instruction:

- `finding_summary` is `tuple[FindingSummary, ...]` rather than `list[dict]`. The
  serialised JSON is unchanged, a list of objects with exactly `detector_id`, `label`,
  `score`, `action`. It is typed because the no-raw-text invariant cannot be asserted
  about a free `dict`.
- `detectors` is a tuple for the same reason `EvidenceRecord` is frozen: a mutable
  list inside an audit artifact is not immutable in any useful sense.

## The entire public API

```python
from flowx_border import scan_input, scan_output, load_policy

policy = load_policy("policy.yaml")
decision = scan_input(text, policy, ctx=None)
decision = scan_output(text, policy, ctx=None)
```

Two functions. If a task appears to require a third public entry point, stop and
ask before adding it. Everything else in the package is an implementation detail
or an adapter.

## What a detector may need, and how a caller finds out

The goal is to offer everything useful for guarding LLM input and output. Nothing on
this list is forbidden. What matters is that a caller knows what they are taking on when
they enable a detector, and finds out at the moment they enable it rather than from a
latency graph in production.

So this is a property of each detector rather than a rule in a document.
`Spec.requires` in `detectors/catalogue.py` declares it, and
`registry.deployment_notes(policy)` reads it back as one line per requirement, naming
the detectors that brought it in. It returns lines rather than raising: needing a GPU is
not an error, and a caller who wants it to be fatal can treat a non-empty result that
way.

### The packages

**Core** is every detector that needs nothing beyond a CPU and the base install. It runs
on a laptop with the network interface down, and it is what a caller gets unless they
enable something else deliberately. **It is twenty-five of the twenty-eight**, corrected
on 2026-08-13 from a hand-written twenty-six that named only two exceptions and forgot
`json_schema`.

Worth noting how that was caught, because it is the chain working as designed. The
landing page generates its detector table from `docs/detectors.md`, which is rendered from
`detectors/reference.py`, which reads the catalogue. So the site said twenty-five while
this file said twenty-six, and the code settled it. Do not restate this count by hand;
read it off `CATALOGUE` the way `deployment_notes` does.

Three are outside it, and between them they exercise the whole mechanism:

- `sql_injection` needs the sqlglot parser, so it declares `requires={"dependency"}`,
  ships in the `sql` extra, and is absent from the registry rather than degraded to a
  pass when that extra is not installed.
- `json_schema` needs `jsonschema` for the same reason and behaves the same way, in the
  `schema` extra. It is the one this file kept losing, presumably because validating a
  caller's own schema feels like it should be free.
- `url_reachability` makes an HTTP request, so it declares `requires={"network"}`. It is
  T3, it is disabled in both shipped policies, and `tests/test_offline.py` excludes it
  by definition: the claim that a scan works with the interface down is a claim about
  CORE, and this is not in CORE. Its budget is the one entry in the whole table that is
  a deadline the detector enforces on itself rather than a figure somebody measured,
  because it depends on a network the library does not control.

A text-to-SQL product wants the first and takes the dependency; a product that cites
links wants the second and accepts the latency. Everyone else neither pays for them nor
hears about them, and a policy that enables either gets told at load rather than in
production.

Beyond core, a detector declares one or more of these, and enabling it produces a note:

| requires | what the caller is taking on |
|---|---|
| `network` | a third party in the latency path of every scan, and their outage becomes yours |
| `gpu` | an accelerator, or a much slower scan on CPU |
| `llm` | a generative model, reproducible only with decoding pinned |
| `dependency` | a runtime dependency outside the base install |

`docs/porting-guardrails-validators.md` tags the not-yet-built validators with the
requirement each would bring, so the migration backlog and the packaging use one
vocabulary.

### The numbered entries, kept because other files cite them by number

`adapters/llm_guard_compat.py`, `detectors/guardrails_hub.py` and the docs refer to
these by number, so the numbering is stable even though several are now defaults rather
than prohibitions.

1. **Network at scan time.** Weights are fetched once at install or first load and
   cached. Everything in core works with the interface down, and `tests/conftest.py`
   blocks outbound connections for the whole suite, so a detector that needs egress
   declares `requires={"network"}` and marks its tests `@pytest.mark.network`.
2. **CPU is the reference target.** A detector that needs an accelerator declares
   `requires={"gpu"}`. This is about who can deploy the library rather than principle:
   an embeddable library that always needs a GPU is one most callers cannot embed.
3. **A new detector has to earn its place, and there is no cap on how many can.** The
   count gate went on 2026-08-11. It was eight for v1, thirteen on 2026-08-10, and
   uncapped on 2026-08-11 when the Guardrails Hub port landed. v1 is twenty-eight and
   nineteen landed on one day. What is left is three things a detector must do:

   - Work in all 26 languages, with fixtures for each and, if it is model-backed, a
     per-language evaluation table rather than one aggregate.
   - Meet its tier's budget at the reference input, asserted in `tests/test_budgets.py`.
   - Never silently do nothing. Unconfigured, unavailable or uncomparable are findings
     it reports, not conditions it passes through.

   A fourth, "it answers a security or governance question", was dropped on 2026-08-11
   when `output_format` landed. That one answers no security question and says so in its
   own docstring; it exists so sixteen hub shape validators have one destination instead
   of sixteen. Recorded as dropped rather than deleted, because collapsing sixteen into
   one is still the right move for the seventeenth.

   The reason the cap existed is kept because it was overruled rather than refuted:
   breadth is how the predecessor projects died. Uncapped, the three rules above are
   what stop breadth becoming shallowness, so they matter more now than they did.
4. **A generative model inside a detector** declares `requires={"llm"}`, and `{"gpu"}`
   too if it needs one. Small local models are legitimate detectors; Llama Guard and
   ShieldGemma are the proof the category is useful. Two things to get right rather than
   to avoid: pin greedy decoding and a seed, or entry 6 breaks and the evidence record
   with it; and give it a budget it can actually meet, since a 1.6B generative pass on
   CPU is far past the 300 ms T3 ceiling when the 278M encoders cost 151 ms. A
   classification head on a small base answers most of the same questions without
   either problem, so prefer it and say why when you do not.
5. **Policy is data, not code.** Not a default, a requirement. `policy_hash` pins
   behaviour only because the document fully determines behaviour, so a Python callback
   in a policy file makes every evidence record citing that hash a weaker claim than it
   looks. It is also what lets a compliance officer who does not write Python review a
   policy.
6. **Deterministic given the same inputs and model revisions.** Not a default either.
   No sampling, no temperature, no clock inside a scan. `EvidenceRecord` exists to be
   checked later by someone who was not there, and a record that cannot be reproduced is
   a log line with a signature on it. A `requires={"llm"}` detector satisfies this by
   pinning decoding, not by being exempt from it.
7. **A new runtime dependency** is a judgement call about install weight and
   supply-chain surface in a library other people embed. The base set is `pydantic`,
   `pyyaml`, `onnxruntime`, `tokenizers`, `huggingface-hub` and `cryptography`. Add to
   it when it buys something, say what, and declare `requires={"dependency"}` if it is
   optional rather than base.

## Detector set

**The reference input, without which no budget below means anything.** 87 tokens of
prose, 396 characters, one thread, CPU execution provider, INT8 weights. Measured
2026-08-11 on an Apple M-series laptop. The exact string is `REFERENCE_INPUT` in
`tests/test_budgets.py` so a figure can be reproduced rather than argued about.

Stating the length and the thread count is the whole point. The previous version of this
table gave bare millisecond figures with neither, which made every one of them
unfalsifiable: `pii` at "15 ms" is true at 27 tokens and false by a factor of three at the
length the model was trained on. Budgets are per detector, per scan, at that input.

| ID | Side | Tier | Type | Budget (p95) | Measured | Status |
|---|---|---|---|---|---|---|
| `secrets` | input | T0 | regex + entropy | 1 ms | 0.04 ms | built |
| `disclosure` | output | T0 | rule + template match | 5 ms | 0.04 ms | built |
| `invisible_text` | input, output | T0 | rule | 5 ms | 0.04 ms | built |
| `pii` | input, output | T1 | NER, XLM-R base ONNX | 225 ms | 153 ms | built |
| `output_leakage` | output | T1 | NER, reuses `pii` weights | 225 ms | 153 ms | built |
| `gibberish` | input | T1 | classifier | 225 ms | 151 ms | built |
| `banned_terms` | input, output | T1 | policy term list | 5 ms | 0.23 ms | built |
| `system_prompt_leakage` | output | T1 | containment + phrases | 5 ms | 0.36 ms | built |
| `markup_injection` | input, output | T1 | rule | 5 ms | 0.23 ms | built |
| `internal_domains` | output | T1 | policy domain list | 5 ms | 0.23 ms | built |
| `output_format` | output | T1 | policy shape assertions | 5 ms | 0.02 ms | built |
| `postal_code` | output | T1 | per-country format + range | 5 ms | 0.02 ms | built |
| `repetition` | output | T1 | sentence similarity | 5 ms | 0.09 ms | built |
| `summary_support` | output | T1 | sentence overlap vs source | 5 ms | 0.71 ms | built |
| `code_present` | input, output | T1 | code shape signals | 5 ms | 0.01 ms | built |
| `token_limit` | input, output | T1 | token count vs a pinned tokenizer | 5 ms | 0.19 ms | built |
| `json_schema` | output | T1 | JSON Schema, `schema` extra | 5 ms | 0.02 ms | built |
| `sql_injection` | output | T1 | SQL parse tree, `sql` extra | 5 ms | 0.31 ms | built |
| `url_reachability` | output | T3 | HTTP request, needs network | 3000 ms | deadline | built |
| `moderation` | input, output | T2 | 13-label classifier, Qwen3-0.6B | 150 ms | – | pipeline built, corpus outstanding |
| `injection` | input | T2 | classifier | 225 ms | 151 ms | built |
| `regulated_advice` | output | T2 | classifier | 225 ms | 151 ms | built |
| `toxicity` | input, output | T2 | classifier | 225 ms | 151 ms | built |
| `nsfw` | input, output | T2 | classifier | 225 ms | 151 ms | built |
| `bias` | output | T2 | classifier | 225 ms | 151 ms | built |
| `politeness` | output | T2 | classifier | 225 ms | 151 ms | built |
| `topic_scope` | input | T3 | bi-encoder vs taxonomy | 300 ms | 214 ms | built |
| `groundedness` | output | T3 | cross-encoder vs sources | 300 ms | 61 ms | built, model refused |

Three things this table now says that the old one did not.

**Cost is per token and linear within a window, with a step at each window boundary**, and
the budget is not one number for every encoder detector because the quantisation recipe
differs. 0.60 ms per token at one thread for `piiguard`, whose INT8 export quantises
throughout and weighs 266 MB. The nine models trained here quantise the embedding matrix
only, because INT8 over all ops moved 51 of 300 decisions, and that leaves the transformer
in fp32 at 511 MB and 151 ms for the same 87 tokens. Three times the cost, measured
2026-08-11, and the price of an export that does not change a verdict.

So every encoder detector carries a 225 ms budget, `pii` included. **This said "`pii` keeps
75" until 2026-08-14, and that was the withdrawn 51 ms figure leaving a trace.** 75 is
51 x 1.5, the headroom rule applied to a rate that was retracted on 2026-08-12; the
catalogue has said `Spec("T1", ..., 225.0)` since. Read a budget off `CATALOGUE`, never off
this paragraph. That is the third place the 51 ms survived its own withdrawal, after the
detector table and the hero stat, and the instruction stands: when a measurement is
superseded, grep for it.

Recovering the difference means finding the op subset that quantises without moving a
decision, which is queued on the training side rather than assumed to exist. Until then the
honest statement is that a decision-safe export costs three times a decision-changing one.

**The per-token rate itself was measured across a window boundary and was 22 percent too
steep.** Re-taken 2026-08-14 on a quiet machine against the adopted 26-locale artifact,
recorded in `docs/reference/latency_sweep.json`:

| tokens | p95 | windows |
|---|---|---|
| 16 | 34.03 ms | 1 |
| 64 | 114.89 ms | 1 |
| 87 | 154.13 ms | 1 |
| 94 | 161.60 ms | 1 |
| 95 | 198.53 ms | 2 |
| 128 | 251.16 ms | 2 |

A window holds `trained_max_length - 2` content tokens, 94, because every window is wrapped
in bos and eos. So 94 tokens is one forward pass and 95 is two, a step of 36.93 ms for one
more token. Inside a window the slope is **1.636 ms/token**; averaged from 16 to 96, which
crosses the boundary, it reads 2.011 and is that second pass reported as per-token cost.
Cost is still proportional rather than catastrophic, at about `ceil(n / 94)` passes, which
is the claim worth making. It is the flat-line reading that was wrong.

Worth noting how it was caught, because two mechanisms were proposed for the step and both
were wrong. Not a fast path in the exported graph: the raw session is smooth from 90 to 112
fed tokens. Not a per-window penalty either, and the test that killed that was giving the
detector a 94-token window so every window feeds 96 rather than 98, which made it 2 percent
slower. `cProfile` settled it at 20 calls into onnxruntime per ten `run` calls against 10
below the boundary. The sweep now carries a window count on every point so a consumer cannot
draw one line through points that are not comparable.

The sweep also gained a cross-check at 87 tokens, the one length with a figure it did not
produce: 154.13 against the recorded 153, +0.7 percent, and +1.3 on a second run. Before
that the sweep was internally consistent and unfalsifiable, which is this file's own named
failure mode.

**`piiguard`'s 51 ms was withdrawn on 2026-08-12 and this file kept quoting it until
2026-08-13.** That figure belonged to the published 266 MB INT8 artifact, which was then
measured against its own fp32 weights for the first time and found to lose an entity
entirely on 13 of 120 texts and to disagree on 32. A lost entity is a hole in a redaction
the caller cannot see, in the model behind the two model-backed detectors that run by
default, so it was re-exported with the Gather-only recipe: 533 MB, zero missed, zero
invented, and **153 ms**. The budget went to 225 with the same 1.5x headroom the rest of
the table uses. See commit 5447507, which carries the measurement.

Three places in this file still said 51 afterwards, including the detector table and the
per-scan total below, and the landing page's hero stat said it too. The lesson is narrow
and worth stating: a withdrawn number does not leave the document it was written into. When
a measurement is superseded, grep for it.

**The tier ceilings are not per-scan totals.** A full output-side scan with everything
wired is one rule check plus six encoder passes: `pii` and `output_leakage` share a single
pass at 153 ms, and each of the five output-side T2 classifiers is a different model
needing its own at 151 ms. That is roughly 910 ms at the reference length, not the 310 ms
this paragraph claimed while the classifiers were unwired and assumed to cost what `pii`
costs. The tier system is what keeps that off the common path, T2 being disableable and T3
running only on escalation, which is a scheduling property rather than a cost one.

Sharing the inference is still what makes the pair cheap: `output_leakage` reusing `pii`'s
encoder pass over the same text is one 153 ms pass rather than two. Sharing the session
saved memory; sharing the inference saved the time.

**Threads buy the old numbers back, and the library will not take them.** Measured at 96
tokens: 54.7 ms at one thread, 29.8 at two, 17.8 at four, 12.4 at eight. So a 15 ms T1
budget is reachable, at the price of taking eight cores from the host application on every
scan. The default stays at one thread, because a library that quietly commandeers the
machine it is embedded in is worse than a library that is honestly slower, and a policy
can raise it deliberately.

`gibberish` is T1 because a gibberish input should short circuit the tiers above it rather
than be scored by them, not because it is cheaper. It is not.

Tier semantics:
- **T0** always runs, cannot be disabled, negligible cost.
- **T1** runs on the standard path.
- **T2** runs on the standard path, may be disabled per policy.
- **T3** runs only when a lower tier flags, or when the policy sets `always: true`.

Latency budgets are asserted in `tests/test_budgets.py`. A change that blows a budget
fails CI. If a budget is genuinely wrong, change the budget in a separate commit with
a measurement in the message, never silently in the same commit as the code.

## Core types

`Decision` and `EvidenceRecord` are the load-bearing structures. Changing them is a
breaking change and needs an explicit instruction.

```
Decision
  verdict: "allow" | "redact" | "block" | "flag"
  text: str                  # possibly redacted or rewritten
  original_text: str
  findings: list[Finding]
  evidence: EvidenceRecord
  elapsed_ms: float
  tiers_run: list[str]

Finding
  detector_id: str
  tier: str
  label: str                 # e.g. "email", "prompt_injection", "financial_advice"
  score: float               # 0.0 to 1.0
  span: tuple[int, int] | None
  action: "block" | "redact" | "rewrite" | "flag" | "log"
  model_id: str | None
  model_revision: str | None

EvidenceRecord
  record_id: str             # UUIDv7
  timestamp: str             # RFC 3339, UTC
  direction: "input" | "output"
  policy_id: str
  policy_hash: str           # sha256 of the resolved policy document
  library_version: str
  detectors: list[DetectorAttestation]   # id, model_id, revision, weights sha256
  input_hash: str            # sha256 of original text, never the text itself
  verdict: str
  finding_summary: list[dict]            # detector_id, label, score, action
  signature: str | None      # Ed25519 over the canonical JSON of the above
```

The evidence record never contains raw user text. It contains hashes. This is not
negotiable and there is a test for it.

Serialisation is canonical JSON (sorted keys, no whitespace) so that hashes and
signatures are reproducible across machines.

## Repo layout

```
src/flowx_border/
  __init__.py          # exports scan_input, scan_output, load_policy only
  types.py             # Decision, Finding, EvidenceRecord, DetectorAttestation
  policy.py            # YAML schema, loader, resolution, hashing
  engine.py            # tier orchestration, short-circuit logic, timing
  evidence.py          # record construction, canonical JSON, signing
  detectors/
    base.py            # Detector protocol
    secrets.py         # T0
    disclosure.py      # T0
    invisible_text.py  # T0, bidi controls, tag characters, zero-width
    pii.py             # T1
    injection.py       # T2
    regulated_advice.py# T2
    topic_scope.py     # T3
    groundedness.py    # T3
    output_leakage.py  # T1, reuses the pii session, does not load a second copy
    entity_shapes.py   # what pii tagged that cannot be what it was tagged as
    checksummed.py     # cards and IBANs the checksum finds whatever the model said
    multilingual.py    # folding and matching that behave alike in all 26 languages
    banned_terms.py    # T1, policy-supplied term list
    system_prompt_leakage.py  # T1, containment plus a 26-language phrase file
    markup_injection.py# T1
    internal_domains.py# T1, policy-supplied domain list
    output_format.py   # T1, policy-supplied shape assertions, the only non-security one
    postal_code.py     # T1, per-country postcode shape and range, 29 countries
    repetition.py      # T1, a sentence said twice
    summary_support.py # T1, a summary sentence with no counterpart in the source
    code_present.py    # T1, source code where prose was expected
    token_limit.py     # T1, a token count against a tokenizer the policy pins
    json_schema.py     # T1, the policy's schema, requires the schema extra
    sql_injection.py   # T1, sqlglot parse tree, requires the sql extra
    url_reachability.py# T3, the only detector that leaves the machine
    guardrails_hub.py  # provenance: which hub validators went where, and which did not
    catalogue.py       # id to tier, sides and budget
  models/
    registry.py        # model id to HF repo and pinned revision
    onnx.py            # ONNX Runtime session management, warm-up, pooling
  adapters/
    langgraph.py
    fastapi.py
    llm_guard_compat.py  # scan_prompt / scan_output shim
tests/
  fixtures/            # golden corpus, one directory per detector
  test_offline.py      # asserts no socket use during scan
  test_budgets.py      # latency assertions
  test_evidence.py     # no raw text in records, reproducible hashes
  test_multilingual.py # the folding core, and the upstream bugs it fixes, as regressions
docs/
  porting-guardrails-validators.md  # all 65 hub validators, rendered from the code
  migrating-from-llm-guard.md
policies/
  default.yaml
  bfsi.yaml
```

## What backs each detector

Decided 2026-08-10 after an inventory of the 39 repos on
[huggingface.co/flowxai](https://huggingface.co/flowxai), which is the model
repository for this library. `models/registry.py` pins every entry to a commit sha.

| Detector | Model | State |
|---|---|---|
| `secrets` | – | rules, no weights |
| `disclosure` | – | rules plus a phrasings data file |
| `invisible_text` | – | rules, no weights |
| `pii` | `flowxai/piiguard` default, `flowxai/cee-pii` policy-selectable | piiguard has ONNX and INT8 published |
| `output_leakage` | whichever session `pii` loaded | never a second copy |
| `banned_terms` | – | rules over a policy-supplied term list |
| `system_prompt_leakage` | – | rules plus a phrasings data file |
| `markup_injection` | – | rules, no weights |
| `internal_domains` | – | rules over a policy-supplied domain list |
| `output_format` | – | rules over policy-supplied shape assertions |
| `postal_code` | – | per-country formats in a packaged data file |
| `repetition` | – | stdlib difflib, no weights |
| `summary_support` | – | stdlib difflib against the caller's sources |
| `code_present` | – | regex signals over code shapes, no weights |
| `token_limit` | – | a tokenizer the policy names and pins, no weights |
| `json_schema` | – | the caller's schema, from the policy |
| `sql_injection` | – | the sqlglot parse tree, no weights |
| `url_reachability` | – | an HTTP request, no weights |
| `topic_scope` | `flowxai/semantic-mapper` | 4B generative, GGUF only, see the caveat below |
| `moderation` | ours, Qwen3-0.6B, see `training/` | pipeline validated, corpus outstanding |
| `injection` | none published | ships unavailable in v1 |
| `regulated_advice` | none published | ships unavailable in v1 |
| `groundedness` | retrained 2026-08-13, see below | not published, ships unavailable in v1 |

`piiguard` is XLM-RoBERTa base with 7 entity types (CARD, DATE, EMAIL, IBAN,
NATIONAL_ID, PERSON, PHONE) and checksum validation. `cee-pii` is GLiNER with 34
labels weighted toward CEE, and it has no ONNX export yet, so wiring it means doing
that export first. Both are selectable per policy, and `output_leakage` reuses the
session that `pii` already loaded whichever way the policy went.

`piiguard` was trained on **nine** locales, not the two its hub tags advertise: `en`,
`ro`, `bg`, `hu`, `sl`, `hr`, `de`, `it`, `fr`, all of them EU official languages. The
source of truth is `configs/cross/pii_multi.yaml` in the OpenNER training repo, and
the hub tags need fixing to match. Trained at `max_length: 96`, which is the number to
quote when anyone asks what input the latency figures describe.

**A 26-locale retrain exists and its score cannot be published.** Finished 2026-08-12 on
60,000 train and 6,000 test examples, three epochs, and it reported test precision,
recall, F1 and accuracy of exactly 1.0 at a loss of 1.09e-05. That is not a perfect PII
tagger, it is a test set the generator wrote. Both splits are drawn from the same fixed
`LANG_TEMPLATES` with entities slotted in, so "the entity sits at position N of template
T" is a sufficient rule, and the loss says that is the rule it learned. Human annotators
do not agree with each other at 1.0 on this task.

So the remaining work on the 26 locales is an evaluation the generator cannot ace, and
that is the work rather than the training, which is done and whose weights are fetched.
Either a template set held out of training, or real text. Until one exists, the run has
no per-language table at all and none of its numbers may reach the model card, because a
published 1.0 would be a claim about template memorisation.

**piiguard does not recognise a card number, it recognises the sentence a card number
came in.** Measured 2026-08-13 on the published nine-locale `piiguard`, which is the
artifact v1 ships, over nine locales and PANs from the generator's own `make_pan`:

| the sentence the card sits in | CARD label correct |
|---|---|
| the generator's own template | 100.0%, 360 of 360 |
| the same template with its IBAN clause removed | 32.5%, 117 of 360 |
| a sentence the generator never wrote | 18.3%, 44 of 240 |

There are three templates per locale and in every one of the 26 the card follows an IBAN
in the same clause, so what the model learned is "the digit run at the end of this
sentence, after an IBAN, is a card". Take the IBAN away and it collapses to a third. Take
the sentence away and it collapses to a fifth. That is also why the retrain reported a
test F1 of 1.0: the test split draws on the same three templates.

The second measurement, 240 sentences per form, model alone with the checksum pass
neutralised. Read the `full span` column rather than the label one, because a short span is
a disclosure where a wrong label is a wrong sentence in a record:

| written as | any span | label `card` | full span |
|---|---|---|---|
| `4548 8388 2210 5536` spaced | 100% | 4.2% | **41.2%** |
| compact | 100% | 0.0% | 100% |
| hyphenated | 100% | 0.0% | 100% |
| dotted | 100% | 0.0% | 100% |

**The conclusion drawn from that table was wrong, and the table itself was measured inside a
frame that still contained an IBAN.** It said the spaced form is where the span breaks,
because the model tags each group separately and the groups either side of a space cannot be
joined. Re-measured on 2026-08-13 in a frame with no IBAN in it, all four notations score
identically: typed F1 0.0000 and token coverage 1.0000, spaced included. So notation
explains none of it and the neighbour explains all of it. See the superseded-table section
below, and note that this is the *seventh* instance of the pattern rather than the sixth,
because a measurement that varies one thing inside a fixed frame agrees with the frame.

**Two of my own claims here were wrong and are corrected rather than deleted**, because the
way they were wrong is the useful part. I first recorded the cause as `make_pan` emitting
unspaced PANs. It does not: it groups in fours, and both makers emit only spaced forms. And
I attributed the behaviour to the 26-locale retrain when the artifact under the local
override was the published nine-locale model. Both errors came from generalising a cause
from one input, `4111 1111 1111 1111`, which is all ones and tokenises like nothing a
generator produces. A measurement over the generator's own numbers said something different
in the first minute.

This is the sixth instance of the pattern named below, and the first where the thing
agreeing with itself was a diagnosis rather than a score.

**Superseded 2026-08-13 by a wider measurement. The table below is kept because the way it
was too narrow is the useful part.** It read:

| entity | own template, label / span | novel sentence, label / span |
|---|---|---|
| `PERSON` | 100% / 100% | 100% / 100% |
| `EMAIL` | 100% / 100% | 100% / 100% |
| `PHONE` | 100% / 100% | 100% / 100% |
| `NATIONAL_ID` | 100% / 100% | 100% / 100% |
| `DATE` | 100% / 100% | 61.3% / 100% |
| `IBAN` | 100% / 98.4% | 92.9% / 88.0% |
| `CARD` | 100% / 100% | 13.3% / 23.6% |

and concluded "frame dependence is not general, four types are unaffected". Both halves of
that were artifacts of using one novel sentence per locale. With frames that deliberately
remove each type's habitual predecessor, run through `border_train.heldout_ner_eval` over
1794 rows in 26 languages against the INT8 graph that actually ships:

| entity | typed F1 | exact span | token coverage | mislabelled | leaked tokens |
|---|---|---|---|---|---|
| `PERSON` | 0.9995 | 1.0000 | 1.0000 | 0 | 0 |
| `EMAIL` | 0.9952 | 1.0000 | 1.0000 | 0 | 0 |
| `PHONE` | 0.9765 | 1.0000 | 1.0000 | 0 | 0 |
| `IBAN` | 0.5913 | 0.9928 | 1.0000 | 99 | 0 |
| `CARD` | 0.2539 | 0.8462 | 1.0000 | 351 | 0 |
| `NATIONAL_ID` | 0.0591 | 1.0000 | 1.0000 | 188 | 0 |
| `DATE` | 0.0000 | 0.0000 | 1.0000 | 0 | 0 |

**The headline is the last column, and it is zero everywhere.** Not one sensitive token, out
of thousands across every held-out frame, reaches a caller unredacted. Every gold span is
fully covered by some predicted span. So the whole of this problem is that the model calls
things by the wrong name, and none of it is a disclosure. That is the sentence to keep.

Three corrections to the old reading:

- **Frame dependence is general, not CARD-specific.** `PERSON` in a non-initial position
  scores typed F1 0.5180 with 99 mislabelled spans. It read 100% before because the
  generator puts `PERSON` first in every template and the old measurement did too, so
  "unaffected" meant "never asked".
- **Notation is irrelevant; the frame is everything.** `card_spaced`, `card_compact`,
  `card_hyphenated` and `card_dotted` all score exactly 0.0000 typed and 1.0000 coverage in
  a frame with no IBAN. The earlier claim that the spaced form is where the span breaks
  (41.2% against 100%) was measured inside a frame that still had the IBAN, so it attributed
  to notation what belongs to the neighbour.
- **`DATE` is the reverse of what was written here.** Not "loses its label but never its
  span": exact-offset recall is 0.0000 and coverage is 1.0000, which means the model tags
  `14`, `March` and `2024` as three separate spans instead of one. A redactor covers the
  whole date; an evidence record gets three findings where it should have one. `DATE` also
  produces 624 spurious spans against 208 gold, which is the precision problem, not a recall
  one.

**Do not read `NATIONAL_ID` at 100% as strength, and the reason is worse than first
recorded.** Its old 100% came from a harness where no frame ever asked for a national ID, so
its recall was computed over zero examples while its spurious spans still counted. Asked
properly it is 0.0962 recall with 449 spurious spans: it is not the class with perfect
recall and poor precision, it is poor at both, and it is where the model puts any digit run
it does not recognise.

**The 26-locale retrain is better on every type that matters and should be adopted.** Same
harness, same frames:

| entity | published nine-locale | 26-locale retrain |
|---|---|---|
| `CARD` | 0.2539 | 0.7005 |
| `IBAN` | 0.5913 | 0.9278 |
| `PHONE` | 0.9765 | 1.0000 |
| `EMAIL` | 0.9952 | 0.9988 |
| `PERSON` | 0.9995 | 0.9995 |
| `NATIONAL_ID` | 0.0591 | 0.0970 |
| `DATE` | 0.0000 | 0.0000 |

Mislabelled CARD spans fall from 351 to 106 and IBAN from 99 to 56, token coverage stays
1.0000, and it adds 17 languages.

**The quantisation caveat is settled: it was not quantisation.** Those numbers first came
from the published model's INT8 graph against the retrain's safetensors checkpoint, which is
not a fair comparison. The retrain was exported with the Gather-only recipe, passed the span
gate 120 of 120, and re-scored. Both as INT8, same 1794 rows, the table above is what
holds, and by axis:

| axis | published | retrain |
|---|---|---|
| `neighbour` | 0.286 | 0.563 |
| `surface_form` | 0.000 | 0.250 |
| `shape` | 0.971 | 1.000 |
| `count` | 0.988 | 0.955 |

So **adopt the 26-locale retrain.** Better on CARD, IBAN and PHONE, twice as good on the
axis that isolates frame dependence, 17 more languages, and zero leaked tokens either way.
`count` regresses slightly and is the one thing to watch. `NATIONAL_ID` and `DATE` are
unfixed in both and are the generator's remaining work.

**The export gate had the same flaw as the harness, and finding it mattered.** It first
refused the export over one text of 120, where fp32 tagged a bare `1111` inside `4111 1111
1111 1111` as `NATIONAL_ID` and INT8 did not. Over ten Luhn-valid PANs in the same frame
INT8 matched fp32 on nine, so a twenty-pattern gate was decided by one degenerate
tokenisation, and the all-ones number is now on its third misleading conclusion here. The
deeper fault: the gate compared tagger spans while its own docstring committed to comparing
"the way the library reads spans", and `checksummed.py` is part of that and was missing from
both sides. It now applies the checksum overrule, and the library is a path dependency of
the training repo so it can.

**A related finding worth keeping: the tagger covers some PANs very poorly and the library
does not care.** On `4917 6100 0000 0000` the model covers 4 of 19 characters, on the
all-ones number 8 of 19, fp32 and INT8 alike, because runs of repeated digits tokenise
badly. All ten test PANs still come back `[CARD]` fully redacted end to end through
`scan_output`, because `checksummed.py` finds any Luhn-valid PAN with no model at all. That
is the design working: the model is the recall net and the checksum is the guarantee.

**And that table measures recall only, which is the limit to hold onto.** Every column above
asks whether a real entity was found and named. None asks whether something that is not an
entity was left alone, so a type can score 100% there and still be noisy. The 20 mundane
sentences that caught `nsfw` say what precision looks like: 4 spurious `pii` findings over
20, two of them redacting text a caller would notice.

| what it tagged | in the sentence | what a caller gets back |
|---|---|---|
| `person` = `Friday` | Office hours are Monday to Friday, nine until five. | `Monday to [PERSON], nine until five` |
| `person` = `Maerz` | Rechnung wurde am zwoelften Maerz ausgestellt. | `am zwoelften [PERSON] ausgestellt` |
| `person` = `Tuesday` | Your appointment is confirmed for Tuesday at ten. | flagged, not redacted |
| `national_id` = `1234.56` | The balance was 1234.56 before rounding. | flagged, not redacted |

Weekday and month names go to `PERSON`, and a money amount goes to the fallback class. This
is the same gap `entity_shapes.py` already records for `PERSON`, which has no shape to check
and let `nio` through in Swedish, now with two cases that visibly damage output.

**It stays a corpus fix and does not become a stoplist.** A calendar-word list in the library
would drop a span, and `entity_shapes.py` refuses to drop for a reason that still holds: a
person really can be called April or June or Mars, and turning a visible over-redaction into
an invisible hole is the wrong trade in a redactor. The corpus needs entity-free sentences
and calendar words in prose positions, which is the same fix the held-out harness asked for.

Two things follow. The library side is done: `detectors/checksummed.py` finds any Luhn-valid
PAN and any mod-97-valid IBAN with no model at all, at 100% in all four forms, and overrules
the tag. So the leak is closed today and stays closed whatever a future model does. The
training side is the generator, and the measurement reorders that work: template diversity
first, since frame is what the label actually depends on, and slots that vary independently
so a card is not always preceded by an IBAN. Presentation forms and entity-free sentences
stay on the list, below those two rather than at the top of it.

This is the fifth instance of the same failure in this project: the vacuous single-label
F1, a latency budget measured through a tokenizer load, Maltese blamed on the base model,
`groundedness` scoring its own generator's paraphrase style, and this. The sixth is above,
where the thing that agreed with itself was a diagnosis. The pattern is
worth naming because it keeps arriving disguised as good news. **A measurement that agrees
with itself is the default outcome, not the lucky one.** When a number looks better than
the problem is hard, find what the measurement shares with the thing it measures.

One thing to know before making per-language claims: in the generator, locale `en` is
labelled United Kingdom but uses the German Steuer-IdNr algorithm as a generic numeric
fallback. A real UK NINo carries no checksum, so a fallback is defensible, but the
model learned a German-shaped number as a UK identifier. Do not state that English
national IDs are checksum validated.

**Everything ported from the Guardrails Hub carries no weights at all**, which is why it
works on a machine that has never downloaded a model, the same as the T0 pair. Ten
detectors between them absorbed 32 hub validators, `output_format` taking 18 of those on
its own, and 33 validators were declined. Their provenance and the reason for each
decline are in `docs/porting-guardrails-validators.md`, rendered from
`detectors/guardrails_hub.py` so the two cannot drift. Do not restate those counts by
hand: read them off `PORTED` and `DECLINED`, which is how the numbers in this paragraph
were found to have drifted from seven and 57.

**`groundedness` was retrained on source-side pairs and the leak is closed.** The failure
this fixes: the old corpus asked for ten items of one register per generation request with
the register named in the prompt, so the candidate sentence's style carried the label and the
model classified style instead of comparing anything. 0.882 exact-match accuracy on its own
test split, and four of eight registers barely moved when scored against an unrelated source.

The new corpus is source-side pairs. One candidate sentence, two different sources, opposite
labels. The candidate text is byte-identical across a pair, so style cannot carry the label
by construction rather than by care. Verified on the corpus before spending the GPU: 1574 of
1574 pairs identical-candidate and opposite-label, every register exactly balanced across its
two labels, and a decision stump on lexical overlap beats the majority class by 0.021.

Two numbers from 2026-08-13, and the first is the one that matters:

- **Leak check retained 0.33**, 15 of 46 correct verdicts surviving an unrelated source,
  against the module's own "above about 0.5 is a leak worth chasing". `lexical_overlap`,
  which leaked worst before at 0.54 retained, is now 0.00. The residual sits in
  `numeric_conflict` at 0.50 and `negation_conflict` at 0.38, and is as likely to be the
  model's prior on `supported`, which is half the rows, as any remaining style signal.
- **Pair accuracy 0.6814**, which is the headline the eval prints. Both members of a pair
  correct, so a source-blind model scores near zero on it: it would have to give two
  different labels to two identical candidate texts. That is why this metric is worth more
  than the 0.80 single-row accuracy beside it.

What it is not yet. The corpus is 1574 train pairs, about 60 per language, and the
per-language cells hold 14 to 18 examples, so one item moves a score by six points. The
weak cells, `ga` 0.556, `mt` 0.571, `nl` and `tr` 0.688, are noise at that size and must not
be published as findings. Irish is the one worth chasing first, because Irish is in XLM-R so
the pretraining excuse is unavailable and the corpus is the remaining explanation.

And the `mt` row carries a "not in base model pretraining" note that this file has already
disproved once: `nsfw` Maltese went 0.000 to 1.000 on corpus size alone. At n=14 that note is
a guess, and repeating it as an explanation is the mistake named at the end of this section.

**The open-weight guardrail models are a retrain, not a port.** Decided 2026-08-11 for
Llama Guard and ShieldGemma, extended 2026-08-12 to `gpt-oss-safeguard` when the owner
asked whether Apache-2.0 changed the answer. It does not, and the reason it does not is
the useful part.

| | `gpt-oss-safeguard` | Llama Guard 4 | ShieldGemma |
|---|---|---|---|
| size | 20B and 120B, MoE | 12B | 2B, 9B, 27B text; 4B image |
| design | reasons over a policy given at inference | fixed hazard taxonomy | `Yes`/`No` scored from token probabilities |
| licence | Apache-2.0 plus a usage policy | Llama 4 Community | Gemma terms |

Three positions a model can occupy here, and each row above wins a different one:

- **Inside a detector, at scan time: none of them.** Not a quality judgement. All three
  emit a verdict as generated tokens, which is constraint 4 at any size, and the smallest
  candidate is 2B against the 278M encoders that already cost 151 ms at one thread. Two
  of the three are barred before latency matters, because their weights cannot ship.
  There is also a security argument that is stronger than the latency one: a model that
  reads a policy and then reads attacker-controlled text is itself an injection surface.
  Meta documents Llama Guard 4 as vulnerable to adversarial prompting and Google
  documents ShieldGemma as sensitive to policy wording. A guardrail with the same attack
  surface as the thing it guards is worth less than a classifier head that has none.
- **As a teacher for the `moderation` corpus, off the scan path: `gpt-oss-safeguard-20b`,
  and only it.** Apache-2.0 puts no restriction on its outputs, where the Llama 4 and
  Gemma terms both constrain derivatives, and this repository goes public. Its
  policy-at-inference design is also the right fit rather than merely the permitted one:
  `moderation` is 13 labels defined by our own taxonomy, so a model that reads that
  taxonomy labels against it directly, while a fixed-taxonomy classifier labels against
  MLCommons categories that then need mapping onto our 13. The mapping is where label
  errors would enter, and they would be invisible.
- **As a benchmark baseline: all three.** Scoring a model is not redistributing it, so no
  licence blocks this. The number answers "is our small head good enough" and belongs in
  `benchmarks/`, never in the library.

So the shipped detector stays a classification head on a small Apache-2.0 base, which is
what defaults 4 and 6 want anyway, and the corpus that has been the actual blocker gets
labelled by a model that runs off the scan path with no API spend and no key.

Two constraints on that, one of them already settled. **The current training VM cannot
host it.** Checked 2026-08-12: `border-train` has 15,360 MiB of GPU memory, and 20B needs
roughly 16 GB resident even as MoE, so the labelling pass needs a larger instance or a
CPU run that will be slow rather than impossible. Do not plan the corpus around the VM
that exists. Second, its policy-following is evaluated mainly in English, so the
26-language claim is ours to establish rather than to inherit. A teacher's errors become
our labels either way, so a human-checked slice is not optional.

Recorded rather than deleted, in the pattern this file uses: the licence objection to
Llama Guard and ShieldGemma was real and `gpt-oss-safeguard` answers it. It is the other
two objections, which were always the load-bearing ones, that a 20B policy reasoner makes
worse rather than better.

**`nsfw` blocks ordinary business text, and this is the thing to fix before release.**
Found on 2026-08-13 by running `scan_output` end to end on three sentences after wiring the
checksum pass, which is worth noting: the detector table, the per-language evaluations and
1915 passing tests all looked healthy and none of them touched this. Measured over 20
mundane sentences in ten languages, invoices and appointments and parcel tracking:

| detector | calibrated threshold | fires on its own test negatives | fires on mundane prose | median mundane score |
|---|---|---|---|---|
| `nsfw` | 0.95 | 3.8% | **55%** | **0.9845** |
| `injection` | 0.26 | 0.0% | 15% | 0.0024 |
| `bias` | 0.84 | 2.5% | 0% | 0.0377 |
| `toxicity` | 0.48 | 5.0% | 0% | 0.0063 |
| `politeness` | 0.89 | 1.2% | 0% | 0.0014 |
| `gibberish` | 0.05 | 5.0% | 0% | 0.0012 |

`nsfw` ships `on_fail: block` in the default policy, so 55% of ordinary output would be
refused. Four of the six are clean, so this is one detector rather than a systemic fault.

The cause is not the model and not the library. Its own test negatives score 0.0005 and its
positives 0.9998 through the same INT8 session, which is a correctly trained head. The
negatives are the problem: every one is long and topic-adjacent, art history and clinical
prose and breastfeeding, deliberately hard cases near the boundary. Mundane text is nowhere
in the corpus, so the sigmoid has nothing to place it against and saturates. A macro F1 of
0.976 and a per-language FPR of 0.0 are both true and both measured against hard negatives
only, which is not what a guardrail mostly sees.

Seventh instance of the pattern, and the one that would have shipped. The fix is easy
negatives in the corpus and a retrain, not a threshold: at the calibrated 0.95 it still
fires on 11 of 20.

**The corpus half of that fix landed on 2026-08-14. The model half has not, so the detector
is still broken.** Say it that way round, because a regenerated corpus reads like a fixed
detector and is not one. What exists now is `data/nsfw_{train,val,test}.jsonl`, 9,969
examples over 26 languages, and it addresses both faults the diagnosis named:

| what was wrong | what the corpus holds now |
|---|---|
| every negative a hard negative, mundane text absent | three `mundane_*` registers, 2,180 rows, 30% of negatives |
| positives systematically shorter than negatives | `length_separation` 0.510 / 0.489, against 0.964 before |
| one burst of failures starved one language | positives per language min 94, median 104, max 106 |

The mundane registers are shared in `simple_label.py` rather than written per detector, so
`toxicity`, `bias`, `politeness` and `gibberish` each get the same 2,184 mundane examples and
the same four length bands across 26 languages. That is deliberate: the same mundane sentence
is a negative for all five, and one shared set is what stops the next corpus from repeating
this detector's mistake.

**The held-out test was checked for contamination before being trusted, and that check is the
point.** The post-retrain measurement is the same 20 mundane sentences in
`tests/test_classifier_robustness.py`. A corpus that now deliberately contains mundane prose
is exactly a corpus that could contain those sentences, and then the retrain would score its
own training data and report the fix regardless of whether it worked. Measured: no exact
match, and the highest 4-gram containment of any test sentence in any corpus row is 0.25, on
a parcel-delivery sentence that shares the domain and not the wording. So the test still
tests something.

That check found nothing, which is the outcome to expect and not the reason to skip it. This
file's own pattern is that a measurement agreeing with itself is the default outcome; the 20
sentences would have agreed with a contaminated corpus just as readily.

**A separate finding from the same run: the shipped policies ignored the calibration.**
`toxicity`, `nsfw`, `bias` and `politeness` all carried hand-picked thresholds in
`policies/default.yaml` well below the value each model's `calibration.json` chose on its
validation split. The calibration landed in the training configs and nothing carried it
across. Aligned on 2026-08-13, which took 20 mundane sentences from 18 substantive findings
to 14 and removed every `bias` false positive. `injection` at 0.43 and `gibberish` at 0.37
stay deliberately above their calibrated 0.26 and 0.05, and say so at the key.

**Corpus size was the binding constraint, not the models.** Demonstrated on 2026-08-11 and
worth holding onto, because it changes where effort should go. `nsfw` and `gibberish` were the
two weakest detectors in the table. Their corpora were rebuilt with more positives per
language, nothing about either model or its training changed, and:

| detector | positives, test | macro F1 | worst language |
|---|---|---|---|
| `nsfw` | 52 to 262 | 0.817 to 0.976 | 0.000 to 0.870 |
| `gibberish` | 78 to 276 | 0.834 to 0.966 | 0.400 to 0.870 |

Maltese went from 0.000 to 1.000 in `nsfw`, which is the number that disproved this file's own
claim that the pretraining gap bounded it. Four detectors still sit on single-digit
per-language positives: `toxicity`, `injection`, `politeness` and `bias`. Read their scores as
understated rather than as ceilings, and reach for the corpus before the architecture.

**Three detectors ship unavailable, and they ship loudly.** The registry entry names
the intended repo, the detector raises an error naming the missing model, and the
tests are `xfail` with the repo id in the comment. There is no silent no-op, because
a silent no-op in a security library is a vulnerability. v1 is 18 of 28 detectors real,
stated plainly in the README. Nothing on the site or in the docs may imply otherwise.

**`semantic-mapper` does not fit the detector contract as it stands.** It is a 4B
Qwen3 LoRA that generates JSON against a frozen prompt, published as GGUF. That is a
local LLM call inside a detector, which constraint 4 rules out, and 4B cannot meet a
300 ms CPU budget. `topic_scope` therefore needs either a distilled encoder or an
explicit exception. Raise it before implementing that detector, do not quietly wire
the 4B model in.

Two things to fix on the hub side, not in this repo: no repo carries a `license:` field
in its metadata even where the card states Apache-2.0, and the published `cee-pii` and
`scam-guard-qwen06b` cards still contain pre-publication HTML comments saying "NOT YET
UPLOADED". The registry cannot attest a licence that is not declared.

## Language coverage

Decided 2026-08-10, replacing the earlier five-language target. The supported set is
the 24 official languages of the EU, plus Turkish and Azerbaijani. English is already
an EU official language, so the total is 26, not 25.

| Code | Language | Code | Language | Code | Language |
|---|---|---|---|---|---|
| `bg` | Bulgarian | `et` | Estonian | `lv` | Latvian |
| `hr` | Croatian | `fi` | Finnish | `mt` | Maltese |
| `cs` | Czech | `fr` | French | `pl` | Polish |
| `da` | Danish | `de` | German | `pt` | Portuguese |
| `nl` | Dutch | `el` | Greek | `ro` | Romanian |
| `en` | English | `hu` | Hungarian | `sk` | Slovak |
| `es` | Spanish | `ga` | Irish | `sl` | Slovenian |
| `sv` | Swedish | `it` | Italian | `lt` | Lithuanian |
| `tr` | Turkish (not EU) | `az` | Azerbaijani (not EU) | – | – |

What this obliges:

- Fixtures cover all 26 for every detector. A detector is not done at English plus
  five.
- The `disclosure` phrasings data file carries all 26. That detector is pure data, so
  there is no excuse for a gap.
- Model-backed detectors report per-language evaluation numbers, not one aggregate.
  An aggregate hides the tail, and the tail is the whole point of the project.
- Where a language genuinely underperforms, publish the number and say so. Do not
  drop the language from the table.

Where the models actually are, as of 2026-08-10: `piiguard` covers 9 of the 26 (`en`,
`ro`, `bg`, `hu`, `sl`, `hr`, `de`, `it`, `fr`). The remaining 17 are untested, and the
per-language table says so rather than implying coverage.

Closing that gap is a data task, not a research task, which is the useful thing to know
here. Training data is synthetic and correct by construction, so each new locale needs
a national-ID generator with its real checksum, a phone country code, name lists, and
an email TLD. Most of the 17 have documented schemes: PESEL, Czech and Slovak rodné
číslo, Dutch BSN, Portuguese NIF, Spanish DNI, Swedish personnummer, Finnish
henkilötunnus, Estonian isikukood, Greek AMKA, Irish PPSN, Turkish TC Kimlik.

Two genuine hard cases, and they are different problems:

- **Maltese is not in XLM-RoBERTa's pretraining set.** That is a fact about the base
  model. What was written here, that no amount of synthetic data fixes it, was an
  assumption and it was wrong. On 2026-08-11 `nsfw` scored 0.000 in Maltese, was blamed
  on the base model in this file, in the README and in the benchmark collector, and then
  went to 1.000 with perfect precision and recall when the corpus went from 2 positives
  per language to 10. The 0.000 was the sample size the whole time.

  So the pretraining gap stays on this list as something to know, not as an explanation.
  Before attributing any weak language to it, check how many examples the score rests
  on. Irish, contrary to an earlier note here, is in XLM-R and should be fine.
- **Maltese and Azerbaijani national IDs have no public checksum scheme**, so those
  two can only be generated format-valid, which makes their labels weaker than the
  rest by construction. Say so on the model card.

## Detector protocol

Every detector implements the same shape. No exceptions, no special cases in
`engine.py` for particular detectors.

```python
class Detector(Protocol):
    id: str
    tier: str
    sides: frozenset[str]  # {"input"}, {"output"}, or both

    def warm(self) -> None: ...
    def run(self, text: str, cfg: DetectorConfig, ctx: Context) -> list[Finding]: ...
```

If a task tempts you to branch on `detector.id` inside the engine, the abstraction is
wrong. Stop and raise it.

## Testing rules

- Tests come first. Write the failing test, then the implementation.
- Every detector needs a golden fixture directory with positive cases, negative cases,
  and coverage of every language in the "Language coverage" section below. English-only
  fixtures are a bug.
- No mocking of the ONNX sessions in detector tests. Test the real model. If that is
  too slow for the default run, mark it `@pytest.mark.slow`, do not fake it.
- `pytest -q` must pass with zero network access.

## Tooling

- Python 3.11+, `uv` for dependency management. The host default interpreter is 3.14,
  so pin the version in `pyproject.toml` and always go through `uv run`, never a bare
  `python` or `pytest`.
- `ruff` for lint and format, `mypy --strict` for types. Both run in CI, both must
  be clean.
- Apache-2.0. Every source file carries the SPDX header.
- Conventional commits.

## Commands

```sh
uv sync                              # install, including dev extras
uv run pytest -q                     # default suite, must pass with no network
uv run pytest -q -m "not slow"       # same thing explicitly, slow marks excluded
uv run pytest -q -m slow             # real models, latency budgets
uv run pytest -q tests/test_evidence.py::test_no_raw_text   # one test
uv run pytest -q tests/fixtures/pii -k romanian             # one detector, one language
uv run ruff check . && uv run ruff format --check .
uv run mypy --strict src
grep -rn "$(printf '\u2014')" --include="*.py" --include="*.md" --include="*.yaml" .   # em-dash check, must find nothing
```

The em-dash check is written with `printf` on purpose. Spelling the character
literally in the pattern would make this file match itself.

Two things to know about running the suite:

- The default run must pass with the network down, and `tests/test_offline.py` enforces
  that by patching `socket.socket` to raise. If a change makes a test need the network,
  the change is wrong, not the test.
- Model-backed detector tests use the real ONNX sessions. When they are too slow for the
  default run, mark them `slow`. Never mock a session to make them fast.

Latency budget work belongs in its own commit, with the measurement in the commit
message. Do not adjust a budget in the same commit as the code that missed it.

## Writing style for all documentation, docstrings, and commit messages

- No em-dashes. Use commas, colons, parentheses, or a full stop.
- En-dashes only for null cells in tables.
- Sentence case for headings.
- No marketing language, no superlatives, no "revolutionary", "seamless", "powerful".
- Claims must be checkable. If a number appears in the README, there must be a
  benchmark in the repo that produces it.

## Compliance language: read this before writing any docs

This library does not make anyone compliant with anything. It produces evidence about
controls that were applied. That distinction is load-bearing and legally material.

Permitted phrasing:
- "produces an auditable record of which checks ran and what they found"
- "detects whether a required disclosure is present in the output"
- "supports the evidence requirements of your own AI governance process"

Forbidden phrasing:
- "AI Act compliant" / "makes your system compliant"
- "guarantees", "ensures", "certified"
- naming a specific regulation as if the library satisfies it

The obligations under the EU AI Act sit with the provider or deployer of the system,
not with a library. Runtime checks can observe a narrow slice of this, mainly whether
a disclosure is present in text and whether the configured controls actually ran.
Say that, and nothing more.

## When to stop and ask

This list shortened on 2026-08-11. Most of what was here was permission-seeking about
things that are now judgement calls, and the answer to those is to decide, do it, and
write down what it cost. What is left is the set where being wrong is expensive and
quiet:

- **A change to `Decision` or `EvidenceRecord`.** Breaking, and every archived record
  ever produced is downstream of it.
- **Anything that makes a scan non-reproducible.** Sampling, a clock, a hosted call. See
  defaults 5 and 6: this is what an evidence record is for.
- **A third public function.** Two is the API. A third is a product decision.
- **A latency budget change.** In its own commit, with the measurement in the message,
  never in the same commit as the code that missed it.

Everything else, including a new detector, a new runtime dependency, a local model
inside a detector, or network access during a scan, is yours to decide. Decide it, land
it, and declare what it needs in `Spec.requires` so the caller is told. Keep the record
of what was overruled rather than deleting it. That is how the detector cap and this
list were handled, and it is why both are still readable.
